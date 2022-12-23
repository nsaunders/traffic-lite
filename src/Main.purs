module Main where

import Prelude

import Affjax.Node (defaultRequest, request)
import Affjax.Node as Affjax
import Affjax.RequestHeader (RequestHeader(..))
import Affjax.ResponseFormat as ResponseFormat
import Control.Alt ((<|>))
import Control.Monad.Error.Class (class MonadThrow, throwError, try)
import Control.Monad.Except.Trans (ExceptT(..), except, runExceptT, withExceptT)
import Control.Monad.Morph (hoist)
import Data.Argonaut (Json, decodeJson, encodeJson, getField, parseJson, printJsonDecodeError, stringifyWithIndent, (.:))
import Data.Argonaut.Decode.Decoders (decodeJArray, decodeJObject)
import Data.Array (catMaybes, sortWith, takeEnd, unionBy)
import Data.Bifunctor (bimap, lmap)
import Data.Either (Either(..), either, fromRight)
import Data.Foldable (foldr)
import Data.Map as Map
import Data.Maybe (Maybe(..))
import Data.MediaType (MediaType(..))
import Data.Traversable (traverse)
import Data.Tuple.Nested ((/\))
import Dotenv as Dotenv
import Effect (Effect)
import Effect.Aff (launchAff_)
import Effect.Aff.Class (class MonadAff, liftAff)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Exception as Error
import GitHub.Actions.Core (getInput)
import GitHub.Actions.Core as Actions
import Node.Encoding (Encoding(UTF8))
import Node.FS.Aff (mkdir', readTextFile, writeTextFile)
import Node.FS.Perms (all, mkPerms, read)
import Node.Path (FilePath, dirname)
import Type.Row (type (+))

data AppError
  = ConfigError String
  | FetchError String
  | TypeError String
  | SaveError String

printAppError :: AppError -> String
printAppError (ConfigError details) = "Configuration: " <> details
printAppError (FetchError details) = "Data fetching: " <> details
printAppError (TypeError details) = "Type: " <> details
printAppError (SaveError details) = "Saving data: " <> details

type TimestampRep r = (timestamp :: String | r)

type CountRep r = (count :: Int, uniques :: Int | r)

fetchCounts
  :: forall m r
   . MonadAff m
  => String
  -> { repo :: String, token :: String | r }
  -> ExceptT AppError m (Array { | TimestampRep + CountRep + () })
fetchCounts metricType { token, repo } =
  let
    url = "https://api.github.com/repos/" <> repo <> "/traffic/" <> metricType
    headers =
      [ Accept $ MediaType "application/vnd.github+json"
      , RequestHeader "Authorization" ("Bearer " <> token)
      , RequestHeader "X-GitHub-Api-Version" "2022-11-28"
      ]
    config = defaultRequest
      { url = url, headers = headers, responseFormat = ResponseFormat.json }
  in
    do
      { body } <-
        ExceptT $ lmap (FetchError <<< Affjax.printError) <$>
          (liftAff $ request config)
      except
        $ bimap
            (TypeError <<< printJsonDecodeError)
            (takeEnd 13 <<< sortWith _.timestamp)
        $ decodeJson
            =<< flip getField metricType
            =<< decodeJObject body

fetchClones
  :: forall m r
   . MonadAff m
  => { repo :: String, token :: String | r }
  -> ExceptT AppError m (Array { | TimestampRep + CountRep + () })
fetchClones = fetchCounts "clones"

fetchViews
  :: forall m r
   . MonadAff m
  => { repo :: String, token :: String | r }
  -> ExceptT AppError m (Array { | TimestampRep + CountRep + () })
fetchViews = fetchCounts "views"

readSavedData
  :: forall r m
   . MonadAff m
  => { path :: FilePath | r }
  -> ExceptT AppError m Json
readSavedData { path } = do
  contents <- liftAff $ fromRight "[]" <$> try (readTextFile UTF8 path)
  except $ lmap (TypeError <<< printJsonDecodeError) $ parseJson contents

getCounts
  :: forall m
   . MonadEffect m
  => MonadThrow AppError m
  => String
  -> Json
  -> m (Array { | TimestampRep + CountRep + () })
getCounts metricType json = do
  arr <- either (throwError <<< TypeError <<< printJsonDecodeError) pure $ decodeJArray json
  items <- traverse decodeItem arr
  pure $ catMaybes items
  where
  decodeItem
    :: Json -> m (Maybe { | TimestampRep + CountRep + () })
  decodeItem itemJson = do
    either (throwError <<< TypeError <<< printJsonDecodeError) pure do
      obj <- decodeJObject itemJson
      timestamp <- obj .: "timestamp"
      md :: Maybe { count :: Int, uniques :: Int } <- obj .: metricType
      pure $ (\{ count, uniques } -> { timestamp, count, uniques }) <$> md

getClones
  :: forall m
   . MonadEffect m
  => MonadThrow AppError m
  => Json
  -> m (Array { | TimestampRep + CountRep + () })
getClones = getCounts "clones"

getViews
  :: forall m
   . MonadEffect m
  => MonadThrow AppError m
  => Json
  -> m (Array { | TimestampRep + CountRep + () })
getViews = getCounts "views"

union
  :: forall t r
   . Eq t
  => Array { timestamp :: t | r }
  -> Array { timestamp :: t | r }
  -> Array { timestamp :: t | r }
union = unionBy \a b -> a.timestamp == b.timestamp

buildData
  :: forall r
   . { clones :: Array { | TimestampRep + CountRep + r }
     , views :: Array { | TimestampRep + CountRep + r }
     }
  -> Array
       { | TimestampRep +
           ( views :: Maybe { | CountRep + () }
           , clones :: Maybe { | CountRep + () }
           )
       }
buildData source =
  (\(timestamp /\ { clones, views }) -> { timestamp, clones, views }) <$>
    ( Map.toUnfoldable
        $ flip
            ( foldr \{ timestamp, count, uniques } -> Map.insertWith
                ( \existing addl ->
                    { clones: existing.clones <|> addl.clones
                    , views: existing.views <|> addl.views
                    }
                )
                timestamp
                { clones: Nothing, views: Just { count, uniques } }
            )
            source.views
        $
          foldr
            ( \{ timestamp, count, uniques } -> Map.insert timestamp
                { clones: Just { count, uniques }, views: Nothing }
            )
            Map.empty
            source.clones
    )

saveData
  :: forall m r
   . MonadAff m
  => MonadThrow AppError m
  => Json
  -> { path :: FilePath | r }
  -> m Unit
saveData json { path } = do
  let dir = dirname path
  liftAff (try $ mkdir' dir { mode: mkPerms all all read, recursive: true })
    >>= either
      ( \e -> throwError $ SaveError $ "Creating directory \"" <> dir
          <> "\" failed: "
          <> Error.message e
      )
      pure
  liftAff (try $ writeTextFile UTF8 path $ stringifyWithIndent 2 json)
    >>= either
      ( \e -> throwError $ SaveError $ "Writing file \"" <> path
          <> "\" failed: "
          <> Error.message e
      )
      pure

main :: Effect Unit
main = launchAff_ do
  _ <- Dotenv.loadFile
  result <-
    runExceptT do
      config <-
        withExceptT
          (ConfigError <<< Error.message)
          $ hoist liftEffect
          $ (\path token repo -> { path, token, repo })
              <$> getInput { name: "path", options: pure { required: true } }
              <*> getInput { name: "token", options: pure { required: true } }
              <*> getInput { name: "repo", options: pure { required: true } }
      latestClones <- fetchClones config
      latestViews <- fetchViews config
      saved <- readSavedData config
      savedClones <- getClones saved
      savedViews <- getViews saved
      let
        updated = buildData
          { clones: union latestClones savedClones
          , views: union latestViews savedViews
          }
      saveData (encodeJson updated) config
  liftEffect case result of
    Left err ->
      Actions.error $ printAppError err
    Right _ ->
      Actions.info "Traffic update successful"
