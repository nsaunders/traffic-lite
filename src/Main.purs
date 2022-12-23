module Main where

import Prelude

import Affjax.Node (defaultRequest, request)
import Affjax.Node as Affjax
import Affjax.RequestHeader (RequestHeader(..))
import Affjax.ResponseFormat as ResponseFormat
import Control.Monad.Error.Class (class MonadThrow, throwError, try)
import Control.Monad.Except.Trans (runExceptT, withExceptT)
import Control.Monad.Morph (hoist)
import Control.Monad.Reader.Class (class MonadAsk, ask)
import Control.Monad.Reader.Trans (runReaderT)
import Data.Argonaut
  ( Json
  , decodeJson
  , encodeJson
  , getField
  , parseJson
  , printJsonDecodeError
  , stringifyWithIndent
  , (.:)
  )
import Data.Argonaut.Decode.Decoders (decodeJArray, decodeJObject)
import Data.Array (catMaybes, sortWith, takeEnd)
import Data.Either (Either(..), either, fromRight)
import Data.Maybe (Maybe)
import Data.MediaType (MediaType(..))
import Data.Traversable (traverse)
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
import TrafficLite.Data.Error (Error(..))
import TrafficLite.Data.Error as TrafficLite
import TrafficLite.Data.Metric
  ( CountRep
  , TimestampRep
  , mergeDataSets
  , unionByTimestamp
  )
import Type.Row (type (+))

getInputs
  :: forall m
   . MonadEffect m
  => MonadThrow TrafficLite.Error m
  => m { path :: FilePath, token :: String, repo :: String }
getInputs =
  either throwError pure =<<
    ( runExceptT
        $ withExceptT
            (ConfigError <<< Error.message)
        $ hoist liftEffect
        $ (\path token repo -> { path, token, repo })
            <$> getInput { name: "path", options: pure { required: true } }
            <*> getInput { name: "token", options: pure { required: true } }
            <*> getInput { name: "repo", options: pure { required: true } }
    )

fetchCounts
  :: forall m r
   . MonadAff m
  => MonadAsk { repo :: String, token :: String | r } m
  => MonadThrow TrafficLite.Error m
  => String
  -> m (Array { | TimestampRep + CountRep + () })
fetchCounts metricType = do
  { token, repo } <- ask
  let
    url = "https://api.github.com/repos/" <> repo <> "/traffic/" <> metricType
    headers =
      [ Accept $ MediaType "application/vnd.github+json"
      , RequestHeader "Authorization" ("Bearer " <> token)
      , RequestHeader "X-GitHub-Api-Version" "2022-11-28"
      ]
    config = defaultRequest
      { url = url, headers = headers, responseFormat = ResponseFormat.json }
  { body } <-
    either (throwError <<< FetchError <<< Affjax.printError) pure
      =<< liftAff (request config)
  either
    (throwError <<< TypeError <<< printJsonDecodeError)
    (pure <<< takeEnd 13 <<< sortWith _.timestamp)
    $ decodeJson =<< flip getField metricType =<< decodeJObject body

fetchClones
  :: forall m r
   . MonadAff m
  => MonadAsk { repo :: String, token :: String | r } m
  => MonadThrow TrafficLite.Error m
  => m (Array { | TimestampRep + CountRep + () })
fetchClones = fetchCounts "clones"

fetchViews
  :: forall m r
   . MonadAff m
  => MonadAsk { repo :: String, token :: String | r } m
  => MonadThrow TrafficLite.Error m
  => m (Array { | TimestampRep + CountRep + () })
fetchViews = fetchCounts "views"

readSavedData
  :: forall m r
   . MonadAff m
  => MonadAsk { path :: FilePath | r } m
  => MonadThrow TrafficLite.Error m
  => m Json
readSavedData = do
  { path } <- ask
  liftAff (fromRight "[]" <$> try (readTextFile UTF8 path)) >>=
    either (throwError <<< TypeError <<< printJsonDecodeError) pure <<<
      parseJson

getCounts
  :: forall m
   . MonadEffect m
  => MonadThrow TrafficLite.Error m
  => String
  -> Json
  -> m (Array { | TimestampRep + CountRep + () })
getCounts metricType json = do
  arr <- either (throwError <<< TypeError <<< printJsonDecodeError) pure $
    decodeJArray json
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
  => MonadThrow TrafficLite.Error m
  => Json
  -> m (Array { | TimestampRep + CountRep + () })
getClones = getCounts "clones"

getViews
  :: forall m
   . MonadEffect m
  => MonadThrow TrafficLite.Error m
  => Json
  -> m (Array { | TimestampRep + CountRep + () })
getViews = getCounts "views"

saveData
  :: forall m r
   . MonadAff m
  => MonadAsk { path :: FilePath | r } m
  => MonadThrow TrafficLite.Error m
  => Json
  -> m Unit
saveData json = do
  { path } <- ask
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
    runExceptT $
      getInputs >>=
        runReaderT do
          latestClones <- fetchClones
          latestViews <- fetchViews
          saved <- readSavedData
          savedClones <- getClones saved
          savedViews <- getViews saved
          let
            updated = mergeDataSets
              { clones: unionByTimestamp latestClones savedClones
              , views: unionByTimestamp latestViews savedViews
              }
          saveData (encodeJson updated)
  liftEffect case result of
    Left error ->
      Actions.error $ TrafficLite.printError error
    Right _ ->
      Actions.info "Traffic update successful"
