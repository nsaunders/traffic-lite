module Main where

import Prelude

import Control.Monad.Error.Class (class MonadThrow, throwError)
import Control.Monad.Except.Trans (runExceptT, withExceptT)
import Control.Monad.Morph (hoist)
import Control.Monad.Reader.Trans (runReaderT)
import Data.Either (Either(..), either)
import Dotenv as Dotenv
import Effect (Effect)
import Effect.Aff (launchAff_)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Exception as Error
import GitHub.Actions.Core (getInput)
import GitHub.Actions.Core as Actions
import Node.Path (FilePath)
import TrafficLite.Data.Error (Error(..))
import TrafficLite.Data.Error as TrafficLite
import TrafficLite.Data.Metric (mergeDataSets, splitDataSet, unionByTimestamp)
import TrafficLite.Effect.DataFetching (fetchClones, fetchViews)
import TrafficLite.Effect.Store as Store

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

main :: Effect Unit
main = launchAff_ do
  _ <- Dotenv.loadFile
  result <-
    runExceptT $
      getInputs >>=
        runReaderT do
          latestClones <- fetchClones
          latestViews <- fetchViews
          saved <- splitDataSet <$> Store.get
          let
            updated = mergeDataSets
              { clones: unionByTimestamp latestClones saved.clones
              , views: unionByTimestamp latestViews saved.views
              }
          Store.put updated
  liftEffect case result of
    Left error ->
      Actions.error $ TrafficLite.printError error
    Right _ ->
      Actions.info "Traffic update successful"
