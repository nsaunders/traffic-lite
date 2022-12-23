module TrafficLite.Effect.Environment where

import Prelude

import Control.Monad.Error.Class (class MonadThrow, throwError)
import Control.Monad.Except.Trans (runExceptT)
import Control.Monad.Morph (hoist)
import Data.Either (either)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Exception as Error
import GitHub.Actions.Core (getInput)
import Node.Path (FilePath)
import TrafficLite.Data.Error (Error(ConfigError))
import TrafficLite.Data.Error as TrafficLite

getEnvironment
  :: forall m
   . MonadEffect m
  => MonadThrow TrafficLite.Error m
  => m { path :: FilePath, token :: String, repo :: String }
getEnvironment =
  either (throwError <<< ConfigError <<< Error.message) pure =<<
    ( runExceptT
        $ hoist liftEffect
        $ (\path token repo -> { path, token, repo })
            <$> getInput { name: "path", options: pure { required: true } }
            <*> getInput { name: "token", options: pure { required: true } }
            <*> getInput { name: "repo", options: pure { required: true } }
    )
