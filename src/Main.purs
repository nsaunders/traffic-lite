module Main where

import Prelude

import Control.Monad.Except.Trans (runExceptT)
import Data.Either (either)
import Dotenv as Dotenv
import Effect (Effect)
import Effect.Aff (launchAff_)
import Effect.Class (liftEffect)
import GitHub.Actions.Core as Actions
import TrafficLite.Control.Monad.UpdateM (runUpdateM)
import TrafficLite.Data.Error as TrafficLite
import TrafficLite.Effect.Environment (getEnvironment)
import TrafficLite.Update (update)

main :: Effect Unit
main = launchAff_ do
  _ <- Dotenv.loadFile
  runExceptT (getEnvironment >>= runUpdateM update) >>=
    either
      (liftEffect <<< Actions.error <<< TrafficLite.printError)
      (const $ liftEffect $ Actions.info "Traffic update successful")
