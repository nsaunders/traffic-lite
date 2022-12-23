module Main where

import Prelude

import Control.Monad.Except.Trans (runExceptT)
import Control.Monad.Reader.Trans (runReaderT)
import Data.Either (Either(..))
import Dotenv as Dotenv
import Effect (Effect)
import Effect.Aff (launchAff_)
import Effect.Class (liftEffect)
import GitHub.Actions.Core as Actions
import TrafficLite.Data.Error as TrafficLite
import TrafficLite.Effect.Environment (getEnvironment)
import TrafficLite.Update (update)

main :: Effect Unit
main = launchAff_ do
  _ <- Dotenv.loadFile
  result <- runExceptT $ getEnvironment >>= runReaderT update
  liftEffect case result of
    Left error ->
      Actions.error $ TrafficLite.printError error
    Right _ ->
      Actions.info "Traffic update successful"
