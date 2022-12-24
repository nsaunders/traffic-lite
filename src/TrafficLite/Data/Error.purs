module TrafficLite.Data.Error where

import Prelude

import Data.Generic.Rep (class Generic)
import Data.Show.Generic (genericShow)

data Error
  = ConfigError String
  | FetchError String
  | TypeError String
  | SaveError String

derive instance Generic Error _

instance Show Error where
  show = genericShow

printError :: Error -> String
printError (ConfigError details) = "Configuration: " <> details
printError (FetchError details) = "Data fetching: " <> details
printError (TypeError details) = "Type: " <> details
printError (SaveError details) = "Saving data: " <> details
