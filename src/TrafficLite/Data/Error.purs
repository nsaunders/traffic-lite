module TrafficLite.Data.Error where

import Prelude

data Error
  = ConfigError String
  | FetchError String
  | TypeError String
  | SaveError String

printError :: Error -> String
printError (ConfigError details) = "Configuration: " <> details
printError (FetchError details) = "Data fetching: " <> details
printError (TypeError details) = "Type: " <> details
printError (SaveError details) = "Saving data: " <> details
