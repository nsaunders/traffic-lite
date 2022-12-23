module TrafficLite.Effect.DataFetching where

import Prelude

import Affjax.Node (defaultRequest, request)
import Affjax.Node as Affjax
import Affjax.RequestHeader (RequestHeader(..))
import Affjax.ResponseFormat as ResponseFormat
import Control.Monad.Error.Class (class MonadThrow, throwError)
import Control.Monad.Reader.Class (class MonadAsk, ask)
import Data.Argonaut (decodeJson, getField, printJsonDecodeError)
import Data.Array (sortWith, takeEnd)
import Data.Either (either)
import Data.MediaType (MediaType(..))
import Effect.Aff.Class (class MonadAff, liftAff)
import TrafficLite.Data.Error (Error(..))
import TrafficLite.Data.Error as TrafficLite
import TrafficLite.Data.Metric (CountRep, TimestampRep)
import Type.Row (type (+))

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
    config =
      defaultRequest
        { url = url, headers = headers, responseFormat = ResponseFormat.json }
  { body } <-
    either (throwError <<< FetchError <<< Affjax.printError) pure
      =<< liftAff (request config)
  either
    (throwError <<< TypeError <<< printJsonDecodeError)
    (pure <<< takeEnd 13 <<< sortWith _.timestamp)
    $ decodeJson =<< flip getField metricType =<< decodeJson body

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
