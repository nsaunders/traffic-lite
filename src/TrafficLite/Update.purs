module TrafficLite.Update where

import Prelude

import Control.Monad.Error.Class (class MonadThrow)
import Control.Monad.Reader.Class (class MonadAsk)
import Effect.Aff.Class (class MonadAff)
import Node.Path (FilePath)
import TrafficLite.Data.Error as TrafficLite
import TrafficLite.Data.Metric (mergeDataSets, splitDataSet, unionByTimestamp)
import TrafficLite.Effect.RemoteData (class MonadRemoteData, fetchClones, fetchViews)
import TrafficLite.Effect.Store (class MonadStore)
import TrafficLite.Effect.Store as Store

update
  :: forall m r
   . MonadAff m
  => MonadAsk { path :: FilePath, repo :: String, token :: String | r } m
  => MonadRemoteData m
  => MonadStore m
  => MonadThrow TrafficLite.Error m
  => m Unit
update = do
  latestClones <- fetchClones
  latestViews <- fetchViews
  saved <- splitDataSet <$> Store.get
  let
    updated = mergeDataSets
      { clones: unionByTimestamp latestClones saved.clones
      , views: unionByTimestamp latestViews saved.views
      }
  Store.put updated
