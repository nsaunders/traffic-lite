module TrafficLite.Update where

import Prelude

import TrafficLite.Data.Metric (mergeDataSets, splitDataSet, unionByTimestamp)
import TrafficLite.Effect.RemoteData
  ( class MonadRemoteData
  , fetchClones
  , fetchViews
  )
import TrafficLite.Effect.Store (class MonadStore)
import TrafficLite.Effect.Store as Store

update :: forall m. Bind m => MonadRemoteData m => MonadStore m => m Unit
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
