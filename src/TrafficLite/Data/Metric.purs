module TrafficLite.Data.Metric where

import Prelude

import Control.Alt ((<|>))
import Data.Array (catMaybes, unionBy)
import Data.Foldable (foldr)
import Data.Map as Map
import Data.Maybe (Maybe(..))
import Data.Tuple.Nested ((/\))
import Type.Row (type (+))

type TimestampRep r = (timestamp :: String | r)

type CountRep r = (count :: Int, uniques :: Int | r)

unionByTimestamp
  :: forall t r
   . Eq t
  => Array { timestamp :: t | r }
  -> Array { timestamp :: t | r }
  -> Array { timestamp :: t | r }
unionByTimestamp = unionBy \a b -> a.timestamp == b.timestamp

splitDataSet
  :: forall r
   . Array
       { clones :: Maybe { | CountRep + () }
       , views :: Maybe { | CountRep + () }
       | TimestampRep + r
       }
  -> { clones :: Array { | TimestampRep + CountRep + () }
     , views :: Array { | TimestampRep + CountRep + () }
     }
splitDataSet items =
  { clones: catMaybes $
      ( \{ timestamp, clones } ->
          (\{ count, uniques } -> { timestamp, count, uniques }) <$> clones
      ) <$> items
  , views: catMaybes $
      ( \{ timestamp, views } ->
          (\{ count, uniques } -> { timestamp, count, uniques }) <$> views
      ) <$> items
  }

mergeDataSets
  :: forall r
   . { clones :: Array { | TimestampRep + CountRep + r }
     , views :: Array { | TimestampRep + CountRep + r }
     }
  -> Array
       { | TimestampRep +
           ( views :: Maybe { | CountRep + () }
           , clones :: Maybe { | CountRep + () }
           )
       }
mergeDataSets source =
  (\(timestamp /\ { clones, views }) -> { timestamp, clones, views }) <$>
    ( Map.toUnfoldable
        $ flip
            ( foldr \{ timestamp, count, uniques } -> Map.insertWith
                ( \existing addl ->
                    { clones: existing.clones <|> addl.clones
                    , views: existing.views <|> addl.views
                    }
                )
                timestamp
                { clones: Nothing, views: Just { count, uniques } }
            )
            source.views
        $
          foldr
            ( \{ timestamp, count, uniques } -> Map.insert timestamp
                { clones: Just { count, uniques }, views: Nothing }
            )
            Map.empty
            source.clones
    )
