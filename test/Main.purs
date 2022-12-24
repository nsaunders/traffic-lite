module Test.Main where

import Prelude

import Control.Monad.Reader.Class (class MonadAsk, asks)
import Control.Monad.Reader.Trans (ReaderT, runReaderT)
import Control.Monad.State (State, execState)
import Control.Monad.State.Class (class MonadState, get, put)
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Effect.Aff (launchAff_)
import Test.Spec (describe, it)
import Test.Spec.Assertions (shouldEqual)
import Test.Spec.Reporter (consoleReporter)
import Test.Spec.Runner (runSpec)
import TrafficLite.Data.Metric (CountRep, TimestampRep)
import TrafficLite.Effect.RemoteData (class MonadRemoteData)
import TrafficLite.Effect.Store (class MonadStore)
import TrafficLite.Update (update)
import Type.Row (type (+))

type RemoteData =
  { views :: Array { | TimestampRep + CountRep + () }
  , clones :: Array { | TimestampRep + CountRep + () }
  }

type StoreData =
  Array
    { views :: Maybe { | CountRep + () }
    , clones :: Maybe { | CountRep + () }
    | TimestampRep + ()
    }

newtype TestM a = TestM (ReaderT RemoteData (State StoreData) a)

derive newtype instance Applicative TestM
derive newtype instance Apply TestM
derive newtype instance Bind TestM
derive newtype instance Functor TestM
derive newtype instance Monad TestM
derive newtype instance MonadAsk RemoteData TestM
derive newtype instance MonadState StoreData TestM

instance MonadRemoteData TestM where
  fetchViews = asks _.views
  fetchClones = asks _.clones

instance MonadStore TestM where
  get = get
  put = put

execTestM :: forall a. StoreData -> RemoteData -> TestM a -> StoreData
execTestM initialState remoteData (TestM m) =
  execState (runReaderT m remoteData) initialState

main :: Effect Unit
main = launchAff_ $ runSpec [ consoleReporter ] do
  describe "update" do
    describe "when store is empty" do
      let storeData = []
      it "puts all of the remote data" do
        let
          remoteData =
            { views:
                [ { timestamp: "2022-12-17T00:00:00.000Z"
                  , count: 12
                  , uniques: 11
                  }
                , { timestamp: "2022-12-18T00:00:00.000Z"
                  , count: 3
                  , uniques: 2
                  }
                , { timestamp: "2022-12-19T00:00:00.000Z"
                  , count: 12
                  , uniques: 7
                  }
                , { timestamp: "2022-12-20T00:00:00.000Z"
                  , count: 1
                  , uniques: 1
                  }
                , { timestamp: "2022-12-21T00:00:00.000Z"
                  , count: 0
                  , uniques: 0
                  }
                , { timestamp: "2022-12-22T00:00:00.000Z"
                  , count: 6
                  , uniques: 2
                  }
                , { timestamp: "2022-12-23T00:00:00.000Z"
                  , count: 6
                  , uniques: 3
                  }
                ]
            , clones:
                [ { timestamp: "2022-12-18T00:00:00.000Z"
                  , count: 4
                  , uniques: 4
                  }
                , { timestamp: "2022-12-19T00:00:00.000Z"
                  , count: 3
                  , uniques: 1
                  }
                , { timestamp: "2022-12-20T00:00:00.000Z"
                  , count: 4
                  , uniques: 3
                  }
                , { timestamp: "2022-12-21T00:00:00.000Z"
                  , count: 6
                  , uniques: 6
                  }
                , { timestamp: "2022-12-22T00:00:00.000Z"
                  , count: 3
                  , uniques: 1
                  }
                , { timestamp: "2022-12-23T00:00:00.000Z"
                  , count: 4
                  , uniques: 3
                  }
                , { timestamp: "2022-12-24T00:00:00.000Z"
                  , count: 4
                  , uniques: 2
                  }
                ]
            }
          actual = execTestM storeData remoteData update
          expected =
            [ { timestamp: "2022-12-17T00:00:00.000Z"
              , clones: Nothing
              , views: Just { count: 12, uniques: 11 }
              }
            , { timestamp: "2022-12-18T00:00:00.000Z"
              , clones: Just { count: 4, uniques: 4 }
              , views: Just { count: 3, uniques: 2 }
              }
            , { timestamp: "2022-12-19T00:00:00.000Z"
              , clones: Just { count: 3, uniques: 1 }
              , views: Just { count: 12, uniques: 7 }
              }
            , { timestamp: "2022-12-20T00:00:00.000Z"
              , clones: Just { count: 4, uniques: 3 }
              , views: Just { count: 1, uniques: 1 }
              }
            , { timestamp: "2022-12-21T00:00:00.000Z"
              , clones: Just { count: 6, uniques: 6 }
              , views: Just { count: 0, uniques: 0 }
              }
            , { timestamp: "2022-12-22T00:00:00.000Z"
              , clones: Just { count: 3, uniques: 1 }
              , views: Just { count: 6, uniques: 2 }
              }
            , { timestamp: "2022-12-23T00:00:00.000Z"
              , clones: Just { count: 4, uniques: 3 }
              , views: Just { count: 6, uniques: 3 }
              }
            , { timestamp: "2022-12-24T00:00:00.000Z"
              , clones: Just { count: 4, uniques: 2 }
              , views: Nothing
              }
            ]
        actual `shouldEqual` expected
