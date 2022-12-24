module TrafficLite.Effect.Store (class MonadStore, get, put) where

import Prelude

import Control.Monad.Error.Class (class MonadThrow, throwError, try)
import Control.Monad.Reader.Class (class MonadAsk, ask)
import Data.Argonaut
  ( decodeJson
  , encodeJson
  , parseJson
  , printJsonDecodeError
  , stringifyWithIndent
  )
import Data.Either (either, fromRight)
import Data.Maybe (Maybe)
import Effect.Aff.Class (class MonadAff, liftAff)
import Effect.Exception as Error
import Node.Encoding (Encoding(UTF8))
import Node.FS.Aff (mkdir', readTextFile, writeTextFile)
import Node.FS.Perms (all, mkPerms, read)
import Node.Path (FilePath, dirname)
import TrafficLite.Control.Monad.UpdateM (UpdateM)
import TrafficLite.Data.Error (Error(..))
import TrafficLite.Data.Error as TrafficLite
import TrafficLite.Data.Metric (CountRep, TimestampRep)
import Type.Row (type (+))

class MonadStore (m :: Type -> Type) where
  get
    :: m
         ( Array
             { clones :: Maybe { | CountRep + () }
             , views :: Maybe { | CountRep + () }
             | TimestampRep + ()
             }
         )
  put
    :: Array
         { clones :: Maybe { | CountRep + () }
         , views :: Maybe { | CountRep + () }
         | TimestampRep + ()
         }
    -> m Unit

getImpl
  :: forall m r
   . MonadAff m
  => MonadAsk { path :: FilePath | r } m
  => MonadThrow TrafficLite.Error m
  => m
       ( Array
           { clones :: Maybe { | CountRep + () }
           , views :: Maybe { | CountRep + () }
           | TimestampRep + ()
           }
       )
getImpl = do
  { path } <- ask
  liftAff (fromRight "[]" <$> try (readTextFile UTF8 path)) >>=
    either (throwError <<< TypeError <<< printJsonDecodeError) pure <<<
      (decodeJson <=< parseJson)

putImpl
  :: forall m r
   . MonadAff m
  => MonadAsk { path :: FilePath | r } m
  => MonadThrow TrafficLite.Error m
  => Array
       { clones :: Maybe { | CountRep + () }
       , views :: Maybe { | CountRep + () }
       | TimestampRep + ()
       }
  -> m Unit
putImpl metrics = do
  { path } <- ask
  let dir = dirname path
  liftAff (try $ mkdir' dir { mode: mkPerms all all read, recursive: true })
    >>= either
      ( \e -> throwError $ SaveError $ "Creating directory \"" <> dir
          <> "\" failed: "
          <> Error.message e
      )
      pure
  liftAff
    (try $ writeTextFile UTF8 path $ stringifyWithIndent 2 $ encodeJson metrics)
    >>= either
      ( \e -> throwError $ SaveError $ "Writing file \"" <> path
          <> "\" failed: "
          <> Error.message e
      )
      pure

instance MonadStore UpdateM where
  get = getImpl
  put = putImpl
