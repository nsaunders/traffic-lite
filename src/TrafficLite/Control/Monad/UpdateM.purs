module TrafficLite.Control.Monad.UpdateM where

import Prelude

import Control.Monad.Error.Class (class MonadThrow)
import Control.Monad.Except.Trans (ExceptT)
import Control.Monad.Reader.Class (class MonadAsk)
import Control.Monad.Reader.Trans (ReaderT, runReaderT)
import Effect.Aff (Aff)
import Effect.Aff.Class (class MonadAff)
import Effect.Class (class MonadEffect)
import Node.Path (FilePath)
import TrafficLite.Data.Error as TrafficLite

newtype UpdateM a = UpdateM
  ( ReaderT { path :: FilePath, repo :: String, token :: String }
      (ExceptT TrafficLite.Error Aff)
      a
  )

derive newtype instance Applicative UpdateM
derive newtype instance Apply UpdateM
derive newtype instance Bind UpdateM
derive newtype instance Functor UpdateM
derive newtype instance Monad UpdateM
derive newtype instance MonadAff UpdateM
derive newtype instance
  MonadAsk { path :: FilePath, repo :: String, token :: String } UpdateM

derive newtype instance MonadEffect UpdateM
derive newtype instance MonadThrow TrafficLite.Error UpdateM

runUpdateM
  :: forall r a
   . UpdateM a
  -> { path :: FilePath, repo :: String, token :: String | r }
  -> ExceptT TrafficLite.Error Aff a
runUpdateM (UpdateM reader) { path, repo, token } = runReaderT reader
  { path, repo, token }
