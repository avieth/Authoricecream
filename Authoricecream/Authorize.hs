{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}

module Authoricecream.Authorize (

    Authorized
  , withAuthorization

  , authorizedResource
  , authorizedThing
  , authorizedContext

  , Authorizes(..)

  ) where

import Control.Applicative
import Control.Monad.IO.Class
import Control.Monad.Trans.Class
import Control.Monad.Trans.Reader
import Authenticake.Authenticate

newtype Authorized ctx t r m a = Authorized {
    runAuthorized :: ReaderT r (Authenticate ctx t m) a
  } deriving (Functor, Applicative, Monad)

instance MonadTrans (Authorized ctx t r) where
  lift = Authorized . lift . lift

authorizedResource :: Monad m => Authorized ctx t r m r
authorizedResource = Authorized ask

authorizedThing :: (Functor m, Monad m) => Authorized ctx t r m t
authorizedThing = Authorized $ lift authenticatedThing

authorizedContext :: (Functor m, Monad m) => Authorized ctx t r m ctx
authorizedContext = Authorized $ lift authenticatedContext

withAuthorization
  :: forall ctx t r m a .
     ( Functor m
     , Monad m
     , Authorizes ctx t r
     )
  => ctx
  -> r
  -> (NotAuthorizedReason ctx t r -> Authenticate ctx t m a)
  -- ^ in case not authorized!
  -> Authorized ctx t r m a
  -> Authenticate ctx t m a
withAuthorization ctx resrc ifUnauthorized term = do
    datum <- authenticatedThing
    decision <- lift $ authorize ctx datum resrc
    case decision of
      Just denial -> ifUnauthorized denial
      Nothing -> runReaderT (runAuthorized term) resrc

class Authorizes ctx datum resource where
  type NotAuthorizedReason ctx datum resource
  authorize
    :: (
       )
    => ctx
    -> datum
    -> resource
    -> m (Maybe (NotAuthorizedReason ctx datum resource))
