{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}

module Authoricecream.Authorize (

    Authorize
  , withAuthorization

  , authorizedResource
  , authorizedThing

  , Authorizer(..)

  ) where

import Control.Applicative
import Control.Monad.IO.Class
import Control.Monad.Trans.Class
import Control.Monad.Trans.Reader
import Authenticake.Authenticate

newtype Authorize ctx t r m a = Authorize {
    runAuthorize :: ReaderT r (Authenticate ctx t m) a
  } deriving (Functor, Applicative, Monad)

instance MonadTrans (Authorize ctx t r) where
  lift = Authorize . lift . lift

authorizedResource :: Monad m => Authorize ctx t r m r
authorizedResource = Authorize ask

authorizedThing :: Monad m => Authorize ctx t r m t
authorizedThing = Authorize $ lift authenticatedThing

withAuthorization
  :: forall ctx t r m a .
     ( MonadIO m
     , Authorizer ctx t r
     )
  => ctx
  -> r
  -> (NotAuthorizedReason ctx t r -> Authenticate ctx t m a)
  -- ^ in case not authorized!
  -> Authorize ctx t r m a
  -> Authenticate ctx t m a
withAuthorization ctx resrc ifUnauthorized term = do
    datum <- authenticatedThing
    decision <- lift $ authorize ctx datum resrc
    case decision of
      Just denial -> ifUnauthorized denial
      Nothing -> runReaderT (runAuthorize term) resrc

class Authorizer ctx datum resource where
  type NotAuthorizedReason ctx datum resource
  authorize
    :: ( MonadIO m
       )
    => ctx
    -> datum
    -> resource
    -> m (Maybe (NotAuthorizedReason ctx datum resource))
