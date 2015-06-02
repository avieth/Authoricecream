{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

module Authoricecream.Authorize (

    Authorized
  , withAuthorization
  , AuthorizationOutcome(..)

  , authorizedResource
  , authorizedThing
  , authorizedContext

  , Authorizes(..)

  ) where

import Control.Applicative
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

data AuthorizationOutcome ctx datum rsrc t where
  AuthorizationFailed :: NotAuthorizedReason ctx datum rsrc -> AuthorizationOutcome ctx datum rsrc t
  AuthorizationOK :: t -> AuthorizationOutcome ctx datum rsrc t

deriving instance (Show t, Show (NotAuthorizedReason ctx datum rsrc))
  => Show (AuthorizationOutcome ctx datum rsrc t)

instance Functor (AuthorizationOutcome ctx datum rsrc) where
  fmap f term = case term of
      AuthorizationFailed x -> AuthorizationFailed x
      AuthorizationOK x -> AuthorizationOK (f x)

withAuthorization
  :: forall ctx t r m a .
     ( Functor m
     , Monad m
     , Authorizes ctx t r
     )
  => ctx
  -> (forall s . AuthorizeF ctx t r s -> m s)
  -> r
  -> Authorized ctx t r m a
  -> Authenticate ctx t m (AuthorizationOutcome ctx t r a)
withAuthorization ctx lifter resrc term = do
    datum <- authenticatedThing
    decision <- lift . lifter $ authorize ctx datum resrc
    case decision of
      Just denial -> return (AuthorizationFailed denial)
      Nothing -> fmap AuthorizationOK (runReaderT (runAuthorized term) resrc)

class Authorizes ctx datum resource where
  type NotAuthorizedReason ctx datum resource
  type AuthorizeF ctx datum resource :: * -> *
  authorize
    :: (
       )
    => ctx
    -> datum
    -> resource
    -> (AuthorizeF ctx datum resource) (Maybe (NotAuthorizedReason ctx datum resource))
