{-# OPTIONS_GHC -fno-warn-orphans #-}
module SAML2.XML.Pickle
  ( module Text.XML.HXT.Arrow.Pickle.Xml
  , Inv.biCase
  , module Control.Invertible.Monoidal
  ) where

import Control.Invertible.Monoidal
import qualified Data.Invertible as Inv
import Text.XML.HXT.Arrow.Pickle.Schema (scSeq, scAlt)
import Text.XML.HXT.Arrow.Pickle.Xml

instance Inv.Functor PU where
  fmap (f Inv.:<->: g) p = PU -- xpWrap
    { appPickle = appPickle p . g
    , appUnPickle = fmap f $ appUnPickle p
    , theSchema = theSchema p
    }
instance Monoidal PU where
  unit = xpUnit
  p >*< q = PU -- xpPair
    { appPickle = \(a, b) -> appPickle p a . appPickle q b
    , appUnPickle = do
        a <- appUnPickle p 
        b <- appUnPickle q
        return (a, b)
    , theSchema = theSchema p `scSeq` theSchema q
    }
instance MonoidalAlt PU where
  p >|< q = PU
    { appPickle = either (appPickle p) (appPickle q)
    , appUnPickle = mchoice (Left <$> appUnPickle p) return (Right <$> appUnPickle q)
    , theSchema = theSchema p `scAlt` theSchema q
    }
