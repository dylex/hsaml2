{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE TypeOperators #-}
module SAML2.XML
  ( module SAML2.XML.Types
  , module SAML2.Core.Datatypes
  , URI
  , IP, xpIP
  , Identified(..)
  , Identifiable(..)
  , unidentify
  , xpIdentified
  , xpIdentifier
  , IdentifiedURI
  ) where

import qualified Data.Invertible as Inv
import Network.URI (URI)

import SAML2.XML.Types
import SAML2.Core.Datatypes
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS

type IP = XS.String

xpIP :: XP.PU IP
xpIP = XS.xpString

data Identified b a
  = Identified !a
  | Unidentified !b
  deriving (Eq, Show)

class Eq b => Identifiable b a | a -> b where
  identifier :: a -> b
  identifiedValues :: [a]
  default identifiedValues :: (Bounded a, Enum a) => [a]
  identifiedValues = [minBound..maxBound]
  reidentify :: b -> Identified b a
  reidentify u = maybe (Unidentified u) Identified $ lookup u l where
    l = [ (identifier a, a) | a <- identifiedValues ]

unidentify :: Identifiable b a => Identified b a -> b
unidentify (Identified a) = identifier a
unidentify (Unidentified b) = b

identify :: Identifiable b a => b Inv.<-> Identified b a
identify = reidentify Inv.:<->: unidentify

xpIdentified :: Identifiable b a => XP.PU b -> XP.PU (Identified b a)
xpIdentified = Inv.fmap identify

xpIdentifier :: Identifiable b a => XP.PU b -> String -> XP.PU a
xpIdentifier b t = XP.xpWrapEither
  ( \u -> case reidentify u of
      Identified a -> Right a
      Unidentified _ -> Left ("invalid " ++ t)
  , identifier
  ) b

type IdentifiedURI = Identified URI

instance Identifiable URI a => XP.XmlPickler (Identified URI a) where
  xpickle = xpIdentified XS.xpAnyURI
