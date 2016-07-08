module SAML2.XML
  ( module SAML2.XML.Types
  , module SAML2.Core.Datatypes
  , URI
  , Preidentified(..)
  , xpPreidentified
  , PreidentifiedURI
  , xpPreidentifiedURI
  ) where

import Network.URI (URI)

import SAML2.XML.Types
import SAML2.Core.Datatypes
import qualified SAML2.XML.Pickle as XP

data Preidentified b a
  = Preidentified !a
  | Unidentified !b
  deriving (Eq, Show)

type PreidentifiedURI = Preidentified URI

xpPreidentified :: (Eq b, Bounded a, Enum a) => XP.PU b -> (a -> b) -> XP.PU (Preidentified b a)
xpPreidentified b g = XP.xpWrap
  ( \u -> maybe (Unidentified u) Preidentified $ lookup u l
  , f
  ) b
  where
  l = [ (g a, a) | a <- [minBound..maxBound] ]
  f (Preidentified a) = g a
  f (Unidentified u) = u

xpPreidentifiedURI :: (Bounded a, Enum a) => (a -> URI) -> XP.PU (PreidentifiedURI a)
xpPreidentifiedURI = xpPreidentified XP.xpickle
