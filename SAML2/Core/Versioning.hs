-- |
-- SAML Versioning
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §4
module SAML2.Core.Versioning
  ( SAMLVersion(..)
  , samlVersion
  ) where

import Data.Version (Version, makeVersion)

import qualified SAML2.XML.Pickle as XP

data SAMLVersion
  = SAML10
  | SAML11
  | SAML20
  deriving (Eq, Ord, Enum, Bounded)

samlVersion :: SAMLVersion -> Version
samlVersion SAML10 = makeVersion [1,0]
samlVersion SAML11 = makeVersion [1,1]
samlVersion SAML20 = makeVersion [2,0]

instance Show SAMLVersion where
  show SAML10 = "1.0"
  show SAML11 = "1.1"
  show SAML20 = "2.0"

instance Read SAMLVersion where
  readsPrec _ ('1':'.':'0':s) = [(SAML10, s)]
  readsPrec _ ('1':'.':'1':s) = [(SAML11, s)]
  readsPrec _ ('2':'.':'0':s) = [(SAML20, s)]
  readsPrec _ _ = []

instance XP.XmlPickler SAMLVersion where
  xpickle = XP.xpPrim    
