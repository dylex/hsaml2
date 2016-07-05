module SAML2.Version
  ( SAMLVersion(..)
  ) where

import Data.Version (Version, makeVersion)

data SAMLVersion
  = SAML10
  | SAML11
  | SAML20

samlVersion :: SAMLVersion -> Version
samlVersion SAML10 = makeVersion [1,0]
samlVersion SAML11 = makeVersion [1,1]
samlVersion SAML20 = makeVersion [2,0]

instance Show SAMLVersion where
  show = show . samlVersion
  showsPrec p = showsPrec p . samlVersion
