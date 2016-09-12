-- |
-- OASIS Security Assertion Markup Language (SAML) V2.0
--
module SAML2
  ( Identified(..)
    -- * Assertions and Protocols
  , module SAML2.Core
    -- * Bindings
  , module SAML2.Bindings
  ) where

import SAML2.XML
import SAML2.Core
import SAML2.Bindings
