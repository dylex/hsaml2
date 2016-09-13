-- |
-- OASIS Security Assertion Markup Language (SAML) V2.0
--
module SAML2
  ( NonEmpty(..)
  , Identified(..)
  , namespaceURI
  , samlToXML
  , xmlToSAML
    -- * Assertions and Protocols
  , module SAML2.Core
    -- * Bindings
  , module SAML2.Bindings
    -- * Metadata
  , module SAML2.Metadata
  ) where

import Data.List.NonEmpty (NonEmpty(..))
import SAML2.XML
import SAML2.Core
import SAML2.Bindings
import SAML2.Metadata
