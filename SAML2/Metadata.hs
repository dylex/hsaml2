-- |
-- Metadata for the OASIS Security Assertion Markup Language (SAML) V2.0
--
-- <http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf saml-metadata-2.0-os>
module SAML2.Metadata
  ( -- * §2
    nsMD
  , EntityID
  , Endpoint(..)
  , IndexedEndpoint(..)
  , Localized(..)
  , LocalizedName
  , LocalizedURI
  , Metadata(..)
  , Extensions(..)
  , Descriptors(..)
  , Descriptor(..)
  , Organization(..)
  , Contact(..)
  , ContactType(..)
  , AdditionalMetadataLocation(..)
  , RoleDescriptor(..)
  , KeyDescriptor(..)
  , KeyTypes(..)
  , SSODescriptor(..)
  , AttributeConsumingService(..)
  , RequestedAttribute(..)
  ) where

import SAML2.XML.Types
import SAML2.Metadata.Metadata

nsMD :: Namespace
nsMD = ns
