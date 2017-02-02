{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
-- Metadata for SAML V2.0
-- 
-- <http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf saml-metadata-2.0-os> §2
module SAML2.Metadata.Metadata where

import Data.Foldable (fold)
import qualified Network.URI as URI
import qualified Text.XML.HXT.Arrow.Pickle.Schema as XPS

import SAML2.Lens
import SAML2.XML
import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Signature.Types as DS
import qualified SAML2.XML.Encryption as XEnc
import SAML2.Core.Namespaces
import SAML2.Core.Versioning
import SAML2.Core.Identifiers
import qualified SAML2.Core.Assertions as SAML
import SAML2.Bindings.Identifiers

ns :: Namespace
ns = mkNamespace "md" $ samlURN SAML20 ["metadata"]

xpElem :: String -> XP.PU a -> XP.PU a
xpElem = xpTrimElemNS ns

-- |§2.2.1
type EntityID = AnyURI

xpEntityID :: XP.PU EntityID
xpEntityID = XS.xpAnyURI -- XXX maxLength=1024

-- |§2.2.2
data Endpoint = Endpoint
  { endpointBinding :: IdentifiedURI Binding
  , endpointLocation :: AnyURI
  , endpointResponseLocation :: Maybe AnyURI
  , endpointAttrs :: Nodes
  , endpointXML :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler Endpoint where
  xpickle = [XP.biCase|
      ((((b, l), r), a), x) <-> Endpoint b l r a x|]
    XP.>$<  (XP.xpAttr "Binding" XP.xpickle
      XP.>*< XP.xpAttr "Location" XS.xpAnyURI
      XP.>*< XP.xpAttrImplied "ResponseLocation" XS.xpAnyURI
      XP.>*< XP.xpAnyAttrs
      XP.>*< XP.xpList xpTrimAnyElem)

-- |§2.2.3
data IndexedEndpoint = IndexedEndpoint
  { indexedEndpoint :: Endpoint
  , indexedEndpointIndex :: XS.UnsignedShort
  , indexedEndpointIsDefault :: XS.Boolean
  } deriving (Eq, Show)

instance XP.XmlPickler IndexedEndpoint where
  xpickle = [XP.biCase|
      ((i, d), e) <-> IndexedEndpoint e i d|]
    XP.>$<  (XP.xpAttr "index" XS.xpUnsignedShort
      XP.>*< XP.xpDefault False (XP.xpAttr "isDefault" XS.xpBoolean)
      XP.>*< XP.xpickle)

data Localized a = Localized
  { localizedLang :: XS.Language
  , localized :: a
  } deriving (Eq, Show)

xpLocalized :: XP.PU a -> XP.PU (Localized a)
xpLocalized p = [XP.biCase|
    (l, x) <-> Localized l x|]
  XP.>$<  (xpXmlLang
    XP.>*< p)

-- |§2.2.4
type LocalizedName = Localized XS.String

instance XP.XmlPickler LocalizedName where
  xpickle = xpLocalized XS.xpString

-- |§2.2.5
type LocalizedURI = Localized XS.AnyURI

instance XP.XmlPickler LocalizedURI where
  xpickle = xpLocalized XS.xpAnyURI

data Metadata
  = EntityDescriptor
    { entityID :: EntityID
    , metadataID :: Maybe XS.ID
    , metadataValidUntil :: Maybe XS.DateTime
    , metadataCacheDuration :: Maybe XS.Duration
    , entityAttrs :: Nodes
    , metadataSignature :: Maybe DS.Signature
    , metadataExtensions :: Extensions
    , entityDescriptors :: Descriptors
    , entityOrganization :: Maybe Organization
    , entityContactPerson :: [Contact]
    , entityAditionalMetadataLocation :: [AdditionalMetadataLocation]
    } -- ^§2.3.2
  | EntitiesDescriptor
    { metadataID :: Maybe XS.ID
    , metadataValidUntil :: Maybe XS.DateTime
    , metadataCacheDuration :: Maybe XS.Duration
    , entitiesName :: Maybe XS.String
    , metadataSignature :: Maybe DS.Signature
    , metadataExtensions :: Extensions
    , entities :: List1 Metadata
    } -- ^§2.3.1
  deriving (Eq, Show)

instance XP.XmlPickler Metadata where
  xpickle = [XP.biCase|
      Left ((((((((((e, i), vu), cd), xa), sig), ext), desc), org), cp), aml) <-> EntityDescriptor e i vu cd xa sig ext desc org cp aml
      Right ((((((i, vu), cd), n), sig), ext), l) <-> EntitiesDescriptor i vu cd n sig ext l|]
    XP.>$< (xpElem "EntityDescriptor"
            (XP.xpAttr "entityID" xpEntityID
      XP.>*< XP.xpAttrImplied "ID" XS.xpID
      XP.>*< XP.xpAttrImplied "validUntil" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "cacheDuration" XS.xpDuration
      XP.>*< XP.xpAnyAttrs
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< XP.xpList XP.xpickle
      XP.>*< XP.xpList XP.xpickle)
    XP.>|<  xpElem "EntitiesDescriptor"
            (XP.xpAttrImplied "ID" XS.xpID
      XP.>*< XP.xpAttrImplied "validUntil" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "cacheDuration" XS.xpDuration
      XP.>*< XP.xpAttrImplied "Name" XS.xpString
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< xpList1 XP.xpickle))

instance DS.Signable Metadata where
  signature' = $(fieldLens 'metadataSignature)
  signedID = fold . metadataID

-- |§2.3.1 empty list means missing
newtype Extensions = Extensions{ extensions :: Nodes }
  deriving (Eq, Show, Monoid)

instance XP.XmlPickler Extensions where
  xpickle = XP.xpDefault (Extensions []) $
    xpElem "Extensions" $ [XP.biCase|
      x <-> Extensions x|]
    XP.>$<  (XP.xpList1 xpTrimAnyElem)

data Descriptors
  = Descriptors{ descriptors :: List1 Descriptor }
  | AffiliationDescriptor
    { affiliationDescriptorAffiliationOwnerID :: EntityID
    , affiliationDescriptorID :: Maybe XS.ID
    , affiliationDescriptorValidUntil :: Maybe XS.DateTime
    , affiliationDescriptorCacheDuration :: Maybe XS.Duration
    , affiliationDescriptorAttrs :: Nodes
    , affiliationDescriptorSignature :: Maybe DS.Signature
    , affiliationDescriptorExtensions :: Extensions
    , affiliationDescriptorAffiliateMember :: List1 EntityID
    , affiliationDescriptorKeyDescriptor :: [KeyDescriptor]
    } -- ^§2.5
  deriving (Eq, Show)

instance XP.XmlPickler Descriptors where
  xpickle = [XP.biCase|
      Left l <-> Descriptors l
      Right ((((((((o, i), vu), cd), a), sig), ext), am), kd) <-> AffiliationDescriptor o i vu cd a sig ext am kd|]
    XP.>$<  (xpList1 XP.xpickle
    XP.>|<  xpElem "AffiliationDescriptor"
            (XP.xpAttr "affiliationOwnerID" xpEntityID
      XP.>*< XP.xpAttrImplied "ID" XS.xpID
      XP.>*< XP.xpAttrImplied "validUntil" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "cacheDuration" XS.xpDuration
      XP.>*< XP.xpAnyAttrs
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< xpList1 (xpElem "AffiliateMember" xpEntityID)
      XP.>*< XP.xpList XP.xpickle))

data Descriptor
  = Descriptor
    { descriptorRole :: !RoleDescriptor
    } -- ^§2.4.1
  | IDPSSODescriptor
    { descriptorRole :: !RoleDescriptor
    , descriptorSSO :: !SSODescriptor
    , descriptorWantAuthnRequestsSigned :: XS.Boolean
    , descriptorSingleSignOnService :: List1 Endpoint
    , descriptorNameIDMappingService :: [Endpoint]
    , descriptorAssertionIDRequestService :: [Endpoint]
    , descriptorAttributeProfile :: [XS.AnyURI]
    , descriptorAttribute :: [SAML.Attribute]
    } -- ^§2.4.3
  | SPSSODescriptor
    { descriptorRole :: !RoleDescriptor
    , descriptorSSO :: !SSODescriptor
    , descriptorAuthnRequestsSigned :: XS.Boolean
    , descriptorWantAssertionsSigned :: XS.Boolean
    , descriptorAssertionConsumerService :: List1 IndexedEndpoint
    , descriptorAttributeConsumingService :: [AttributeConsumingService]
    } -- ^§2.4.4
  | AuthnAuthorityDescriptor
    { descriptorRole :: !RoleDescriptor
    , descriptorAuthnQueryService :: List1 Endpoint
    , descriptorAssertionIDRequestService :: [Endpoint]
    , descriptorNameIDFormat :: [IdentifiedURI NameIDFormat]
    } -- ^§2.4.5
  | AttributeAuthorityDescriptor
    { descriptorRole :: !RoleDescriptor
    , descriptorAttributeService :: List1 Endpoint
    , descriptorAssertionIDRequestService :: [Endpoint]
    , descriptorNameIDFormat :: [IdentifiedURI NameIDFormat]
    , descriptorAttributeProfile :: [XS.AnyURI]
    , descriptorAttribute :: [SAML.Attribute]
    } -- ^§2.4.7
  | PDPDescriptor
    { descriptorRole :: !RoleDescriptor
    , descriptorAuthzService :: List1 Endpoint
    , descriptorAssertionIDRequestService :: [Endpoint]
    , descriptorNameIDFormat :: [IdentifiedURI NameIDFormat]
    } -- ^§2.4.6
  deriving (Eq, Show)

instance XP.XmlPickler Descriptor where
  xpickle = [XP.biCase|
      Left (Left (Left (Left (Left r)))) <-> Descriptor r
      Left (Left (Left (Left (Right (((((((ws, r), s), sso), nim), air), ap), a))))) <-> IDPSSODescriptor r s ws sso nim air ap a
      Left (Left (Left (Right (((((a, w), r), s), e), t)))) <-> SPSSODescriptor r s a w e t
      Left (Left (Right (((r, a), s), n))) <-> AuthnAuthorityDescriptor r a s n
      Left (Right (((((r, a), s), n), tp), t)) <-> AttributeAuthorityDescriptor r a s n tp t
      Right (((r, a), s), n) <-> PDPDescriptor r a s n|]
    XP.>$< (xpElem "RoleDescriptor" XP.xpickle
    XP.>|<  xpElem "IDPSSODescriptor"
            (XP.xpDefault False (XP.xpAttr "WantAuthnRequestsSigned" XS.xpBoolean)
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< xpList1 (xpElem "SingleSignOnService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "NameIDMappingService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "AssertionIDRequestService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "AttributeProfile" XS.xpAnyURI)
      XP.>*< XP.xpList XP.xpickle)
    XP.>|<  xpElem "SPSSODescriptor"
            (XP.xpDefault False (XP.xpAttr "AuthnRequestsSigned" XS.xpBoolean)
      XP.>*< XP.xpDefault False (XP.xpAttr "WantAssertionsSigned" XS.xpBoolean)
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< xpList1 (xpElem "AssertionConsumerService" XP.xpickle)
      XP.>*< XP.xpList XP.xpickle)
    XP.>|<  xpElem "AuthnAuthorityDescriptor"
            (XP.xpickle
      XP.>*< xpList1 (xpElem "AuthnQueryService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "AssertionIDRequestService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "NameIDFormat" XP.xpickle))
    XP.>|<  xpElem "AttributeAuthorityDescriptor"
            (XP.xpickle
      XP.>*< xpList1 (xpElem "AttributeService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "AssertionIDRequestService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "NameIDFormat" XP.xpickle)
      XP.>*< XP.xpList (xpElem "AttributeProfile" XS.xpAnyURI)
      XP.>*< XP.xpList XP.xpickle)
    XP.>|<  xpElem "PDPDescriptor"
            (XP.xpickle
      XP.>*< xpList1 (xpElem "AuthzService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "AssertionIDRequestService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "NameIDFormat" XP.xpickle)))

-- |§2.3.2.1
data Organization = Organization
  { organizationAttrs :: Nodes
  , organizationExtensions :: Extensions
  , organizationName :: List1 LocalizedName
  , organizationDisplayName :: List1 LocalizedName
  , organizationURL :: List1 LocalizedURI
  } deriving (Eq, Show)

instance XP.XmlPickler Organization where
  xpickle = xpElem "Organization" $
    [XP.biCase|
      ((((a, e), n), d), u) <-> Organization a e n d u|]
    XP.>$<  (XP.xpAnyAttrs
      XP.>*< XP.xpickle
      XP.>*< xpList1 (xpElem "OrganizationName" XP.xpickle)
      XP.>*< xpList1 (xpElem "OrganizationDisplayName" XP.xpickle)
      XP.>*< xpList1 (xpElem "OrganizationURL" XP.xpickle))

-- |§2.3.2.2
data Contact = ContactPerson
  { contactType :: ContactType
  , contactAttrs :: Nodes
  , contactExtensions :: Extensions
  , contactCompany :: Maybe XS.String
  , contactGivenName :: Maybe XS.String
  , contactSurName :: Maybe XS.String
  , contactEmailAddress :: [XS.AnyURI]
  , contactTelephoneNumber :: [XS.String]
  } deriving (Eq, Show)

instance XP.XmlPickler Contact where
  xpickle = xpElem "ContactPerson" $
    [XP.biCase|
      (((((((t, a), ext), c), g), s), e), tn) <-> ContactPerson t a ext c g s e tn|]
    XP.>$<  (XP.xpAttr "contactType" XP.xpickle
      XP.>*< XP.xpAnyAttrs
      XP.>*< XP.xpickle
      XP.>*< XP.xpOption (xpElem "Company" XS.xpString)
      XP.>*< XP.xpOption (xpElem "GivenName" XS.xpString)
      XP.>*< XP.xpOption (xpElem "SurName" XS.xpString)
      XP.>*< XP.xpList (xpElem "EmailAddress" XS.xpAnyURI)
      XP.>*< XP.xpList (xpElem "TelephoneNumber" XS.xpString))

data ContactType
  = ContactTypeTechnical
  | ContactTypeSupport
  | ContactTypeAdministrative
  | ContactTypeBilling
  | ContactTypeOther
  deriving (Eq, Enum, Bounded, Show)

instance Identifiable XString ContactType where
  identifier ContactTypeTechnical       = "technical"
  identifier ContactTypeSupport         = "support"
  identifier ContactTypeAdministrative  = "administrative"
  identifier ContactTypeBilling         = "billing"
  identifier ContactTypeOther           = "other"
instance XP.XmlPickler ContactType where
  xpickle = xpIdentifier (XP.xpTextDT (XPS.scDT (namespaceURIString ns) "ContactTypeType" [])) "ContactTypeType"

-- |§2.3.2.3
data AdditionalMetadataLocation = AdditionalMetadataLocation
  { additionalMetadataLocationNamespace :: XS.AnyURI
  , additionalMetadataLocation :: XS.AnyURI
  } deriving (Eq, Show)

instance XP.XmlPickler AdditionalMetadataLocation where
  xpickle = xpElem "AdditionalMetadataLocation" $
    [XP.biCase|
      (n, l) <-> AdditionalMetadataLocation n l|]
    XP.>$<  (XP.xpAttr "namespace" XS.xpAnyURI
      XP.>*< XS.xpAnyURI)

-- |§2.4.1
data RoleDescriptor = RoleDescriptor
  { roleDescriptorID :: Maybe XS.ID
  , roleDescriptorValidUntil :: Maybe XS.DateTime
  , roleDescriptorCacheDuration :: Maybe XS.Duration
  , roleDescriptorProtocolSupportEnumeration :: [XS.AnyURI]
  , roleDescriptorErrorURL :: Maybe XS.AnyURI
  , roleDescriptorAttrs :: Nodes
  , roleDescriptorSignature :: Maybe DS.Signature
  , roleDescriptorExtensions :: Extensions
  , roleDescriptorKeyDescriptor :: [KeyDescriptor]
  , roleDescriptorOrganization :: Maybe Organization
  , roleDescriptorContactPerson :: [Contact]
  } deriving (Eq, Show)

instance XP.XmlPickler RoleDescriptor where
  xpickle = [XP.biCase|
      ((((((((((i, vu), cd), ps), eu), a), sig), ext), key), org), cp) <-> RoleDescriptor i vu cd ps eu a sig ext key org cp|]
    XP.>$<  (XP.xpAttrImplied "ID" XS.xpID
      XP.>*< XP.xpAttrImplied "validUntil" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "cacheDuration" XS.xpDuration
      XP.>*< XP.xpAttr "protocolSupportEnumeration" xpAnyURIList
      XP.>*< XP.xpAttrImplied "errorURL" XS.xpAnyURI
      XP.>*< XP.xpAnyAttrs
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< XP.xpList XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpList XP.xpickle)
    where
    xpAnyURIList = XP.xpWrapEither
      ( mapM (maybe (Left "invalid anyURI") Right . URI.parseURIReference) . words
      , tail . foldr ((.) (' ':) . URI.uriToString id) ""
      ) $ XP.xpTextDT $ XPS.scDT (namespaceURIString ns) "anyURIListType" []

instance DS.Signable RoleDescriptor where
  signature' = $(fieldLens 'roleDescriptorSignature)
  signedID = fold . roleDescriptorID

-- |§2.4.1.1
data KeyDescriptor = KeyDescriptor
  { keyDescriptorUse :: KeyTypes
  , keyDescriptorKeyInfo :: DS.KeyInfo
  , keyDescriptorEncryptionMethod :: [XEnc.EncryptionMethod]
  } deriving (Eq, Show)

instance XP.XmlPickler KeyDescriptor where
  xpickle = xpElem "KeyDescriptor" $
    [XP.biCase|
      ((t, i), m) <-> KeyDescriptor t i m|]
    XP.>$<  (XP.xpDefault KeyTypeBoth (XP.xpAttr "use" XP.xpickle)
      XP.>*< XP.xpickle
      XP.>*< XP.xpList (xpElem "EncryptionMethod" XEnc.xpEncryptionMethodType))

data KeyTypes
  = KeyTypeSigning
  | KeyTypeEncryption
  | KeyTypeBoth
  deriving (Eq, Enum, Bounded, Show)

-- |Does the second KeyTypes include the first type of use?
keyType :: KeyTypes -> KeyTypes -> Bool
keyType _ KeyTypeBoth = True
keyType k t = k == t

instance Identifiable XString KeyTypes where
  identifier KeyTypeSigning     = "signing"
  identifier KeyTypeEncryption  = "encryption"
  identifier KeyTypeBoth        = ""
  identifiedValues = [KeyTypeEncryption, KeyTypeSigning]
instance XP.XmlPickler KeyTypes where
  xpickle = xpIdentifier (XP.xpTextDT (XPS.scDT (namespaceURIString ns) "KeyTypes" [])) "KeyTypes"

-- |§2.4.2
data SSODescriptor = SSODescriptor
  { ssoDescriptorArtifactResolutionService :: [IndexedEndpoint]
  , ssoDescriptorSingleLogoutService :: [Endpoint]
  , ssoDescriptorManageNameIDService :: [Endpoint]
  , ssoDescriptorNameIDFormat :: [IdentifiedURI NameIDFormat]
  } deriving (Eq, Show)

instance XP.XmlPickler SSODescriptor where
  xpickle = [XP.biCase|
      (((a, s), m), n) <-> SSODescriptor a s m n|]
    XP.>$<  (XP.xpList (xpElem "ArtifactResolutionService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "SingleLogoutService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "ManageNameIDService" XP.xpickle)
      XP.>*< XP.xpList (xpElem "NameIDFormat" XP.xpickle))

-- |§2.4.4.1
data AttributeConsumingService = AttributeConsumingService
  { attributeConsumingServiceIndex :: XS.UnsignedShort
  , attributeConsumingServiceIsDefault :: Bool
  , attributeConsumingServiceServiceName :: List1 LocalizedName
  , attributeConsumingServiceServiceDescription :: [LocalizedName]
  , attributeConsumingServiceRequestedAttribute :: List1 RequestedAttribute
  } deriving (Eq, Show)

instance XP.XmlPickler AttributeConsumingService where
  xpickle = xpElem "AttributeConsumingService" $
    [XP.biCase|
      ((((i, d), sn), sd), ra) <-> AttributeConsumingService i d sn sd ra|]
    XP.>$<  (XP.xpAttr "index" XS.xpUnsignedShort
      XP.>*< XP.xpDefault False (XP.xpAttr "isDefault" XS.xpBoolean)
      XP.>*< xpList1 (xpElem "ServiceName" XP.xpickle)
      XP.>*< XP.xpList (xpElem "ServiceDescription" XP.xpickle)
      XP.>*< xpList1 XP.xpickle)

-- |§2.4.4.1.1
data RequestedAttribute = RequestedAttribute
  { requestedAttribute :: !SAML.Attribute
  , requestedAttributeIsRequired :: Bool
  } deriving (Eq, Show)

instance XP.XmlPickler RequestedAttribute where
  xpickle = xpElem "RequestedAttribute" $
    [XP.biCase|
      (r, a) <-> RequestedAttribute a r|]
    XP.>$<  (XP.xpDefault False (XP.xpAttr "isRequired" XS.xpBoolean)
      XP.>*< SAML.xpAttributeType)
