{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- SAML Protocols
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §3
module SAML2.Core.Protocols where

import Control.Lens (Lens', lens, (.~), (^.))
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy, asProxyTypeOf)
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.Arrow.Pickle.Schema as XPS

import SAML2.Lens
import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Signature.Types as DS
import SAML2.Core.Namespaces
import SAML2.Core.Versioning
import qualified SAML2.Core.Assertions as SAML
import SAML2.Core.Identifiers
import SAML2.Bindings.General (RelayState)
import SAML2.Bindings.Identifiers

ns :: Namespace
ns = mkNamespace "samlp" $ samlURN SAML20 ["protocol"]

xpElem :: String -> XP.PU a -> XP.PU a
xpElem = xpTrimElemNS ns

data ProtocolType = ProtocolType
  { protocolID :: XS.ID
  , protocolVersion :: SAMLVersion
  , protocolIssueInstant :: DateTime
  , protocolDestination :: Maybe AnyURI
  , protocolConsent :: IdentifiedURI Consent
  , protocolIssuer :: Maybe SAML.Issuer
  , protocolSignature :: Maybe DS.Signature
  , protocolExtensions :: [Node]
  , relayState :: Maybe RelayState -- ^out-of-band data, not part of XML
  } deriving (Eq, Show)

instance XP.XmlPickler ProtocolType where
  xpickle = XP.xpWrap (pt, tp)
    $       (XP.xpAttr "ID" XS.xpID
      XP.>*< XP.xpAttr "Version" XP.xpickle
      XP.>*< XP.xpAttr "IssueInstant" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "Destination" XS.xpAnyURI
      XP.>*< XP.xpDefault (Identified ConsentUnspecified) (XP.xpAttr "Consent" XP.xpickle)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption (xpElem "Extensions" $ XP.xpList1 xpTrimAnyElem))
    where
    pt (((((((i, v), t), d), c), u), g), x) = ProtocolType i v t d c u g (fromMaybe [] x) Nothing
    tp (ProtocolType i v t d c u g [] _) = (((((((i, v), t), d), c), u), g), Nothing)
    tp (ProtocolType i v t d c u g x _) = (((((((i, v), t), d), c), u), g), Just x)

class XP.XmlPickler a => SAMLProtocol a where
  samlProtocol' :: Lens' a ProtocolType
  isSAMLResponse :: a -> Bool
  isSAMLResponse_ :: Proxy a -> Maybe Bool
  isSAMLResponse_ = Just . isSAMLResponse . asProxyTypeOf undefined 

samlProtocolToXML :: SAMLProtocol a => a -> BSL.ByteString
samlProtocolToXML = XP.pickleDoc XP.xpickle
  HXT.>>> HXT.runLA (HXT.xshowBlob (HXT.getChildren
    HXT.>>> HXT.cleanupNamespaces HXT.collectPrefixUriPairs))
  HXT.>>> BSL.concat

samlXMLToProtocol :: SAMLProtocol a => BSL.ByteString -> Either String a
samlXMLToProtocol = foldr (je . XP.unpickleDoc' XP.xpickle) (Left "invalid XML")
  . HXT.runLA
    (HXT.xreadDoc
    -- HXT.>>> HXT.removeDocWhiteSpace -- XXX insufficient?
    HXT.>>> HXT.propagateNamespaces
    HXT.>>> HXT.processBottomUp (HXT.processAttrl (HXT.none `HXT.when` HXT.isNamespaceDeclAttr)))
  . BSLC.unpack -- XXX encoding?
  where
  je x (Left _) = x
  je _ x = x

-- |§3.2.1
newtype RequestAbstractType = RequestAbstractType
  { requestProtocol :: ProtocolType
  } deriving (Eq, Show)

instance XP.XmlPickler RequestAbstractType where
  xpickle = [XP.biCase|p <-> RequestAbstractType p|]
    XP.>$< XP.xpickle

class SAMLProtocol a => SAMLRequest a where
  samlRequest' :: Lens' a RequestAbstractType

requestProtocol' :: Lens' RequestAbstractType ProtocolType
requestProtocol' = $(fieldLens 'requestProtocol)

-- |§3.2.2
data StatusResponseType = StatusResponseType
  { statusProtocol :: !ProtocolType
  , statusInResponseTo :: Maybe XS.NCName
  , status :: Status
  } deriving (Eq, Show)

instance XP.XmlPickler StatusResponseType where
  xpickle = [XP.biCase|((p, r), s) <-> StatusResponseType p r s|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpAttrImplied "InResponseTo" XS.xpNCName
      XP.>*< XP.xpickle)

class SAMLProtocol a => SAMLResponse a where
  samlResponse' :: Lens' a StatusResponseType

statusProtocol' :: Lens' StatusResponseType ProtocolType
statusProtocol' = $(fieldLens 'statusProtocol)

-- |§3.2.2.1
data Status = Status
  { statusCode :: StatusCode
  , statusMessage :: Maybe XString -- ^§3.2.2.3
  , statusDetail :: Maybe Nodes -- ^§3.2.2.4
  } deriving (Eq, Show)

instance XP.XmlPickler Status where
  xpickle = xpElem "Status" $ [XP.biCase|
      ((c, m), d) <-> Status c m d|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpOption (xpElem "StatusMessage" XP.xpText0)
      XP.>*< XP.xpOption (xpElem "StatusDetail" xpAnyCont))

-- |§3.2.2.2
data StatusCode = StatusCode
  { statusCode1 :: StatusCode1
  , statusCodes :: [IdentifiedURI StatusCode2]
  } deriving (Eq, Show)

instance XP.XmlPickler StatusCode where
  xpickle = xpElem "StatusCode" $ [XP.biCase|
      (v, c) <-> StatusCode v c|]
    XP.>$<  (XP.xpAttr "Value" XP.xpickle
      XP.>*< xpStatusCodes) where
    xpStatusCodes = [XP.biCase|
        Nothing <-> []
        Just (v, c) <-> v : c|]
      XP.>$< XP.xpOption (xpElem "StatusCode" $
               XP.xpAttr "Value" XP.xpickle
        XP.>*< xpStatusCodes)

data StatusCode1
  = StatusSuccess
  | StatusRequester
  | StatusResponder
  | StatusVersionMismatch
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI StatusCode1 where
  identifier = samlURNIdentifier "status" . f where
    f StatusSuccess         = (SAML20, "Success")
    f StatusRequester       = (SAML20, "Requester")
    f StatusResponder       = (SAML20, "Responder")
    f StatusVersionMismatch = (SAML20, "VersionMismatch")
instance XP.XmlPickler StatusCode1 where
  xpickle = xpIdentifier XS.xpAnyURI "status"

data StatusCode2
  = StatusAuthnFailed
  | StatusInvalidAttrNameOrValue  
  | StatusInvalidNameIDPolicy     
  | StatusNoAuthnContext          
  | StatusNoAvailableIDP          
  | StatusNoPassive               
  | StatusNoSupportedIDP          
  | StatusPartialLogout           
  | StatusProxyCountExceeded      
  | StatusRequestDenied           
  | StatusRequestUnsupported      
  | StatusRequestVersionDeprecated
  | StatusRequestVersionTooHigh   
  | StatusRequestVersionTooLow    
  | StatusResourceNotRecognized   
  | StatusTooManyResponses        
  | StatusUnknownAttrProfile      
  | StatusUnknownPrincipal        
  | StatusUnsupportedBinding      
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI StatusCode2 where
  identifier = samlURNIdentifier "status" . f where
    f StatusAuthnFailed               = (SAML20, "AuthnFailed")
    f StatusInvalidAttrNameOrValue    = (SAML20, "InvalidAttrNameOrValue")
    f StatusInvalidNameIDPolicy       = (SAML20, "InvalidNameIDPolicy")
    f StatusNoAuthnContext            = (SAML20, "NoAuthnContext")
    f StatusNoAvailableIDP            = (SAML20, "NoAvailableIDP")
    f StatusNoPassive                 = (SAML20, "NoPassive")
    f StatusNoSupportedIDP            = (SAML20, "NoSupportedIDP")
    f StatusPartialLogout             = (SAML20, "PartialLogout")
    f StatusProxyCountExceeded        = (SAML20, "ProxyCountExceeded")
    f StatusRequestDenied             = (SAML20, "RequestDenied")
    f StatusRequestUnsupported        = (SAML20, "RequestUnsupported")
    f StatusRequestVersionDeprecated  = (SAML20, "RequestVersionDeprecated")
    f StatusRequestVersionTooHigh     = (SAML20, "RequestVersionTooHigh")
    f StatusRequestVersionTooLow      = (SAML20, "RequestVersionTooLow")
    f StatusResourceNotRecognized     = (SAML20, "ResourceNotRecognized")
    f StatusTooManyResponses          = (SAML20, "TooManyResponses")
    f StatusUnknownAttrProfile        = (SAML20, "UnknownAttrProfile")
    f StatusUnknownPrincipal          = (SAML20, "UnknownPrincipal")
    f StatusUnsupportedBinding        = (SAML20, "UnsupportedBinding")

successStatus :: Status
successStatus = Status (StatusCode StatusSuccess []) Nothing Nothing

-- |§3.3.1
data AssertionIDRequest = AssertionIDRequest
  { assertionIDRequest :: !RequestAbstractType
  , assertionIDRequestRef :: List1 (SAML.AssertionIDRef)
  } deriving (Eq, Show)

instance XP.XmlPickler AssertionIDRequest where
  xpickle = xpElem "AssertionIDRequest" $ [XP.biCase|
      (q, r) <-> AssertionIDRequest q r|]
    XP.>$<  (XP.xpickle
      XP.>*< xpList1 XP.xpickle)
instance SAMLProtocol AssertionIDRequest where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest AssertionIDRequest where
  samlRequest' = $(fieldLens 'assertionIDRequest)

-- |§3.3.2.1
data SubjectQueryAbstractType = SubjectQueryAbstractType
  { subjectQuery :: !RequestAbstractType
  , subjectQuerySubject :: SAML.Subject
  } deriving (Eq, Show)

instance XP.XmlPickler SubjectQueryAbstractType where
  xpickle = [XP.biCase|
      (q, r) <-> SubjectQueryAbstractType q r|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpickle)

subjectQuery' :: Lens' SubjectQueryAbstractType RequestAbstractType
subjectQuery' = $(fieldLens 'subjectQuery)

-- |§3.3.2.2
data AuthnQuery = AuthnQuery
  { authnQuery :: !SubjectQueryAbstractType
  , authnQuerySessionIndex :: Maybe XString
  , authnQueryRequestedAuthnContext :: Maybe RequestedAuthnContext
  } deriving (Eq, Show)

instance XP.XmlPickler AuthnQuery where
  xpickle = xpElem "AuthnQuery" $ [XP.biCase|
      ((q, i), c) <-> AuthnQuery q i c|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpAttrImplied "SessionIndex" XS.xpString
      XP.>*< XP.xpOption XP.xpickle)
instance SAMLProtocol AuthnQuery where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest AuthnQuery where
  samlRequest' = authnQuery' . subjectQuery' where
    authnQuery' = $(fieldLens 'authnQuery)

-- |§3.3.2.2.1
data RequestedAuthnContext = RequestedAuthnContext
  { requestedAuthnContextComparison :: Maybe AuthnContextComparisonType
  , requestedAuthnContextRefs :: AuthnContextRefs
  } deriving (Eq, Show)

instance XP.XmlPickler RequestedAuthnContext where
  xpickle = xpElem "RequestedAuthnContext" $ [XP.biCase|
      (c, r) <-> RequestedAuthnContext c r|]
    XP.>$<  (XP.xpAttrImplied "Comparison" XP.xpickle
      XP.>*< XP.xpickle)

data AuthnContextRefs
  = AuthnContextClassRefs (List1 AnyURI)
  | AuthnContextDeclRefs (List1 AnyURI)
  deriving (Eq, Show)

instance XP.XmlPickler AuthnContextRefs where
  xpickle = [XP.biCase|
      Left l <-> AuthnContextClassRefs l
      Right l <-> AuthnContextDeclRefs l|]
    XP.>$<  (xpList1 (SAML.xpElem "AuthnContextClassRef" XS.xpAnyURI)
      XP.>|< xpList1 (SAML.xpElem "AuthnContextDeclRef" XS.xpAnyURI))

data AuthnContextComparisonType
  = ComparisonExact
  | ComparisonMinimum
  | ComparisonMaximum
  | ComparisonBetter
  deriving (Eq, Enum, Bounded, Show)

instance Identifiable XString AuthnContextComparisonType where
  identifier ComparisonExact = "exact"
  identifier ComparisonMinimum = "minimum"
  identifier ComparisonMaximum = "maximum"
  identifier ComparisonBetter = "better"
instance XP.XmlPickler AuthnContextComparisonType where
  xpickle = xpIdentifier (XP.xpTextDT (XPS.scDT (namespaceURI ns) "AuthnContextComparisonType" [])) "AuthnContextComparisonType"

-- |§3.3.2.3
data AttributeQuery = AttributeQuery
  { attributeQuery :: !SubjectQueryAbstractType
  , attributeQueryAttributes :: [SAML.Attribute]
  } deriving (Eq, Show)

instance XP.XmlPickler AttributeQuery where
  xpickle = xpElem "AttributeQuery" $ [XP.biCase|
      (q, a) <-> AttributeQuery q a|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpList XP.xpickle)
instance SAMLProtocol AttributeQuery where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest AttributeQuery where
  samlRequest' = attributeQuery' . subjectQuery' where
    attributeQuery' = $(fieldLens 'attributeQuery)

-- |§3.3.2.4
data AuthzDecisionQuery = AuthzDecisionQuery
  { authzDecisionQuery :: !SubjectQueryAbstractType
  , authzDecisionQueryResource :: AnyURI
  , authzDecisionQueryActions :: [SAML.Action]
  , authzDecisionQueryEvidence :: SAML.Evidence
  } deriving (Eq, Show)

instance XP.XmlPickler AuthzDecisionQuery where
  xpickle = xpElem "AuthzDecisionQuery" $ [XP.biCase|
      (((q, r), a), e) <-> AuthzDecisionQuery q r a e|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpAttr "Resource" XS.xpAnyURI
      XP.>*< XP.xpList XP.xpickle
      XP.>*< XP.xpickle)
instance SAMLProtocol AuthzDecisionQuery where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest AuthzDecisionQuery where
  samlRequest' = authzDecisionQuery' . subjectQuery' where
    authzDecisionQuery' = $(fieldLens 'authzDecisionQuery)

-- |§3.3.3
data Response = Response
  { response :: !StatusResponseType
  , responseAssertions :: [SAML.PossiblyEncrypted SAML.Assertion]
  } deriving (Eq, Show)

instance XP.XmlPickler Response where
  xpickle = xpElem "Response" $ [XP.biCase|
      (r, a) <-> Response r a|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpList SAML.xpPossiblyEncrypted)
instance SAMLProtocol Response where
  samlProtocol' = samlResponse' . statusProtocol'
  isSAMLResponse _ = True
instance SAMLResponse Response where
  samlResponse' = $(fieldLens 'response)

-- |§3.4.1
data AuthnRequest = AuthnRequest
  { authnRequest :: !RequestAbstractType
  , authnRequestForceAuthn :: XS.Boolean
  , authnRequestIsPassive :: XS.Boolean
  , authnRequestAssertionConsumerService :: AssertionConsumerService
  , authnRequestAssertionConsumingServiceIndex :: Maybe XS.UnsignedShort
  , authnRequestProviderName :: Maybe XString
  , authnRequestSubject :: Maybe SAML.Subject
  , authnRequestNameIDPolicy :: Maybe NameIDPolicy
  , authnRequestConditions :: Maybe SAML.Conditions
  , authnRequestRequestedAuthnContext :: Maybe RequestedAuthnContext
  , authnRequestScoping :: Maybe Scoping
  } deriving (Eq, Show)

data AssertionConsumerService
  = AssertionConsumerServiceIndex XS.UnsignedShort
  | AssertionConsumerServiceURL
    { authnRequestAssertionConsumerServiceURL :: Maybe AnyURI
    , authnRequestProtocolBinding :: Maybe (IdentifiedURI Binding)
    }
  deriving (Eq, Show)

instance XP.XmlPickler AuthnRequest where
  xpickle = xpElem "AuthnRequest" $ [XP.biCase|
      ((((((((((q, f), p), Left i), g), n), s), np), c), r), sc) <-> AuthnRequest q f p (AssertionConsumerServiceIndex i) g n s np c r sc
      ((((((((((q, f), p), Right (u, b)), g), n), s), np), c), r), sc) <-> AuthnRequest q f p (AssertionConsumerServiceURL u b) g n s np c r sc|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpDefault False (XP.xpAttr "ForceAuthn" XS.xpBoolean)
      XP.>*< XP.xpDefault False (XP.xpAttr "IsPassive" XS.xpBoolean)
      XP.>*<  (XP.xpAttr "AssertionConsumerServiceIndex" XS.xpUnsignedShort
        XP.>|<  (XP.xpAttrImplied "AssertionConsumerServiceURL" XS.xpAnyURI
          XP.>*< XP.xpAttrImplied "ProtocolBinding" XP.xpickle))
      XP.>*< XP.xpAttrImplied "AttributeConsumingServiceIndex" XS.xpUnsignedShort
      XP.>*< XP.xpAttrImplied "ProviderName" XS.xpString
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle)
instance SAMLProtocol AuthnRequest where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest AuthnRequest where
  samlRequest' = $(fieldLens 'authnRequest)

-- |§3.4.1.1
data NameIDPolicy = NameIDPolicy
  { nameIDPolicyFormat :: IdentifiedURI NameIDFormat
  , nameIDPolicySPNameQualifier :: Maybe XString
  , nameIDPolicyAllowCreate :: Bool
  } deriving (Eq, Show)

instance XP.XmlPickler NameIDPolicy where
  xpickle = xpElem "NameIDPolicy" $ [XP.biCase|
      ((f, q), c) <-> NameIDPolicy f q c|]
    XP.>$<  (XP.xpDefault (Identified NameIDFormatUnspecified) (XP.xpAttr "Format" XP.xpickle)
      XP.>*< XP.xpAttrImplied "SPNameQualifier" XS.xpString
      XP.>*< XP.xpDefault False (XP.xpAttr "AllowCreate" XS.xpBoolean))

-- |§3.4.1.2
data Scoping = Scoping
  { scopingProxyCount :: Maybe XS.NonNegativeInteger
  , scopingIDPList :: Maybe IDPList
  , scopingRequesterID :: [AnyURI]
  } deriving (Eq, Show)

instance XP.XmlPickler Scoping where
  xpickle = xpElem "Scoping" $ [XP.biCase|
      ((c, i), r) <-> Scoping c i r|]
    XP.>$<  (XP.xpAttrImplied "ProxyCount" XS.xpNonNegativeInteger
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpList (xpElem "RequesterID" XS.xpAnyURI))

-- |§3.4.1.3
data IDPList = IDPList
  { idpList :: List1 IDPEntry
  , idpGetComplete :: Maybe AnyURI
  } deriving (Eq, Show)

instance XP.XmlPickler IDPList where
  xpickle = xpElem "IDPList" $ [XP.biCase|
      (l, c) <-> IDPList l c|]
    XP.>$<  (xpList1 XP.xpickle
      XP.>*< XP.xpOption (xpElem "GetComplete" XS.xpAnyURI))

-- |§3.4.1.3.1
data IDPEntry = IDPEntry
  { idpEntryProviderID :: AnyURI
  , idpEntryName :: Maybe XString
  , idpEntryLoc :: Maybe AnyURI
  } deriving (Eq, Show)

instance XP.XmlPickler IDPEntry where
  xpickle = xpElem "IDPEntry" $ [XP.biCase|
      ((p, n), l) <-> IDPEntry p n l|]
    XP.>$<  (XP.xpAttr "ProviderID" XS.xpAnyURI
      XP.>*< XP.xpAttrImplied "Name" XS.xpString
      XP.>*< XP.xpAttrImplied "Loc" XS.xpAnyURI)

-- |§3.5.1
data ArtifactResolve = ArtifactResolve
  { artifactResolve :: !RequestAbstractType
  , artifactResolveArtifact :: XString
  } deriving (Eq, Show)

instance XP.XmlPickler ArtifactResolve where
  xpickle = xpElem "ArtifactResolve" $ [XP.biCase|
      (r, a) <-> ArtifactResolve r a|]
    XP.>$<  (XP.xpickle
      XP.>*< xpElem "Artifact" XS.xpString)
instance SAMLProtocol ArtifactResolve where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest ArtifactResolve where
  samlRequest' = $(fieldLens 'artifactResolve)

-- |§3.5.2
data ArtifactResponse = ArtifactResponse
  { artifactResponse :: !StatusResponseType
  , artifactResponseMessage :: Maybe Node
  } deriving (Eq, Show)

instance XP.XmlPickler ArtifactResponse where
  xpickle = xpElem "ArtifactResponse" $ [XP.biCase|
      (r, a) <-> ArtifactResponse r a|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpOption xpTrimAnyElem)
instance SAMLProtocol ArtifactResponse where
  samlProtocol' = samlResponse' . statusProtocol'
  isSAMLResponse _ = True
instance SAMLResponse ArtifactResponse where
  samlResponse' = $(fieldLens 'artifactResponse)

-- |§3.6.1
data ManageNameIDRequest = ManageNameIDRequest
  { manageNameIDRequest :: !RequestAbstractType
  , manageNameIDRequestNameID :: SAML.PossiblyEncrypted SAML.NameID
  , manageNameIDRequestNewID :: Maybe (SAML.PossiblyEncrypted NewID)
  } deriving (Eq, Show)

instance XP.XmlPickler ManageNameIDRequest where
  xpickle = xpElem "ManageNameIDRequest" $ [XP.biCase|
      ((r, o), Left n) <-> ManageNameIDRequest r o (Just n)
      ((r, o), Right ()) <-> ManageNameIDRequest r o Nothing|]
    XP.>$<  (XP.xpickle
      XP.>*< SAML.xpPossiblyEncrypted
      XP.>*< (SAML.xpPossiblyEncrypted
        XP.>|< xpElem "Terminate" XP.xpUnit))
instance SAMLProtocol ManageNameIDRequest where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest ManageNameIDRequest where
  samlRequest' = $(fieldLens 'manageNameIDRequest)

newtype NewID = NewID XString
  deriving (Eq, Show)

instance XP.XmlPickler NewID where
  xpickle = xpElem "NewID" $ [XP.biCase|
      n <-> NewID n|]
    XP.>$< XS.xpString

type NewEncryptedID = SAML.EncryptedElement NewID

instance XP.XmlPickler NewEncryptedID where
  xpickle = xpElem "NewEncryptedID" SAML.xpEncryptedElement

-- |§3.6.2
newtype ManageNameIDResponse = ManageNameIDResponse
  { manageNameIDResponse :: StatusResponseType }
  deriving (Eq, Show)

instance XP.XmlPickler ManageNameIDResponse where
  xpickle = xpElem "ManageNameIDResponse" $ [XP.biCase|
      r <-> ManageNameIDResponse r|]
    XP.>$< XP.xpickle
instance SAMLProtocol ManageNameIDResponse where
  samlProtocol' = samlResponse' . statusProtocol'
  isSAMLResponse _ = True
instance SAMLResponse ManageNameIDResponse where
  samlResponse' = $(fieldLens 'manageNameIDResponse)

-- |§3.7.1
data LogoutRequest = LogoutRequest
  { logoutRequest :: !RequestAbstractType
  , logoutRequestReason :: Maybe (Identified XString LogoutReason)
  , logoutRequestNotOnOrAfter :: Maybe XS.DateTime
  , logoutRequestIdentifier :: SAML.PossiblyEncrypted SAML.Identifier
  , logoutRequestSessionIndex :: Maybe XString
  } deriving (Eq, Show)

instance XP.XmlPickler LogoutRequest where
  xpickle = xpElem "LogoutRequest" $ [XP.biCase|
      ((((q, r), t), i), s) <-> LogoutRequest q r t i s|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpAttrImplied "Reason" XP.xpickle
      XP.>*< XP.xpAttrImplied "NotOnOrAfter" XS.xpDateTime
      XP.>*< SAML.xpPossiblyEncrypted
      XP.>*< XP.xpOption (xpElem "SessionIndex" XS.xpString))
instance SAMLProtocol LogoutRequest where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest LogoutRequest where
  samlRequest' = $(fieldLens 'logoutRequest)

-- |§3.7.2
newtype LogoutResponse = LogoutResponse
  { logoutResponse :: StatusResponseType }
  deriving (Eq, Show)

instance XP.XmlPickler LogoutResponse where
  xpickle = xpElem "LogoutResponse" $ [XP.biCase|
      r <-> LogoutResponse r|]
    XP.>$< XP.xpickle
instance SAMLProtocol LogoutResponse where
  samlProtocol' = samlResponse' . statusProtocol'
  isSAMLResponse _ = True
instance SAMLResponse LogoutResponse where
  samlResponse' = $(fieldLens 'logoutResponse)

-- |§3.7.3
data LogoutReason
  = LogoutReasonUser
  | LogoutReasonAdmin
  deriving (Eq, Enum, Bounded, Show)

instance Identifiable XString LogoutReason where
  identifier = show . samlURNIdentifier "logout" . f where
    f LogoutReasonUser  = (SAML20, "user")
    f LogoutReasonAdmin = (SAML20, "admin")
instance XP.XmlPickler (Identified XString LogoutReason) where
  xpickle = xpIdentified XS.xpString

-- |§3.8.1
data NameIDMappingRequest = NameIDMappingRequest
  { nameIDMappingRequest :: !RequestAbstractType
  , nameIDMappingRequestIdentifier :: SAML.PossiblyEncrypted SAML.Identifier
  , nameIDMappingRequestPolicy :: NameIDPolicy
  } deriving (Eq, Show)

instance XP.XmlPickler NameIDMappingRequest where
  xpickle = xpElem "NameIDMappingRequest" $ [XP.biCase|
      ((r, i), p) <-> NameIDMappingRequest r i p|]
    XP.>$<  (XP.xpickle
      XP.>*< SAML.xpPossiblyEncrypted
      XP.>*< XP.xpickle)
instance SAMLProtocol NameIDMappingRequest where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest NameIDMappingRequest where
  samlRequest' = $(fieldLens 'nameIDMappingRequest)

-- |§3.8.2
data NameIDMappingResponse = NameIDMappingResponse
  { nameIDMappingResponse :: !StatusResponseType
  , nameIDMappingResponseNameID :: SAML.PossiblyEncrypted SAML.NameID
  } deriving (Eq, Show)

instance XP.XmlPickler NameIDMappingResponse where
  xpickle = xpElem "NameIDMappingResponse" $ [XP.biCase|
      (r, a) <-> NameIDMappingResponse r a|]
    XP.>$<  (XP.xpickle
      XP.>*< SAML.xpPossiblyEncrypted)
instance SAMLProtocol NameIDMappingResponse where
  samlProtocol' = samlResponse' . statusProtocol'
  isSAMLResponse _ = True
instance SAMLResponse NameIDMappingResponse where
  samlResponse' = $(fieldLens 'nameIDMappingResponse)

data AnyRequest
  = RequestAssertionIDRequest   !AssertionIDRequest
  | RequestAuthnQuery           !AuthnQuery 
  | RequestAttributeQuery       !AttributeQuery 
  | RequestAuthzDecisionQuery   !AuthzDecisionQuery 
  | RequestAuthnRequest         !AuthnRequest
  | RequestArtifactResolve      !ArtifactResolve 
  | RequestManageNameIDRequest  !ManageNameIDRequest 
  | RequestLogoutRequest        !LogoutRequest 
  | RequestNameIDMappingRequest !NameIDMappingRequest 
  deriving (Eq, Show)

instance XP.XmlPickler AnyRequest where
  xpickle = [XP.biCase|
      Left (Left (Left (Left (Left (Left (Left (Left r))))))) <-> RequestAssertionIDRequest r
      Left (Left (Left (Left (Left (Left (Left (Right r))))))) <-> RequestAuthnQuery r
      Left (Left (Left (Left (Left (Left (Right r)))))) <-> RequestAttributeQuery r
      Left (Left (Left (Left (Left (Right r))))) <-> RequestAuthzDecisionQuery r
      Left (Left (Left (Left (Right r)))) <-> RequestAuthnRequest r
      Left (Left (Left (Right r))) <-> RequestArtifactResolve r
      Left (Left (Right r)) <-> RequestManageNameIDRequest r
      Left (Right r) <-> RequestLogoutRequest r
      Right r <-> RequestNameIDMappingRequest r|]
    XP.>$<  (XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle)
instance SAMLProtocol AnyRequest where
  samlProtocol' = samlRequest' . requestProtocol'
  isSAMLResponse _ = False
instance SAMLRequest AnyRequest where
  samlRequest' = lens g s where
    g (RequestAssertionIDRequest   r) = r ^. samlRequest'
    g (RequestAuthnQuery           r) = r ^. samlRequest'
    g (RequestAttributeQuery       r) = r ^. samlRequest'
    g (RequestAuthzDecisionQuery   r) = r ^. samlRequest'
    g (RequestAuthnRequest         r) = r ^. samlRequest'
    g (RequestArtifactResolve      r) = r ^. samlRequest'
    g (RequestManageNameIDRequest  r) = r ^. samlRequest'
    g (RequestLogoutRequest        r) = r ^. samlRequest'
    g (RequestNameIDMappingRequest r) = r ^. samlRequest'
    s (RequestAssertionIDRequest   r) q = RequestAssertionIDRequest   $ samlRequest' .~ q $ r
    s (RequestAuthnQuery           r) q = RequestAuthnQuery           $ samlRequest' .~ q $ r
    s (RequestAttributeQuery       r) q = RequestAttributeQuery       $ samlRequest' .~ q $ r
    s (RequestAuthzDecisionQuery   r) q = RequestAuthzDecisionQuery   $ samlRequest' .~ q $ r
    s (RequestAuthnRequest         r) q = RequestAuthnRequest         $ samlRequest' .~ q $ r
    s (RequestArtifactResolve      r) q = RequestArtifactResolve      $ samlRequest' .~ q $ r
    s (RequestManageNameIDRequest  r) q = RequestManageNameIDRequest  $ samlRequest' .~ q $ r
    s (RequestLogoutRequest        r) q = RequestLogoutRequest        $ samlRequest' .~ q $ r
    s (RequestNameIDMappingRequest r) q = RequestNameIDMappingRequest $ samlRequest' .~ q $ r

data AnyResponse
  = ResponseResponse         !Response 
  | ResponseArtifactResponse !ArtifactResponse 
  deriving (Eq, Show)

instance XP.XmlPickler AnyResponse where
  xpickle = [XP.biCase|
      Left r <-> ResponseResponse r
      Right r <-> ResponseArtifactResponse r|]
    XP.>$<  (XP.xpickle
      XP.>|< XP.xpickle)
instance SAMLProtocol AnyResponse where
  samlProtocol' = samlResponse' . statusProtocol'
  isSAMLResponse _ = True
instance SAMLResponse AnyResponse where
  samlResponse' = lens g s where
    g (ResponseResponse         r) = r ^. samlResponse'
    g (ResponseArtifactResponse r) = r ^. samlResponse'
    s (ResponseResponse         r) q = ResponseResponse         $ samlResponse' .~ q $ r
    s (ResponseArtifactResponse r) q = ResponseArtifactResponse $ samlResponse' .~ q $ r
    
data AnyProtocol
  = ProtocolRequest  !AnyRequest
  | ProtocolResponse !AnyResponse
  deriving (Eq, Show)

instance XP.XmlPickler AnyProtocol where
  xpickle = [XP.biCase|
      Left r <-> ProtocolRequest r
      Right r <-> ProtocolResponse r|]
    XP.>$<  (XP.xpickle
      XP.>|< XP.xpickle)
instance SAMLProtocol AnyProtocol where
  samlProtocol' = lens g s where
    g (ProtocolRequest  r) = r ^. samlProtocol'
    g (ProtocolResponse r) = r ^. samlProtocol'
    s (ProtocolRequest  r) q = ProtocolRequest  $ samlProtocol' .~ q $ r
    s (ProtocolResponse r) q = ProtocolResponse $ samlProtocol' .~ q $ r
  isSAMLResponse (ProtocolRequest _) = False
  isSAMLResponse (ProtocolResponse _) = True
  isSAMLResponse_ _ = Nothing
