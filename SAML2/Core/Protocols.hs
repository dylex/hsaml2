{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
-- |
-- SAML Protocols
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §3
module SAML2.Core.Protocols where

import qualified Text.XML.HXT.Arrow.Pickle.Schema as XPS

import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Encryption as XEnc
import qualified SAML2.XML.Signature as DS
import SAML2.Core.Namespaces
import SAML2.Core.Versioning
import qualified SAML2.Core.Assertions as SAML
import SAML2.Core.Identifiers
import SAML2.Profiles.ConfirmationMethod

ns :: Namespace
ns = mkNamespace "samlp" $ samlURN SAML20 ["protocol"]

nsName :: XString -> QName
nsName = mkNName ns

xpElem :: String -> XP.PU a -> XP.PU a
xpElem = XP.xpElemQN . nsName

-- |§3.2.1
data RequestAbstractType = RequestAbstractType
  { requestID :: XS.ID
  , requestVersion :: SAMLVersion
  , requestIssueInstant :: DateTime
  , requestDestination :: Maybe AnyURI
  , requestConsent :: PreidentifiedURI Consent
  , requestIssuer :: Maybe SAML.Issuer
  , requestSignature :: Maybe DS.Signature
  , requestExtensions :: [Node]
  }

instance XP.XmlPickler RequestAbstractType where
  xpickle = [XP.biCase|
      (((((((i, v), t), d), c), u), g), Nothing) <-> RequestAbstractType i v t d c u g []
      (((((((i, v), t), d), c), u), g), Just x) <-> RequestAbstractType i v t d c u g x|]
    XP.>$<  (XP.xpAttr "ID" XS.xpID
      XP.>*< XP.xpAttr "Version" XP.xpickle
      XP.>*< XP.xpAttr "IssueInstant" XP.xpickle
      XP.>*< XP.xpAttrImplied "Destination" XP.xpickle
      XP.>*< XP.xpDefault (Preidentified ConsentUnspecified) (XP.xpAttr "Consent" XP.xpickle)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption (xpElem "Extensions" $ XP.xpList1 XP.xpTree))

-- |§3.2.2
data StatusResponseType = StatusResponseType
  { statusID :: XS.ID
  , statusInResponseTo :: Maybe XS.NCName
  , statusVersion :: SAMLVersion
  , statusIssueInstant :: DateTime
  , statusDestination :: Maybe AnyURI
  , statusConsent :: PreidentifiedURI Consent
  , statusIssuer :: Maybe SAML.Issuer
  , statusSignature :: Maybe DS.Signature
  , statusExtensions :: [Node]
  , status :: Status
  }

instance XP.XmlPickler StatusResponseType where
  xpickle = [XP.biCase|
      (((((((((i, r), v), t), d), c), u), g), Nothing), s) <-> StatusResponseType i r v t d c u g [] s
      (((((((((i, r), v), t), d), c), u), g), Just x), s) <-> StatusResponseType i r v t d c u g x s|]
    XP.>$<  (XP.xpAttr "ID" XS.xpID
      XP.>*< XP.xpAttrImplied "InResponseTo" XS.xpNCName
      XP.>*< XP.xpAttr "Version" XP.xpickle
      XP.>*< XP.xpAttr "IssueInstant" XP.xpickle
      XP.>*< XP.xpAttrImplied "Destination" XP.xpickle
      XP.>*< XP.xpDefault (Preidentified ConsentUnspecified) (XP.xpAttr "Consent" XP.xpickle)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption (xpElem "Extensions" $ XP.xpList1 XP.xpTree)
      XP.>*< XP.xpickle)

-- |§3.2.2.1
data Status = Status
  { statusCode :: StatusCode
  , statusMessage :: Maybe XString -- ^§3.2.2.3
  , statusDetail :: Maybe Nodes -- ^§3.2.2.4
  }

instance XP.XmlPickler Status where
  xpickle = [XP.biCase|
      ((c, m), d) <-> Status c m d|]
    XP.>$<  (XP.xpickle
      XP.>*< XP.xpOption (xpElem "StatusMessage" XP.xpText0)
      XP.>*< XP.xpOption (xpElem "StatusDetail" XP.xpTrees))

-- |§3.2.2.2
data StatusCode = StatusCode
  { statusCode1 :: StatusCode1
  , statusCodes :: [PreidentifiedURI StatusCode2]
  }

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

instance XP.XmlPickler StatusCode1 where
  xpickle = xpEnumSAMLURN "status" f where
    f StatusSuccess         = (SAML20, "Success")
    f StatusRequester       = (SAML20, "Requester")
    f StatusResponder       = (SAML20, "Responder")
    f StatusVersionMismatch = (SAML20, "VersionMismatch")

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

instance XP.XmlPickler (PreidentifiedURI StatusCode2) where
  xpickle = xpPreidentifiedSAMLURN "status" f where
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
