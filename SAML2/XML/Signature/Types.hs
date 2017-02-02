{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- XML Signature Syntax and Processing
--
-- <http://www.w3.org/TR/xmldsig-core1/> (selected portions)
module SAML2.XML.Signature.Types where

import Control.Lens (Lens')
import Crypto.Number.Serialize (i2osp, os2ip)
import qualified Data.X509 as X509

import SAML2.XML
import qualified SAML2.XML.Schema as XS
import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP
import qualified SAML2.XML.Canonical as C14N
import SAML2.XML.ASN1

nsFrag :: String -> URI
nsFrag = httpURI "www.w3.org" "/2000/09/xmldsig" "" . ('#':)

nsFrag11 :: String -> URI
nsFrag11 = httpURI "www.w3.org" "/2009/xmldsig11" "" . ('#':)

ns :: Namespace 
ns = mkNamespace "ds" $ nsFrag ""

ns11 :: Namespace 
ns11 = mkNamespace "dsig11" $ nsFrag11 ""

xpElem :: String -> XP.PU a -> XP.PU a
xpElem = xpTrimElemNS ns

xpElem11 :: String -> XP.PU a -> XP.PU a
xpElem11 = xpTrimElemNS ns11

-- |§4.1
type CryptoBinary = Integer -- as Base64Binary

xpCryptoBinary :: XP.PU CryptoBinary
xpCryptoBinary = XP.xpWrap (os2ip, i2osp) XS.xpBase64Binary

-- |§4.2
data Signature = Signature
  { signatureId :: Maybe ID
  , signatureSignedInfo :: SignedInfo
  , signatureSignatureValue :: SignatureValue
  , signatureKeyInfo :: Maybe KeyInfo
  , signatureObject :: [Object]
  } deriving (Eq, Show)

instance XP.XmlPickler Signature where
  xpickle = xpElem "Signature" $
    [XP.biCase|((((i, s), v), k), o) <-> Signature i s v k o|] 
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpList XP.xpickle)

class Signable a where
  signature' :: Lens' a (Maybe Signature)
  signedID :: a -> XS.ID

-- |§4.3
data SignatureValue = SignatureValue
  { signatureValueId :: Maybe ID
  , signatureValue :: XS.Base64Binary
  } deriving (Eq, Show)

instance XP.XmlPickler SignatureValue where
  xpickle = xpElem "SignatureValue" $
    [XP.biCase|(i, v) <-> SignatureValue i v|] 
    XP.>$< (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XS.xpBase64Binary)

-- |§4.4
data SignedInfo = SignedInfo
  { signedInfoId :: Maybe ID
  , signedInfoCanonicalizationMethod :: CanonicalizationMethod
  , signedInfoSignatureMethod :: SignatureMethod
  , signedInfoReference :: List1 Reference
  } deriving (Eq, Show)

instance XP.XmlPickler SignedInfo where
  xpickle = xpElem "SignedInfo" $
    [XP.biCase|(((i, c), s), r) <-> SignedInfo i c s r|] 
    XP.>$< (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< xpList1 XP.xpickle)

-- |§4.4.1
data CanonicalizationMethod = CanonicalizationMethod 
  { canonicalizationMethodAlgorithm :: IdentifiedURI C14N.CanonicalizationAlgorithm
  , canonicalizationMethodInclusiveNamespaces :: Maybe C14N.InclusiveNamespaces
  , canonicalizationMethod :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler CanonicalizationMethod where
  xpickle = xpElem "CanonicalizationMethod" $
    [XP.biCase|((a, n), x) <-> CanonicalizationMethod a n x|] 
    XP.>$< (XP.xpAttr "Algorithm" XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpAnyCont)

simpleCanonicalization :: C14N.CanonicalizationAlgorithm -> CanonicalizationMethod
simpleCanonicalization a = CanonicalizationMethod (Identified a) Nothing []

-- |§4.4.2
data SignatureMethod = SignatureMethod
  { signatureMethodAlgorithm :: IdentifiedURI SignatureAlgorithm
  , signatureMethodHMACOutputLength :: Maybe Int
  , signatureMethod :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler SignatureMethod where
  xpickle = xpElem "SignatureMethod" $
    [XP.biCase|((a, l), x) <-> SignatureMethod a l x|] 
    XP.>$< (XP.xpAttr "Algorithm" XP.xpickle
      XP.>*< XP.xpOption (xpElem "HMACOutputLength" XP.xpickle)
      XP.>*< XP.xpAnyCont)

-- |§4.4.3
data Reference = Reference
  { referenceId :: Maybe ID
  , referenceURI :: Maybe AnyURI
  , referenceType :: Maybe AnyURI -- xml object type
  , referenceTransforms :: Maybe Transforms
  , referenceDigestMethod :: DigestMethod
  , referenceDigestValue :: XS.Base64Binary -- ^§4.3.3.6
  } deriving (Eq, Show)

instance XP.XmlPickler Reference where
  xpickle = xpElem "Reference" $
    [XP.biCase|(((((i, u), t), f), m), v) <-> Reference i u t f m v|] 
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XP.xpAttrImplied "URI" XS.xpAnyURI
      XP.>*< XP.xpAttrImplied "Type" XS.xpAnyURI
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< xpElem "DigestValue" XS.xpBase64Binary)

-- |§4.4.3.4
newtype Transforms = Transforms{ transforms :: List1 Transform }
  deriving (Eq, Show)

instance XP.XmlPickler Transforms where
  xpickle = xpElem "Transforms" $
    [XP.biCase|l <-> Transforms l|]
    XP.>$< xpList1 XP.xpickle

data Transform = Transform
  { transformAlgorithm :: IdentifiedURI TransformAlgorithm
  , transformInclusiveNamespaces :: Maybe C14N.InclusiveNamespaces
  , transform :: [TransformElement]
  } deriving (Eq, Show)

instance XP.XmlPickler Transform where
  xpickle = xpElem "Transform" $
    [XP.biCase|((a, n), l) <-> Transform a n l|]
    XP.>$< (XP.xpAttr "Algorithm" XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpList XP.xpickle)

simpleTransform :: TransformAlgorithm -> Transform
simpleTransform a = Transform (Identified a) Nothing []

data TransformElement
  = TransformElementXPath XString
  | TransformElement Node 
  deriving (Eq, Show)

instance XP.XmlPickler TransformElement where
  xpickle = [XP.biCase|
      Left s  <-> TransformElementXPath s
      Right x <-> TransformElement x |]
    XP.>$< (xpElem "XPath" XS.xpString
      XP.>|< xpTrimAnyElem)

-- |§4.4.3.5
data DigestMethod = DigestMethod
  { digestAlgorithm :: IdentifiedURI DigestAlgorithm
  , digest :: [Node]
  } deriving (Eq, Show)

instance XP.XmlPickler DigestMethod where
  xpickle = xpElem "DigestMethod" $
    [XP.biCase|(a, d) <-> DigestMethod a d|]
    XP.>$< (XP.xpAttr "Algorithm" XP.xpickle
      XP.>*< XP.xpAnyCont)

simpleDigest :: DigestAlgorithm -> DigestMethod
simpleDigest a = DigestMethod (Identified a) []

-- |§4.5
data KeyInfo = KeyInfo
  { keyInfoId :: Maybe ID
  , keyInfoElements :: List1 KeyInfoElement
  } deriving (Eq, Show)

xpKeyInfoType :: XP.PU KeyInfo
xpKeyInfoType = [XP.biCase|(i, l) <-> KeyInfo i l|] 
  XP.>$< (XP.xpAttrImplied "Id" XS.xpID
    XP.>*< xpList1 XP.xpickle)

instance XP.XmlPickler KeyInfo where
  xpickle = xpElem "KeyInfo" xpKeyInfoType

data KeyInfoElement
  = KeyName XString -- ^§4.5.1
  | KeyInfoKeyValue KeyValue -- ^§4.5.2
  | RetrievalMethod
    { retrievalMethodURI :: URI
    , retrievalMethodType :: Maybe URI
    , retrievalMethodTransforms :: Maybe Transforms
    } -- ^§4.5.3
  | X509Data
    { x509Data :: List1 X509Element
    } -- ^§4.5.4
  | PGPData
    { pgpKeyID :: Maybe XS.Base64Binary
    , pgpKeyPacket :: Maybe XS.Base64Binary
    , pgpData :: Nodes
    } -- ^§4.5.5
  | SPKIData 
    { spkiData :: List1 SPKIElement
    } -- ^§4.5.6
  | MgmtData XString -- ^§4.5.7
  | KeyInfoElement Node
  deriving (Eq, Show)

instance XP.XmlPickler KeyInfoElement where
  xpickle = [XP.biCase|
      Left (Left (Left (Left (Left (Left (Left n)))))) <-> KeyName n
      Left (Left (Left (Left (Left (Left (Right v)))))) <-> KeyInfoKeyValue v
      Left (Left (Left (Left (Left (Right ((u, t), f)))))) <-> RetrievalMethod u t f
      Left (Left (Left (Left (Right l)))) <-> X509Data l
      Left (Left (Left (Right ((i, p), x)))) <-> PGPData i p x
      Left (Left (Right l)) <-> SPKIData l
      Left (Right m) <-> MgmtData m
      Right x <-> KeyInfoElement x|]
    XP.>$<  (xpElem "KeyName" XS.xpString
      XP.>|< XP.xpickle
      XP.>|< xpElem "RetrievalMethod"
              (XP.xpAttr "URI" XS.xpAnyURI
        XP.>*< XP.xpAttrImplied "Type" XS.xpAnyURI
        XP.>*< XP.xpOption XP.xpickle)
      XP.>|< xpElem "X509Data" (xpList1 XP.xpickle)
      XP.>|< xpElem "PGPData"
              (XP.xpOption (xpElem "PGPKeyID" XS.xpBase64Binary)
        XP.>*< XP.xpOption (xpElem "PGPKeyPacket" XS.xpBase64Binary)
        XP.>*< XP.xpList xpTrimAnyElem)
      XP.>|< xpElem "SPKIData" (xpList1 XP.xpickle)
      XP.>|< xpElem "MgmtData" XS.xpString
      XP.>|< XP.xpTree)

-- |§4.5.2
data KeyValue
  = DSAKeyValue
    { dsaKeyValuePQ :: Maybe (CryptoBinary, CryptoBinary)
    , dsaKeyValueG :: Maybe CryptoBinary
    , dsaKeyValueY :: CryptoBinary
    , dsaKeyValueJ :: Maybe CryptoBinary
    , dsaKeyValueSeedPgenCounter :: Maybe (CryptoBinary, CryptoBinary)
    } -- ^§4.5.2.1
  | RSAKeyValue
    { rsaKeyValueModulus
    , rsaKeyValueExponent :: CryptoBinary
    } -- ^§4.5.2.2
  | ECKeyValue
    { ecKeyValueId :: Maybe XS.ID
    , ecKeyValue :: ECKeyValue
    , ecKeyValuePublicKey :: ECPoint
    } -- ^§4.5.2.3
  | KeyValue Node
  deriving (Eq, Show)

instance XP.XmlPickler KeyValue where
  xpickle = xpElem "KeyValue" $
    [XP.biCase|
      Left (Left (Left ((((pq, g), y), j), sp))) <-> DSAKeyValue pq g y j sp
      Left (Left (Right (m, e))) <-> RSAKeyValue m e
      Left (Right ((i, v), p)) <-> ECKeyValue i v p
      Right x <-> KeyValue x|]
    XP.>$< (xpElem "DSAKeyValue" 
              (XP.xpOption
                (xpElem "P" xpCryptoBinary
          XP.>*< xpElem "Q" xpCryptoBinary)
        XP.>*< XP.xpOption (xpElem "G" xpCryptoBinary)
        XP.>*< xpElem "Y" xpCryptoBinary
        XP.>*< XP.xpOption (xpElem "J" xpCryptoBinary)
        XP.>*< (XP.xpOption
                (xpElem "Seed" xpCryptoBinary
          XP.>*< xpElem "PgenCounter" xpCryptoBinary)))
      XP.>|< xpElem "RSAKeyValue" 
              (xpElem "Modulus" xpCryptoBinary
        XP.>*< xpElem "Exponent" xpCryptoBinary)
      XP.>|< xpElem11 "ECKeyValue"
              (XP.xpAttrImplied "Id" XS.xpID
        XP.>*< XP.xpickle
        XP.>*< xpElem11 "PublicKey" xpCryptoBinary)
      XP.>|< XP.xpTree)

data ECKeyValue
  = ECParameters
    { ecParametersFieldID :: ECFieldID
    , ecParametersCurve :: ECCurve
    , ecParametersBase :: ECPoint
    , ecParametersOrder :: CryptoBinary
    , ecParametersCoFactor :: Maybe Integer
    , ecParametersValidationData :: Maybe ECValidationData
    } -- ^§4.5.2.3.1
  | ECNamedCurve
    { ecNamedCurveURI :: XS.AnyURI
    }
  deriving (Eq, Show)

type ECPoint = CryptoBinary

instance XP.XmlPickler ECKeyValue where
  xpickle =
    [XP.biCase|
      Left (((((f, c), b), o), cf), vd) <-> ECParameters f c b o cf vd
      Right u <-> ECNamedCurve u|]
    XP.>$<  (xpElem11 "ECParameters" 
              (XP.xpickle
        XP.>*< XP.xpickle
        XP.>*< xpElem11 "Base" xpCryptoBinary
        XP.>*< xpElem11 "Order" xpCryptoBinary
        XP.>*< XP.xpOption (xpElem11 "CoFactor" XS.xpInteger)
        XP.>*< XP.xpOption XP.xpickle)
      XP.>|< xpElem11 "NamedCurve"
              (XP.xpAttr "URI" XS.xpAnyURI))

data ECFieldID
  = ECPrime
    { ecP :: CryptoBinary
    }
  | ECTnB
    { ecM :: XS.PositiveInteger
    , ecK :: XS.PositiveInteger
    }
  | ECPnB
    { ecM :: XS.PositiveInteger
    , ecK1, ecK2, ecK3 :: XS.PositiveInteger
    }
  | ECGnB
    { ecM :: XS.PositiveInteger
    }
  | ECFieldID Node
  deriving (Eq, Show)

instance XP.XmlPickler ECFieldID where
  xpickle = xpElem11 "FieldID" $
    [XP.biCase|
      Left (Left (Left (Left p))) <-> ECPrime p
      Left (Left (Left (Right (m, k)))) <-> ECTnB m k
      Left (Left (Right (((m, k1), k2), k3))) <-> ECPnB m k1 k2 k3
      Left (Right m) <-> ECGnB m
      Right x <-> ECFieldID x|]
    XP.>$<  (xpElem11 "Prime" 
              (xpElem11 "P" xpCryptoBinary)
      XP.>|< xpElem11 "TnB" 
              (xpElem11 "M" XS.xpPositiveInteger
        XP.>*< xpElem11 "K" XS.xpPositiveInteger)
      XP.>|< xpElem11 "PnB" 
              (xpElem11 "M" XS.xpPositiveInteger
        XP.>*< xpElem11 "K1" XS.xpPositiveInteger
        XP.>*< xpElem11 "K2" XS.xpPositiveInteger
        XP.>*< xpElem11 "K3" XS.xpPositiveInteger)
      XP.>|< xpElem11 "GnB" 
              (xpElem11 "M" XS.xpPositiveInteger)
      XP.>|< xpTrimAnyElem)

data ECCurve = ECCurve
  { ecCurveA, ecCurveB :: CryptoBinary
  } deriving (Eq, Show)

instance XP.XmlPickler ECCurve where
  xpickle = xpElem11 "Curve" $
    [XP.biCase|
      (a, b) <-> ECCurve a b|]
    XP.>$<  (xpElem11 "A" xpCryptoBinary
      XP.>*< xpElem11 "B" xpCryptoBinary)

data ECValidationData = ECValidationData
  { ecValidationDataHashAlgorithm :: AnyURI
  , ecValidationDataSeed :: CryptoBinary
  } deriving (Eq, Show)

instance XP.XmlPickler ECValidationData where
  xpickle = xpElem11 "ValidationData" $
    [XP.biCase|
      (a, s) <-> ECValidationData a s|]
    XP.>$<  (XP.xpAttr "hashAlgorithm" XS.xpAnyURI
      XP.>*< xpElem11 "seed" xpCryptoBinary)

-- |§4.5.4.1
type X509DistinguishedName = XString

xpX509DistinguishedName :: XP.PU X509DistinguishedName
xpX509DistinguishedName = XS.xpString

data X509Element
  = X509IssuerSerial
    { x509IssuerName :: X509DistinguishedName
    , x509SerialNumber :: Int
    }
  | X509SKI XS.Base64Binary
  | X509SubjectName X509DistinguishedName
  | X509Certificate X509.SignedCertificate
  | X509CRL X509.SignedCRL
  | X509Digest
    { x509DigestAlgorithm :: IdentifiedURI DigestAlgorithm
    , x509Digest :: XS.Base64Binary
    }
  | X509Element Node
  deriving (Eq, Show)

instance XP.XmlPickler X509Element where
  xpickle = [XP.biCase|
      Left (Left (Left (Left (Left (Left (n, i)))))) <-> X509IssuerSerial n i
      Left (Left (Left (Left (Left (Right n))))) <-> X509SubjectName n
      Left (Left (Left (Left (Right b)))) <-> X509SKI b
      Left (Left (Left (Right b))) <-> X509Certificate b
      Left (Left (Right b)) <-> X509CRL b
      Left (Right (a, d)) <-> X509Digest a d
      Right x <-> X509Element x|]
    XP.>$< (xpElem "X509IssuerSerial"
              (xpElem "X509IssuerName" xpX509DistinguishedName
        XP.>*< xpElem "X509SerialNumber" XP.xpickle)
      XP.>|< xpElem "X509SubjectName" xpX509DistinguishedName
      XP.>|< xpElem "X509SKI" XS.xpBase64Binary
      XP.>|< xpElem "X509Certificate" xpX509Signed
      XP.>|< xpElem "X509CRL" xpX509Signed
      XP.>|< xpElem11 "X509Digest"
              (XP.xpAttr "Algorithm" XP.xpickle
        XP.>*< XS.xpBase64Binary)
      XP.>|< xpTrimAnyElem)

-- |§4.4.6
data SPKIElement
  = SPKISexp XS.Base64Binary
  | SPKIElement Node
  deriving (Eq, Show)

instance XP.XmlPickler SPKIElement where
  xpickle = [XP.biCase|
      Left b <-> SPKISexp b
      Right x <-> SPKIElement x|]
    XP.>$<  (xpElem "SPKISexp" XS.xpBase64Binary
      XP.>|< xpTrimAnyElem)

-- |§4.5
data Object = Object
  { objectId :: Maybe ID
  , objectMimeType :: Maybe XString
  , objectEncoding :: Maybe (IdentifiedURI EncodingAlgorithm)
  , objectXML :: [ObjectElement]
  } deriving (Eq, Show)

instance XP.XmlPickler Object where
  xpickle = xpElem "Object" $
    [XP.biCase|(((i, m), e), x) <-> Object i m e x|] 
    XP.>$< (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XP.xpAttrImplied "MimeType" XS.xpString
      XP.>*< XP.xpAttrImplied "Encoding" XP.xpickle
      XP.>*< XP.xpList XP.xpickle)

data ObjectElement
  = ObjectSignature Signature
  | ObjectSignatureProperties SignatureProperties
  | ObjectManifest Manifest
  | ObjectElement Node
  deriving (Eq, Show)

instance XP.XmlPickler ObjectElement where
  xpickle = [XP.biCase|
      Left (Left (Left s)) <-> ObjectSignature s
      Left (Left (Right p)) <-> ObjectSignatureProperties p
      Left (Right m) <-> ObjectManifest m
      Right x <-> ObjectElement x|]
    XP.>$<  (XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpTree)

-- |§5.1
data Manifest = Manifest
  { manifestId :: Maybe ID
  , manifestReferences :: List1 Reference
  } deriving (Eq, Show)

instance XP.XmlPickler Manifest where
  xpickle = xpElem "Manifest" $
    [XP.biCase|(i, r) <-> Manifest i r|] 
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< xpList1 XP.xpickle)

-- |§5.2
data SignatureProperties = SignatureProperties
  { signaturePropertiesId :: Maybe ID
  , signatureProperties :: List1 SignatureProperty
  } deriving (Eq, Show)

instance XP.XmlPickler SignatureProperties where
  xpickle = xpElem "SignatureProperties" $
    [XP.biCase|(i, p) <-> SignatureProperties i p|] 
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< xpList1 XP.xpickle)

data SignatureProperty = SignatureProperty
  { signaturePropertyId :: Maybe ID
  , signaturePropertyTarget :: AnyURI
  , signatureProperty :: List1 Node
  } deriving (Eq, Show)

instance XP.XmlPickler SignatureProperty where
  xpickle = xpElem "SignatureProperty" $
    [XP.biCase|((i, t), x) <-> SignatureProperty i t x|] 
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XP.xpAttr "Target" XS.xpAnyURI
      XP.>*< xpList1 XP.xpTree)

-- |§6.1
data EncodingAlgorithm
  = EncodingBase64
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI EncodingAlgorithm where
  identifier EncodingBase64 = nsFrag "base64"

-- |§6.2
data DigestAlgorithm
  = DigestSHA1 -- ^§6.2.1
  | DigestSHA224 -- ^§6.2.2
  | DigestSHA256 -- ^§6.2.3
  | DigestSHA384 -- ^§6.2.4
  | DigestSHA512 -- ^§6.2.5
  | DigestRIPEMD160 -- ^xmlenc §5.7.4
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI DigestAlgorithm where
  identifier DigestSHA1 = nsFrag "sha1"
  identifier DigestSHA224 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#sha224"
  identifier DigestSHA256 = httpURI "www.w3.org" "/2001/04/xmlenc" "" "#sha256"
  identifier DigestSHA384 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#sha384"
  identifier DigestSHA512 = httpURI "www.w3.org" "/2001/04/xmlenc" "" "#sha512"
  identifier DigestRIPEMD160 = httpURI "www.w3.org" "/2001/04/xmlenc" "" "#ripemd160"

-- |§6.3
data MACAlgorithm
  = MACHMAC_SHA1 -- ^§6.3.1
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI MACAlgorithm where
  identifier MACHMAC_SHA1 = nsFrag "hmac-sha1"

-- |§6.4
data SignatureAlgorithm
  = SignatureDSA_SHA1
  | SignatureDSA_SHA256
  | SignatureRSA_SHA1
  | SignatureRSA_SHA224
  | SignatureRSA_SHA256
  | SignatureRSA_SHA384
  | SignatureRSA_SHA512
  | SignatureECDSA_SHA1
  | SignatureECDSA_SHA224
  | SignatureECDSA_SHA256
  | SignatureECDSA_SHA384
  | SignatureECDSA_SHA512
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI SignatureAlgorithm where
  identifier SignatureDSA_SHA1 = nsFrag "dsa-sha1"
  identifier SignatureDSA_SHA256 = nsFrag11 "dsa-sha256"
  identifier SignatureRSA_SHA1 = nsFrag "rsa-sha1"
  identifier SignatureRSA_SHA224 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#rsa-sha224"
  identifier SignatureRSA_SHA256 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#rsa-sha256"
  identifier SignatureRSA_SHA384 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#rsa-sha384"
  identifier SignatureRSA_SHA512 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#rsa-sha512"
  identifier SignatureECDSA_SHA1   = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#ecdsa-sha1"
  identifier SignatureECDSA_SHA224 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#ecdsa-sha224"
  identifier SignatureECDSA_SHA256 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#ecdsa-sha256"
  identifier SignatureECDSA_SHA384 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#ecdsa-sha384"
  identifier SignatureECDSA_SHA512 = httpURI "www.w3.org" "/2001/04/xmldsig-more" "" "#ecdsa-sha512"

-- |§6.6
data TransformAlgorithm
  = TransformCanonicalization C14N.CanonicalizationAlgorithm -- ^§6.6.1
  | TransformBase64 -- ^§6.6.2
  | TransformXPath -- ^§6.6.3
  | TransformEnvelopedSignature -- ^§6.6.4
  | TransformXSLT -- ^§6.6.5
  deriving (Eq, Show)

instance Identifiable URI TransformAlgorithm where
  identifier (TransformCanonicalization c) = identifier c
  identifier TransformBase64 = nsFrag "base64"
  identifier TransformXPath = httpURI "www.w3.org" "/TR/1999/REC-xpath-19991116" "" ""
  identifier TransformEnvelopedSignature = nsFrag "enveloped-signature"
  identifier TransformXSLT = httpURI "www.w3.org" "/TR/1999/REC-xslt-19991116" "" ""
  identifiedValues =
    map TransformCanonicalization identifiedValues ++
    [ TransformBase64
    , TransformXSLT
    , TransformXPath
    , TransformEnvelopedSignature
    ]
