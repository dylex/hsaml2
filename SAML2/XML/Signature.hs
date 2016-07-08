{-# LANGUAGE TypeSynonymInstances, FlexibleInstances, QuasiQuotes #-}
-- |
-- XML Signature Syntax and Processing
--
-- <http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/> (selected portions)
module SAML2.XML.Signature where

import SAML2.XML
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Pickle as XP

nsFrag :: String -> URI
nsFrag = httpURI "www.w3.org" "/2000/09/xmldsig" "" . ('#':)

ns :: Namespace 
ns = mkNamespace "ds" $ nsFrag ""

nsName :: XString -> QName
nsName = mkNName ns

-- |§4.0.1
newtype CryptoBinary = CryptoBinary XS.Base64Binary

-- |§4.1
data Signature = Signature
  { signatureId :: Maybe ID
  , signatureSignedInfo :: SignedInfo
  , signatureSignatureValue :: SignatureValue
  , signatureKeyInfo :: Maybe KeyInfo
  , signatureObject :: [Object]
  }

-- |§4.2
data SignatureValue = SignatureValue
  { signatureValueId :: Maybe ID
  , signatureValue :: XS.Base64Binary
  }

-- |§4.3
data SignedInfo = SignedInfo
  { signedInfoId :: Maybe ID
  , signedInfoCanonicalizationMethod :: CanonicalizationMethod
  , signedInfoSignatureMethod :: SignatureMethod
  , signedInfoReference :: List1 Reference
  }

-- |§4.3.1
data CanonicalizationMethod = CanonicalizationMethod 
  { canonicalizationMethodAlgorithm :: PreidentifiedURI CanonicalizationAlgorithm
  , canonicalizationMethod :: Nodes
  }

-- |§4.3.2
data SignatureMethod = SignatureMethod
  { signatureMethodAlgorithm :: PreidentifiedURI SignatureAlgorithm
  , signatureMethodHMACOutputLength :: Maybe Int
  , signatureMethod :: Nodes
  }

-- |§4.3.3
data Reference = Reference
  { referenceId :: Maybe ID
  , referenceURI :: Maybe AnyURI
  , referenceType :: Maybe AnyURI -- xml object type
  , referenceTransforms :: Maybe Transforms
  , referenceDigestMethod :: DigestMethod
  , referenceDigestValue :: DigestValue
  }

-- |§4.3.3.4
newtype Transforms = Transforms{ transforms :: List1 Transform }

instance XP.XmlPickler Transforms where
  xpickle = XP.xpElemQN (nsName "Transforms") $
    [XP.biCase|l <-> Transforms l|]
    XP.>$< xpList1 XP.xpickle

data Transform = Transform
  { transformAlgorithm :: PreidentifiedURI TransformAlgorithm
  , transform :: [TransformElement]
  }

instance XP.XmlPickler Transform where
  xpickle = XP.xpElemQN (nsName "Transform") $
    [XP.biCase|(a, l) <-> Transform a l|]
    XP.>$< (XP.xpAttrQN (nsName "Algorithm") XP.xpickle
      XP.>*< XP.xpList XP.xpickle)

data TransformElement
  = TransformElementXPath XString
  | TransformElement Node 

instance XP.XmlPickler TransformElement where
  xpickle = [XP.biCase|
      Left s  <-> TransformElementXPath s
      Right x <-> TransformElement x |]
    XP.>$< (XP.xpElemQN (nsName "XPath") XS.xpString
      XP.>|< XP.xpTree)

-- |§4.3.3.5
data DigestMethod = DigestMethod
  { digestAlgorithm :: PreidentifiedURI DigestAlgorithm
  , digest :: [Node]
  }

instance XP.XmlPickler DigestMethod where
  xpickle = XP.xpElemQN (nsName "DigestMethod") $
    [XP.biCase|(a, d) <-> DigestMethod a d|]
    XP.>$< (XP.xpCheckEmptyAttributes (XP.xpAttrQN (nsName "Algorithm") XP.xpickle)
      XP.>*< XP.xpList XP.xpTree)

-- |§4.3.3.6
newtype DigestValue = DigestValue XS.Base64Binary

instance XP.XmlPickler DigestValue where
  xpickle = XP.xpElemQN (nsName "DigestValue") $
    [XP.biCase|l <-> DigestValue l|]
    XP.>$< XS.xpBase64Binary

-- |§4.4
data KeyInfo = KeyInfo
  { keyInfoId :: Maybe ID
  , keyInfoElements :: List1 KeyInfoElement
  }
data KeyInfoElement
  = KeyInfoKeyName KeyName
  | KeyInfoKeyValue KeyValue
  -- | KeyInfoRetrievalMethod
  -- | KeyInfoX509Data
  -- | KeyInfoPGPData
  -- | KeyInfoSPKIData
  -- | KeyInfoMgmtData
  | KeyInfoElement Node

-- |§4.4.1
type KeyName = XString

-- |§4.4.2
data KeyValue
  = KeyValueDSA DSAKeyValue
  | KeyValueRSA RSAKeyValue
  | KeyValue Node

-- |§4.4.2.1
data DSAKeyValue = DSAKeyValue
  { dsaKeyValuePQ :: Maybe (CryptoBinary, CryptoBinary)
  , dsaKeyValueG :: Maybe CryptoBinary
  , dsaKeyValueY :: CryptoBinary
  , dsaKeyValueJ :: Maybe CryptoBinary
  , dsaKeyValueSeedPgenCounter :: Maybe (CryptoBinary, CryptoBinary)
  }

-- |§4.4.2.2
data RSAKeyValue = RSAKeyValue
  { rsaKeyValueModulus
  , rsaKeyValueExponent :: CryptoBinary
  }

-- |§4.5
data Object = Object
  { objectId :: Maybe ID
  , objectMimeType :: Maybe XString
  , objectEncoding :: Maybe (PreidentifiedURI EncodingAlgorithm)
  , objectXML :: Nodes
  }

instance XP.XmlPickler Object where
  xpickle = XP.xpElemQN (nsName "Object") $
    [XP.biCase|(((i, m), e), x) <-> Object i m e x|] 
    XP.>$< (XP.xpCheckEmptyAttributes (XP.xpOption (XP.xpAttrQN (nsName "Id") XS.xpID)
      XP.>*< XP.xpOption (XP.xpAttrQN (nsName "MimeType") XS.xpString)
      XP.>*< XP.xpOption (XP.xpAttrQN (nsName "Encoding") XP.xpickle))
      XP.>*< XP.xpTrees)

-- |§6.1
data EncodingAlgorithm
  = EncodingBase64
  deriving (Eq, Bounded, Enum)

instance XP.XmlPickler (PreidentifiedURI EncodingAlgorithm) where
  xpickle = xpPreidentifiedURI f where
    f EncodingBase64 = nsFrag "base64"

-- |§6.2
data DigestAlgorithm
  = DigestSHA1 -- ^§6.2.1
  deriving (Eq, Bounded, Enum)

instance XP.XmlPickler (PreidentifiedURI DigestAlgorithm) where
  xpickle = xpPreidentifiedURI f where
    f DigestSHA1 = nsFrag "sha1"

-- |§6.3
data MACAlgorithm
  = MACHMAC_SHA1 -- ^§6.3.1
  deriving (Eq, Bounded, Enum)

instance XP.XmlPickler (PreidentifiedURI MACAlgorithm) where
  xpickle = xpPreidentifiedURI f where
    f MACHMAC_SHA1 = nsFrag "hmac-sha1"

-- |§6.4
data SignatureAlgorithm
  = SignatureDSA_SHA1
  | SignatureRSA_SHA1
  deriving (Eq, Bounded, Enum)

instance XP.XmlPickler (PreidentifiedURI SignatureAlgorithm) where
  xpickle = xpPreidentifiedURI f where
    f SignatureDSA_SHA1 = nsFrag "dsa-sha1"
    f SignatureRSA_SHA1 = nsFrag "rsa-sha1"

-- |§6.5
data CanonicalizationAlgorithm
  = CanonicalXML10 -- ^§6.5.1
  | CanonicalXML10Comments -- ^§6.5.1
  | CanonicalXML11 -- ^§6.5.2
  | CanonicalXML11Comments -- ^§6.5.2
  deriving (Eq, Bounded, Enum)

canonicalizationAlgorithmURI :: CanonicalizationAlgorithm -> URI
canonicalizationAlgorithmURI CanonicalXML10         = httpURI "www.w3.org" "/TR/2001/REC-xml-c14n-20010315" "" ""
canonicalizationAlgorithmURI CanonicalXML10Comments = httpURI "www.w3.org" "/TR/2001/REC-xml-c14n-20010315" "" "#WithComments"
canonicalizationAlgorithmURI CanonicalXML11         = httpURI "www.w3.org" "/2006/12/xml-c14n11" "" ""
canonicalizationAlgorithmURI CanonicalXML11Comments = httpURI "www.w3.org" "/2006/12/xml-c14n11" "" "#WithComments"

instance XP.XmlPickler (PreidentifiedURI CanonicalizationAlgorithm) where
  xpickle = xpPreidentifiedURI canonicalizationAlgorithmURI

-- |§6.6
data TransformAlgorithm
  = TransformCanonicalization CanonicalizationAlgorithm -- ^§6.6.1
  | TransformBase64 -- ^§6.6.2
  | TransformXPath -- ^§6.6.3
  | TransformEnvelopedSignature -- ^§6.6.4
  | TransformXSLT -- ^§6.6.5
  deriving (Eq)

instance Bounded TransformAlgorithm where
  minBound = TransformBase64
  maxBound = TransformCanonicalization maxBound

instance Enum TransformAlgorithm where
  fromEnum TransformBase64 = 0
  fromEnum TransformXSLT = 1
  fromEnum TransformXPath = 2
  fromEnum TransformEnvelopedSignature = 3
  fromEnum (TransformCanonicalization c) = 4 + fromEnum c
  toEnum 0 = TransformBase64
  toEnum 1 = TransformXSLT
  toEnum 2 = TransformXPath
  toEnum 3 = TransformEnvelopedSignature
  toEnum c = TransformCanonicalization (toEnum (c - 4))

instance XP.XmlPickler (PreidentifiedURI TransformAlgorithm) where
  xpickle = xpPreidentifiedURI f where
    f (TransformCanonicalization c) = canonicalizationAlgorithmURI c
    f TransformBase64 = nsFrag "base64"
    f TransformXPath = httpURI "www.w3.org" "/TR/1999/REC-xpath-19991116" "" ""
    f TransformEnvelopedSignature = nsFrag "enveloped-signature"
    f TransformXSLT = httpURI "www.w3.org" "/TR/1999/REC-xslt-19991116" "" ""

