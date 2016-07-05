-- |
-- XML Signature Syntax and Processing
--
-- <http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/> (selected portions)
module SAML2.XML.Signature where

import qualified SAML2.XML as XML
import qualified SAML2.XML.Schema as XS

-- |§4.0.1
newtype CryptoBinary = CryptoBinary XS.Base64Binary

-- |§4.1
data Signature = Signature
  { signatureId :: Maybe XML.ID
  , signatureSignedInfo :: SignedInfo
  , signatureSignatureValue :: SignatureValue
  , signatureKeyInfo :: Maybe KeyInfo
  , signatureObject :: [Object]
  }

-- |§4.2
data SignatureValue = SignatureValue
  { signatureValueId :: Maybe XML.ID
  , signatureValue :: XS.Base64Binary
  }

-- |§4.3
data SignedInfo = SignedInfo
  { signedInfoId :: Maybe XML.ID
  , signedInfoCanonicalizationMethod :: CanonicalizationMethod
  , signedInfoSignatureMethod :: SignatureMethod
  , signedInfoReference :: XML.List1 Reference
  }

-- |§4.3.1
data CanonicalizationMethod = CanonicalizationMethod 
  { canonicalizationMethodAlgorithm :: CanonicalizationAlgorithm
  , canonicalizationMethod :: XML.Nodes
  }

-- |§4.3.2
data SignatureMethod = SignatureMethod
  { signatureMethodAlgorithm :: SignatureAlgorithm
  , signatureMethodHMACOutputLength :: Maybe Int
  , signatureMethod :: XML.Nodes
  }

-- |§4.3.3
data Reference = Reference
  { referenceId :: Maybe XML.ID
  , referenceURI :: Maybe XML.AnyURI
  , referenceType :: Maybe XML.AnyURI -- xml object type
  , referenceTransforms :: Maybe Transforms
  , referenceDigestMethod :: DigestMethod
  , referenceDigestValue :: DigestValue
  }

-- |§4.3.3.4
type Transforms = XML.List1 Transform
data Transform = Transform
  { transformAlgorithm :: TransformAlgorithm
  , transform :: [TransformElement]
  }
data TransformElement
  = TransformElementXPath XML.String
  | TransformElement XML.Node 

-- |§4.3.3.5
data DigestMethod = DigestMethod
  { digestAlgorithm :: DigestAlgorithm
  , digest :: [XML.Node]
  }

-- |§4.3.3.6
newtype DigestValue = DigestValue XS.Base64Binary

-- |§4.4
data KeyInfo = KeyInfo
  { keyInfoId :: Maybe XML.ID
  , keyInfoElements :: XML.List1 KeyInfoElement
  }
data KeyInfoElement
  = KeyInfoKeyName KeyName
  | KeyInfoKeyValue KeyValue
  -- | KeyInfoRetrievalMethod
  -- | KeyInfoX509Data
  -- | KeyInfoPGPData
  -- | KeyInfoSPKIData
  -- | KeyInfoMgmtData
  | KeyInfoElement XML.Node

-- |§4.4.1
type KeyName = XML.String

-- |§4.4.2
data KeyValue
  = KeyValueDSA DSAKeyValue
  | KeyValueRSA RSAKeyValue
  | KeyValue XML.Node

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
  { objectId :: Maybe XML.ID
  , objectMimeType :: Maybe XML.String
  , objectEncoding :: Maybe EncodingAlgorithm
  , objectXML :: XML.Nodes
  }

-- |§6.1
data EncodingAlgorithm
  = EncodingBase64
  | EncodingAlgorithm XML.AnyURI

-- |§6.2
data DigestAlgorithm
  = DigestSHA1 -- ^§6.2.1
  | DigestAlgorithm XML.AnyURI

-- |§6.3
data MACAlgorithm
  = MACHMAC_SHA1 -- ^§6.3.1
  | MACAlgorithm XML.AnyURI

-- |§6.4
data SignatureAlgorithm
  = SignatureDSA_SHA1
  | SignatureRSA_SHA1
  | SignatureAlgorithm XML.AnyURI

-- |§6.5
data CanonicalizationAlgorithm
  = CanonicalXML10 -- ^§6.5.1
  | CanonicalXML10Comments -- ^§6.5.1
  | CanonicalXML11 -- ^§6.5.2
  | CanonicalXML11Comments -- ^§6.5.2
  | CanonicalizationAlgorithm XML.AnyURI

-- |§6.6
data TransformAlgorithm
  = TransformCanonicalization CanonicalizationAlgorithm -- ^§6.6.1
  | TransformBase64 -- ^§6.6.2
  | TransformXPath -- ^§6.6.3
  | TransformEnvelopedSignature -- ^§6.6.4
  | TransformXSLT -- ^§6.6.5
  | TransformAlgorithm XML.AnyURI
