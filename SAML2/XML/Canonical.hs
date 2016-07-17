{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
-- |
-- XML Canonicalization
--
-- For <http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/> §6.5
module SAML2.XML.Canonical where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Lazy as BSL
import qualified Text.XML.HXT.Core as HXT

import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import SAML2.XML.Lint (xmllintToString)

-- |§6.5
data CanonicalizationAlgorithm
  = CanonicalXML10
    { canonicalWithComments :: Bool
    } -- ^§6.5.1 <http://www.w3.org/TR/xml-c14n/ xml-c14n>
  | CanonicalXML11
    { canonicalWithComments :: Bool
    } -- ^§6.5.2 <http://www.w3.org/TR/xml-c14n11/ xml-c14n11>
  | CanonicalXMLExcl10
    { canonicalWithComments :: Bool
    } -- ^<http://www.w3.org/TR/xml-exc-c14n/ xml-exc-c14n>
  deriving (Eq, Show)

instance Bounded CanonicalizationAlgorithm where
  minBound = CanonicalXML10 False
  maxBound = CanonicalXMLExcl10 True

instance Enum CanonicalizationAlgorithm where
  toEnum 0 = CanonicalXML10 False
  toEnum 1 = CanonicalXML10 True
  toEnum 2 = CanonicalXML11 False
  toEnum 3 = CanonicalXML11 True
  toEnum 4 = CanonicalXMLExcl10 False
  toEnum 5 = CanonicalXMLExcl10 True
  toEnum _ = error "SAML2.XML.Signature.CanonicalizationAlgorithm.toEnum: bad argument"
  fromEnum (CanonicalXML10 c)     = 0 + fromEnum c
  fromEnum (CanonicalXML11 c)     = 2 + fromEnum c
  fromEnum (CanonicalXMLExcl10 c) = 4 + fromEnum c

canonicalizationAlgorithmURI :: CanonicalizationAlgorithm -> URI
canonicalizationAlgorithmURI (CanonicalXML10 False)     = httpURI "www.w3.org" "/TR/2001/REC-xml-c14n-20010315" "" ""
canonicalizationAlgorithmURI (CanonicalXML10 True)      = httpURI "www.w3.org" "/TR/2001/REC-xml-c14n-20010315" "" "#WithComments"
canonicalizationAlgorithmURI (CanonicalXML11 False)     = httpURI "www.w3.org" "/2006/12/xml-c14n11" "" ""
canonicalizationAlgorithmURI (CanonicalXML11 True)      = httpURI "www.w3.org" "/2006/12/xml-c14n11" "" "#WithComments"
canonicalizationAlgorithmURI (CanonicalXMLExcl10 False) = httpURI "www.w3.org" "/2001/10/xml-exc-c14n" "" "#"
canonicalizationAlgorithmURI (CanonicalXMLExcl10 True)  = httpURI "www.w3.org" "/2001/10/xml-exc-c14n" "" "#WithComments"

instance XP.XmlPickler (PreidentifiedURI CanonicalizationAlgorithm) where
  xpickle = xpPreidentifiedURI canonicalizationAlgorithmURI

-- |Canonicalize and serialize an XML document
-- This currently just pipes out to xmllint -- there are a number of ways it could be improved.
canonicalize :: CanonicalizationAlgorithm -> HXT.IOStateArrow s HXT.XmlTree BS.ByteString
canonicalize a = (if canonicalWithComments a then HXT.this else HXT.removeAllComment)
  HXT.>>> xmllintToString ['-':'-':xla a]
  HXT.>>> HXT.arr (BSL.toStrict . BSB.toLazyByteString . BSB.stringUtf8) where
  xla CanonicalXML10{} = "c14n"
  xla CanonicalXML11{} = "c14n11"
  xla CanonicalXMLExcl10{} = "exc-c14n"
