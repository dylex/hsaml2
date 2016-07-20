{-# LANGUAGE MultiParamTypeClasses #-}
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

instance Identifiable URI CanonicalizationAlgorithm where
  identifier (CanonicalXML10 False)     = httpURI "www.w3.org" "/TR/2001/REC-xml-c14n-20010315" "" ""
  identifier (CanonicalXML10 True)      = httpURI "www.w3.org" "/TR/2001/REC-xml-c14n-20010315" "" "#WithComments"
  identifier (CanonicalXML11 False)     = httpURI "www.w3.org" "/2006/12/xml-c14n11" "" ""
  identifier (CanonicalXML11 True)      = httpURI "www.w3.org" "/2006/12/xml-c14n11" "" "#WithComments"
  identifier (CanonicalXMLExcl10 False) = httpURI "www.w3.org" "/2001/10/xml-exc-c14n" "" "#"
  identifier (CanonicalXMLExcl10 True)  = httpURI "www.w3.org" "/2001/10/xml-exc-c14n" "" "#WithComments"
  identifiedValues =
    [ CanonicalXML10 False
    , CanonicalXML10 True
    , CanonicalXML11 False
    , CanonicalXML11 True
    , CanonicalXMLExcl10 False
    , CanonicalXMLExcl10 True
    ]

-- |Canonicalize and serialize an XML document
-- This currently just pipes out to xmllint -- there are a number of ways it could be improved.
canonicalize :: CanonicalizationAlgorithm -> HXT.IOStateArrow s HXT.XmlTree BS.ByteString
canonicalize a = (if canonicalWithComments a then HXT.this else HXT.removeAllComment)
  HXT.>>> xmllintToString ['-':'-':xla a]
  HXT.>>> HXT.arr (BSL.toStrict . BSB.toLazyByteString . BSB.stringUtf8) where
  xla CanonicalXML10{} = "c14n"
  xla CanonicalXML11{} = "c14n11"
  xla CanonicalXMLExcl10{} = "exc-c14n"
