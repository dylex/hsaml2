{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
-- |
-- XML Canonicalization
--
-- For <http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/> §6.5
module SAML2.XML.Canonical where

import Control.Monad ((<=<))
import qualified Data.ByteString as BS
import Data.Tree.Class (getChildren)
import qualified Text.XML.HXT.Core as HXT

import SAML2.XML
import qualified SAML2.XML.LibXML2 as LibXML2
import qualified SAML2.XML.Schema as XS
import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP

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

newtype InclusiveNamespaces = InclusiveNamespaces
  { inclusiveNamespacesPrefixList :: XS.NMTOKENS
  } deriving (Eq, Show)

instance XP.XmlPickler InclusiveNamespaces where
  xpickle = xpTrimElemNS (mkNamespace "ec" (httpURI "www.w3.org" "/2001/10/xml-exc-c14n" "" "#")) "InclusiveNamespaces" $
    [XP.biCase|n <-> InclusiveNamespaces n|]
    XP.>$< XP.xpAttr "PrefixList" XS.xpNMTOKENS

-- |Canonicalize and serialize an XML document
--
-- TODO: this is chopping off the root of the input and only considers the children, which is
-- at best surprising.  we should remove this function and only use 'canonicalize'' instead
-- (see below).
canonicalize :: CanonicalizationAlgorithm -> Maybe InclusiveNamespaces -> Maybe String -> HXT.XmlTree -> IO BS.ByteString
canonicalize a i s = canonicalize' a i s . getChildren

canonicalize' :: CanonicalizationAlgorithm -> Maybe InclusiveNamespaces -> Maybe String -> HXT.XmlTrees -> IO BS.ByteString
canonicalize' a i s =
  LibXML2.c14n (cm a) (inclusiveNamespacesPrefixList <$> i) (canonicalWithComments a) s
    <=< LibXML2.fromXmlTrees where
  cm CanonicalXML10{} = LibXML2.C14N_1_0
  cm CanonicalXML11{} = LibXML2.C14N_1_1
  cm CanonicalXMLExcl10{} = LibXML2.C14N_EXCLUSIVE_1_0
