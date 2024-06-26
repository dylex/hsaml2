{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE TypeOperators #-}
module SAML2.XML
  ( module SAML2.XML.Types
  , module SAML2.Core.Datatypes
  , URI
  , xpTrimAnyElem
  , xpTrimElemNS
  , xpXmlLang
  , IP, xpIP
  , Identified(..)
  , Identifiable(..)
  , unidentify
  , xpIdentified
  , xpIdentifier
  , IdentifiedURI
  , samlToDoc
  , samlToDocFirstChild
  , samlToXML
  , docToSAML
  , docToXMLWithoutRoot
  , docToXMLWithRoot
  , xmlToSAML
  , xmlToDoc
  , xmlToDocE
  ) where

import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.UTF8 as BSLU
import Data.Default (Default(..))
import qualified Data.Invertible as Inv
import Data.Maybe (listToMaybe)
import Network.URI (URI)
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.DOM.ShowXml
import Text.XML.HXT.DOM.XmlNode (getChildren)
import qualified Data.Tree.NTree.TypeDefs as HXT

import SAML2.XML.Types
import SAML2.Core.Datatypes
import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP
import qualified SAML2.XML.Schema as XS

xpTrimAnyElem :: XP.PU HXT.XmlTree
xpTrimAnyElem = XP.xpTrim XP.xpAnyElem

xpTrimElemNS :: Namespace -> String -> XP.PU a -> XP.PU a
xpTrimElemNS ns n c = XP.xpTrim $ XP.xpElemQN (mkNName ns n) (c XP.>* XP.xpWhitespace)

xpXmlLang :: XP.PU XS.Language
xpXmlLang = XP.xpAttrQN (mkNName xmlNS "lang") XS.xpLanguage

type IP = XS.String

xpIP :: XP.PU IP
xpIP = XS.xpString

data Identified b a
  = Identified !a
  | Unidentified !b
  deriving (Eq, Show)

instance Default a => Default (Identified b a) where
  def = Identified def

class Eq b => Identifiable b a | a -> b where
  identifier :: a -> b
  identifiedValues :: [a]
  default identifiedValues :: (Bounded a, Enum a) => [a]
  identifiedValues = [minBound..maxBound]
  reidentify :: b -> Identified b a
  reidentify u = maybe (Unidentified u) Identified $ lookup u l where
    l = [ (identifier a, a) | a <- identifiedValues ]

unidentify :: Identifiable b a => Identified b a -> b
unidentify (Identified a) = identifier a
unidentify (Unidentified b) = b

identify :: Identifiable b a => b Inv.<-> Identified b a
identify = reidentify Inv.:<->: unidentify

xpIdentified :: Identifiable b a => XP.PU b -> XP.PU (Identified b a)
xpIdentified = Inv.fmap identify

xpIdentifier :: Identifiable b a => XP.PU b -> String -> XP.PU a
xpIdentifier b t = XP.xpWrapEither
  ( \u -> case reidentify u of
      Identified a -> Right a
      Unidentified _ -> Left ("invalid " ++ t)
  , identifier
  ) b

type IdentifiedURI = Identified URI

instance Identifiable URI a => XP.XmlPickler (Identified URI a) where
  xpickle = xpIdentified XS.xpAnyURI

samlToDoc :: XP.XmlPickler a => a -> HXT.XmlTree
samlToDoc = head
  . HXT.runLA (HXT.processChildren $ HXT.cleanupNamespaces HXT.collectPrefixUriPairs)
  . XP.pickleDoc XP.xpickle

-- | From the input xml forest, take the first child of the first tree.
samlToDocFirstChild :: XP.XmlPickler a => a -> HXT.XmlTree
samlToDocFirstChild = head . getChildren . head
  . HXT.runLA (HXT.processChildren $ HXT.cleanupNamespaces HXT.collectPrefixUriPairs)
  . XP.pickleDoc XP.xpickle

-- | see also 'docToXMLWithRoot'
docToXMLWithoutRoot :: HXT.XmlTree -> BSL.ByteString
docToXMLWithoutRoot =  BSL.concat . HXT.runLA (HXT.xshowBlob HXT.getChildren)

-- | 'docToXML' chops off the root element from the tree.  'docToXMLWithRoot' does not do
-- this.  it may make sense to remove 'docToXMLWithoutRoot', but since i don't understand this
-- code enough to be confident not to break anything, i'll just leave this extra function for
-- reference.
docToXMLWithRoot :: HXT.XmlTree -> BSL.ByteString
docToXMLWithRoot = Text.XML.HXT.DOM.ShowXml.xshowBlob . (:[])

samlToXML :: XP.XmlPickler a => a -> BSL.ByteString
samlToXML = docToXMLWithoutRoot . samlToDoc

xmlToDoc :: BSL.ByteString -> Maybe HXT.XmlTree
xmlToDoc = either (const Nothing) Just . xmlToDocE

xmlToDocE :: BSL.ByteString -> Either String HXT.XmlTree
xmlToDocE = fix . xmlToDocUnsafe
  where
    fix Nothing =
      Left "Nothing"
    fix (Just (HXT.NTree (HXT.XError num msg) shouldBeEmpty)) =
      Left $ show num ++ ": " ++ msg ++ (if null shouldBeEmpty then "" else show shouldBeEmpty)
    fix (Just good) =
      Right good

-- | Take a UTF-8 encoded bytestring and return an xml tree.  This is unsafe and returns xml
-- trees containing parse errors on occasion; call 'xmlToDocE' instead.
xmlToDocUnsafe :: BSL.ByteString -> Maybe HXT.XmlTree
xmlToDocUnsafe = listToMaybe . HXT.runLA
  (HXT.xreadDoc
  HXT.>>> HXT.removeWhiteSpace
  HXT.>>> HXT.neg HXT.isXmlPi
  HXT.>>> HXT.propagateNamespaces)
  . BSLU.toString

docToSAML :: XP.XmlPickler a => HXT.XmlTree -> Either String a
docToSAML = XP.unpickleDoc' XP.xpickle
  . head
  . HXT.runLA (HXT.processBottomUp (HXT.processAttrl (HXT.neg HXT.isNamespaceDeclAttr)))

xmlToSAML :: XP.XmlPickler a => BSL.ByteString -> Either String a
xmlToSAML = maybe (Left "invalid XML") docToSAML . xmlToDoc
