{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE TypeOperators #-}
module SAML2.XML
  ( module SAML2.XML.Types
  , module SAML2.Core.Datatypes
  , URI
  , xpAnyCont
  , xpAnyAttrs
  , xpAny
  , xpAnyElem
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
  , samlToXML
  , docToSAML
  , docToXML
  , xmlToSAML
  , xmlToDoc
  ) where

import Control.Monad.State.Class (state)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Data.Default (Default(..))
import qualified Data.Invertible as Inv
import Data.List (partition)
import Data.Maybe (listToMaybe)
import Network.URI (URI)
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.DOM.XmlNode as HX
import qualified Text.XML.HXT.Arrow.Pickle.Schema as SC

import SAML2.XML.Types
import SAML2.Core.Datatypes
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS

xpAnyCont :: XP.PU HXT.XmlTrees
xpAnyCont = XP.PU
  { XP.appPickle = \c s -> s{ XP.contents = c ++ XP.contents s }
  , XP.appUnPickle = state $ \s -> (XP.contents s, s{ XP.contents = [] })
  , XP.theSchema = SC.Any -- XXX
  }

xpAnyAttrs :: XP.PU HXT.XmlTrees
xpAnyAttrs = XP.PU
  { XP.appPickle = \a s -> s{ XP.attributes = a ++ XP.attributes s }
  , XP.appUnPickle = state $ \s -> (XP.attributes s, s{ XP.attributes = [] })
  , XP.theSchema = SC.Any -- XXX
  }

-- |Any content and attributes
xpAny :: XP.PU HXT.XmlTrees
xpAny = (uncurry (++) Inv.:<->: partition HX.isAttr) XP.>$< (xpAnyAttrs XP.>*< xpAnyCont)

xpAnyElem :: XP.PU HXT.XmlTree
xpAnyElem = XP.xpWrapEither 
  ( \e -> if HX.isElem e then Right e else Left "xpAnyElem: any element expected"
  , id
  ) XP.xpTree

xpTrimAnyElem :: XP.PU HXT.XmlTree
xpTrimAnyElem = XP.xpWhitespace XP.*< xpAnyElem

xpTrimElemNS :: Namespace -> String -> XP.PU a -> XP.PU a
xpTrimElemNS ns n c = XP.xpWhitespace XP.*< XP.xpElemQN (mkNName ns n) (c XP.>* XP.xpWhitespace)

xpXmlLang :: XP.PU XS.Language
xpXmlLang = XP.xpAttrQN (mkNName xmlNS "lang") $ XS.xpLanguage

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

docToXML :: HXT.XmlTree -> BSL.ByteString
docToXML = BSL.concat . HXT.runLA (HXT.xshowBlob HXT.getChildren)

samlToXML :: XP.XmlPickler a => a -> BSL.ByteString
samlToXML = docToXML . samlToDoc

xmlToDoc :: BSL.ByteString -> Maybe HXT.XmlTree
xmlToDoc = listToMaybe . HXT.runLA
  (HXT.xreadDoc
  HXT.>>> HXT.removeWhiteSpace
  HXT.>>> HXT.neg HXT.isXmlPi)
  . BSLC.unpack -- XXX encoding?

docToSAML :: XP.XmlPickler a => HXT.XmlTree -> Either String a
docToSAML = XP.unpickleDoc' XP.xpickle
  . head
  . HXT.runLA (HXT.propagateNamespaces
      HXT.>>> HXT.processBottomUp (HXT.processAttrl (HXT.neg HXT.isNamespaceDeclAttr)))

xmlToSAML :: XP.XmlPickler a => BSL.ByteString -> Either String a
xmlToSAML = maybe (Left "invalid XML") docToSAML . xmlToDoc
