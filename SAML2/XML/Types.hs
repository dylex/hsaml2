{-# LANGUAGE QuasiQuotes #-}
module SAML2.XML.Types where

import Data.List.NonEmpty (NonEmpty(..))
import Network.URI (URI(..), URIAuth(..), uriToString)
import qualified Text.XML.HXT.DOM.TypeDefs as HXT

import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP

type Node = HXT.XmlTree
-- instance XP.XmlPickler XML.Node where xpickle = XP.xpTree
type Nodes = HXT.XmlTrees
-- instance XP.XmlPickler XML.Nodes where xpickle = XP.xpTrees
type List1 a = NonEmpty a

xpList1 :: XP.PU a -> XP.PU (List1 a)
xpList1 f = [XP.biCase|a:l <-> a:|l|] XP.>$< XP.xpList1 f

type QName = HXT.QName

data Namespace = Namespace
  { namespacePrefix :: !String
  , namespaceURI :: !URI
  , namespaceURIString :: !String
  }

mkNamespace :: String -> URI -> Namespace
mkNamespace p u = Namespace p u $ uriToString id u ""

mkNName :: Namespace -> String -> QName
mkNName ns n = HXT.mkQName (namespacePrefix ns) n (namespaceURIString ns)

httpURI :: String -> String -> String -> String -> URI
httpURI host = URI "http:" $ Just $ URIAuth "" host ""

xmlNS, xmlnsNS :: Namespace
xmlNS = mkNamespace "xml" $ httpURI "www.w3.org" "/XML/1998/namespace" "" ""
xmlnsNS = mkNamespace "xmlns" $ httpURI "www.w3.org" "/2000/xmlns/" "" ""
