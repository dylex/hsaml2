module XML
  ( testXML
  , uri
  , pickleElem
  ) where

import Data.Maybe (fromJust)
import Network.URI (URI, parseURIReference)
import qualified Test.HUnit as U

import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.HTTP as HXT (withHTTP)
import qualified Text.XML.HXT.DOM.XmlNode as DOM

parseXML :: HXT.XmlPickler a => String -> IO [Either String a]
parseXML u = fmap (map (HXT.unpickleDoc' HXT.xpickle)) $
  HXT.runX $
    HXT.readDocument [HXT.withCheckNamespaces HXT.yes, HXT.withHTTP [], HXT.withRemoveWS HXT.yes] u
    HXT.>>> HXT.processBottomUp (HXT.processAttrl (HXT.none `HXT.when` HXT.isNamespaceDeclAttr))

testXML :: (Eq a, HXT.XmlPickler a, Show a) => String -> a -> U.Test
testXML u a = U.TestCase $
  U.assertEqual u [Right a] =<< parseXML u

uri :: String -> URI
uri = fromJust . parseURIReference

pickleElem :: HXT.PU a -> a -> HXT.XmlTree
pickleElem p = head . DOM.getChildren . HXT.pickleDoc p
