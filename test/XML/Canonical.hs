{-# LANGUAGE OverloadedStrings #-}
module XML.Canonical (tests) where

import qualified Data.ByteString as BS
import qualified Test.HUnit as U
import qualified Text.XML.HXT.Core as HXT

import SAML2.XML.Canonical

canonicalizeXML :: CanonicalizationAlgorithm -> String -> IO [BS.ByteString]
canonicalizeXML c f = HXT.runX $
  (HXT.readDocument [HXT.withCheckNamespaces HXT.yes, HXT.withValidate HXT.no, HXT.withCanonicalize HXT.no] f
  HXT.>>> canonicalize c)

testC14N :: CanonicalizationAlgorithm -> String -> BS.ByteString -> U.Test
testC14N c f s = U.TestCase $
  U.assertEqual (show c ++ ' ' : f) [s] =<< canonicalizeXML c f

tests :: U.Test
tests = U.test
  [ testC14N (CanonicalXML10 False) "test/XML/noncanonical1.xml"
    "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
  , testC14N (CanonicalXML10 True) "test/XML/noncanonical1.xml"
    "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
  , testC14N (CanonicalXML10 False) "test/XML/noncanonical2.xml"
    "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>"
  , testC14N (CanonicalXML10 False) "test/XML/noncanonical3.xml"
    "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 xmlns:a=\"http://www.ietf.org\" attr=\"default\"></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>"
  , testC14N (CanonicalXML10 False) "test/XML/noncanonical4.xml"
    "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n   <normNames attr=\"A &#xD;&#xA;&#x9; B\"></normNames>\n   <normId id=\"' &#xD;&#xA;&#x9; '\"></normId>\n</doc>"
  , testC14N (CanonicalXML10 False) "test/XML/noncanonical5.xml"
    "<doc attrExtEnt=\"entExt\">\n   Hello, world!\n</doc>"
  , testC14N (CanonicalXML10 False) "test/XML/noncanonical6.xml"
    "<doc>#xC2#xA9</doc>"
  ]
