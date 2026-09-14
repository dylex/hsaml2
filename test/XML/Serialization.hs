{-# LANGUAGE OverloadedStrings #-}

module XML.Serialization (tests) where

import qualified Test.HUnit as U
import Text.XML.HXT.DOM.XmlNode (mkText)

import qualified SAML2.Core.Assertions as A
import SAML2.Core.Identifiers (AttributeNameFormat(AttributeNameFormatUnspecified))
import SAML2.XML

-- | XML meta-characters plus codepoints outside Latin-1.
riskyString :: String
riskyString = "><& проверка テスト 🪲"

mkAttribute :: String -> A.Attribute
mkAttribute v = A.Attribute
  { A.attributeName = "x"
  , A.attributeNameFormat = Identified AttributeNameFormatUnspecified
  , A.attributeFriendlyName = Nothing
  , A.attributeAttrs = []
  , A.attributeValues = [[mkText v]]
  }

assertRoundTrips :: String -> A.Attribute -> Either String A.Attribute -> U.Assertion
assertRoundTrips label orig parsed = case parsed of
  Left err -> U.assertFailure $ label ++ ": failed to parse serialized output: " ++ err
  Right orig' -> U.assertEqual label orig orig'

tests :: U.Test
tests = U.test [encodingAndXMLEscapingRegressionTests]

-- | The serialization functions used to be implemented via HXT's 'Text.XML.HXT.DOM.ShowXml.xshowBlob', which
--
--   1. never XML-escapes '<'\/'&' in text content, so a value containing them produced
--      invalid or structurally wrong XML, and
--   2. packs the shown 'String' into a 'Data.ByteString.Lazy.ByteString' by truncating
--      every 'Char' to @fromEnum c \`mod\` 256@ (i.e. it only supports Latin-1), silently
--      corrupting anything else.
encodingAndXMLEscapingRegressionTests :: U.Test
encodingAndXMLEscapingRegressionTests = U.test
  [ U.TestCase $ do
      let attr = mkAttribute riskyString
      assertRoundTrips "(xmlToSAML . samlToXML) round-trip" attr
        (xmlToSAML $ samlToXML attr)
  , U.TestCase $ do
      let attr = mkAttribute riskyString
      assertRoundTrips "(xmlToSAML . docToXMLWithRoot . samlToDocFirstChild) round-trip" attr
        (xmlToSAML . docToXMLWithRoot $ samlToDocFirstChild attr)
  , U.TestCase $ do
      let attr = mkAttribute riskyString
      assertRoundTrips "(xmlToSAML . docToXMLWithoutRoot . samlToDoc) round-trip" attr
        (xmlToSAML . docToXMLWithoutRoot $ samlToDoc attr)
  ]
