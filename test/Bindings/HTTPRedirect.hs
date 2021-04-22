module Bindings.HTTPRedirect (tests) where

import qualified Data.ByteString.Char8 as BSC
import Data.Time (UTCTime(..), fromGregorian)
import qualified Test.HUnit as U
import Data.ByteString.Char8 (unpack)
import Network.HTTP.Types.URI (renderQuery)

import SAML2.XML
import SAML2.Core.Versioning
import SAML2.Core.Identifiers
import SAML2.Core.Assertions
import SAML2.Core.Protocols
import SAML2.Bindings.HTTPRedirect

import XML
import XML.Keys

tests :: U.Test
tests = U.test
  [ U.TestCase $ do 
      let baseURI = "https://ServiceProvider.com/SAML/SLO/Browser"
          request = 
            (RequestLogoutRequest $ LogoutRequest
              (RequestAbstractType $ ProtocolType
                "d2b7c388cec36fa7c39c28fd298644a8"
                SAML20
                (UTCTime (fromGregorian 2004 1 21) (19*60*60+49))
                (Just $ uri baseURI)
                (Identified ConsentUnspecified)
                (Just $ Issuer $ simpleNameID NameIDFormatEntity "https://IdentityProvider.com/SAML")
                Nothing
                []
                (Just $ BSC.pack "0043bfc1bc45110dae17004005b13a2b"))
              Nothing
              Nothing
              (NotEncrypted $ IdentifierName $ simpleNameID NameIDFormatPersistent "005a06e0-ad82-110d-a556-004005b13a2b")
              ["1"])
      query <- unpack . renderQuery True <$> encodeQuery (Just privkey1) request
      decodedRequest <- decodeURI pubkey1 (uri $ baseURI ++ query)
      U.assertEqual "request" request decodedRequest
  , U.TestCase $ do
      let baseURI = "https://IdentityProvider.com/SAML" 
          resp = (LogoutResponse $ StatusResponseType
                          (ProtocolType
                            "b0730d21b628110d8b7e004005b13a2b"
                            SAML20
                            (UTCTime (fromGregorian 2004 1 21) (19*60*60+49))
                            (Just $ uri baseURI)
                            (Identified ConsentUnspecified)
                            (Just $ Issuer $ simpleNameID NameIDFormatEntity "https://ServiceProvider.com/SAML")
                            Nothing
                            []
                            (Just $ BSC.pack "0043bfc1bc45110dae17004005b13a2b"))
                          (Just "d2b7c388cec36fa7c39c28fd298644a8")
                          successStatus)
      query <- unpack . renderQuery True <$> encodeQuery (Just privkey1) resp
      decodedResponse <- decodeURI pubkey1 (uri $ baseURI ++ query)
      U.assertEqual "response" resp decodedResponse
  ]
