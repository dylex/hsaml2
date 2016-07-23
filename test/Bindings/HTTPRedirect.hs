module Bindings.HTTPRedirect (tests) where

import qualified Data.ByteString.Char8 as BSC
import Data.Time (UTCTime(..), fromGregorian)
import qualified Test.HUnit as U

import SAML2.XML
import SAML2.Core.Versioning
import SAML2.Core.Identifiers
import SAML2.Core.Assertions
import SAML2.Core.Protocols
import SAML2.Bindings.HTTPRedirect

import XML

tests :: U.Test
tests = U.test
  [ U.TestCase $ U.assertEqual "response"
    (LogoutResponse $ StatusResponseType
      (ProtocolType
        "b0730d21b628110d8b7e004005b13a2b"
        SAML20
        (UTCTime (fromGregorian 2004 1 21) (19*60*60+49))
        Nothing
        (Identified ConsentUnspecified)
        (Just $ Issuer $ simpleNameID NameIDFormatUnspecified "https://ServiceProvider.com/SAML")
        Nothing
        []
        (Just $ BSC.pack "0043bfc1bc45110dae17004005b13a2b"))
      (Just "d2b7c388cec36fa7c39c28fd298644a8")
      successStatus)
    =<< decodeURI mempty (readURI "https://IdentityProvider.com/SAML/SLO/Response?SAMLResponse=fVFNa4QwEL0X%2Bh8k912TaDUGFUp7EbZQ6rKH3mKcbQVNJBOX%2FvxaXQ9tYec0vHlv3nzkqIZ%2BlAf7YSf%2FBjhagxB8Db1BuZQKMjkjrcIOpVEDoPRa1o8vB8n3VI7OeqttT1bJbbJCBOc7a8j9XTBH9VyQhqYRbTlrEi4Yo61oUqA0pvShYZHiDQkqs411tAVpeZPqSAgNOkrOas4zzcW55ZlI4liJrTXiBJVBr4wvCJ877ijbcXZkmaRUxtk7CU7gcB5mLu8pKVddvghd%2Ben9iDIMa3CXTsOrs5euBbfXdgh%2F9snDK%2FEqW69Ye%2BUnvGL%2F8CfbQnBS%2FQS3z4QLW9aT1oBIws0j%2FGOyAb9%2FV34Dw5k779IBAAA%3D&RelayState=0043bfc1bc45110dae17004005b13a2b")
  ]
