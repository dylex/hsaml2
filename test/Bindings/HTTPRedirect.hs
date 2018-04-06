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
  [ U.TestCase $ U.assertEqual "request"
    (RequestLogoutRequest $ LogoutRequest
      (RequestAbstractType $ ProtocolType
        "d2b7c388cec36fa7c39c28fd298644a8"
        SAML20
        (UTCTime (fromGregorian 2004 1 21) (19*60*60+49))
        Nothing
        (Identified ConsentUnspecified)
        (Just $ Issuer $ simpleNameID NameIDFormatEntity "https://IdentityProvider.com/SAML")
        Nothing
        []
        (Just $ BSC.pack "0043bfc1bc45110dae17004005b13a2b"))
      Nothing
      Nothing
      (NotEncrypted $ IdentifierName $ simpleNameID NameIDFormatPersistent "005a06e0-ad82-110d-a556-004005b13a2b")
      (Just "1"))
    =<< decodeURI mempty (uri "https://ServiceProvider.com/SAML/SLO/Browser?SAMLRequest=fVFdS8MwFH0f7D%2BUvGdNsq62oSsIQyhMESc%2B%2BJYlmRbWpObeyvz3puv2IMjyFM7HPedyK1DdsZdb%2F%2BEHfLFfgwVMTt3RgTwzazIEJ72CFqRTnQWJWu7uH7dSLJjsg0ev%2FZFMlttiBWADtt6R%2BSyJr9msiRH7O70sCm31Mj%2Bo%2BC%2B1KA5GlEWeZaogSQMw2MYBKodrIhjLKONU8FdeSsZkVr6T5M0GiHMjvWCknqZXZ2OoPxF7kGnaGOuwxZ%2Fn4L9bY8NC%2By4du1XpRXnxPcXizSZ58KFTeHujEWkNPZylsh9bAMYYUjO2Uiy3jCpTCMo5M1StVjmN9SO150sl9lU6RV2Dp0vsLIy7NM7YU82r9B90PrvCf85W%2FwL8zSVQzAEAAA%3D%3D&RelayState=0043bfc1bc45110dae17004005b13a2b")
  , U.TestCase $ U.assertEqual "response"
    (LogoutResponse $ StatusResponseType
      (ProtocolType
        "b0730d21b628110d8b7e004005b13a2b"
        SAML20
        (UTCTime (fromGregorian 2004 1 21) (19*60*60+49))
        Nothing
        (Identified ConsentUnspecified)
        (Just $ Issuer $ simpleNameID NameIDFormatEntity "https://ServiceProvider.com/SAML")
        Nothing
        []
        (Just $ BSC.pack "0043bfc1bc45110dae17004005b13a2b"))
      (Just "d2b7c388cec36fa7c39c28fd298644a8")
      successStatus)
    =<< decodeURI mempty (uri "https://IdentityProvider.com/SAML/SLO/Response?SAMLResponse=fVFNa4QwEL0X%2Bh8k912TaDUGFUp7EbZQ6rKH3mKcbQVNJBOX%2FvxaXQ9tYec0vHlv3nzkqIZ%2BlAf7YSf%2FBjhagxB8Db1BuZQKMjkjrcIOpVEDoPRa1o8vB8n3VI7OeqttT1bJbbJCBOc7a8j9XTBH9VyQhqYRbTlrEi4Yo61oUqA0pvShYZHiDQkqs411tAVpeZPqSAgNOkrOas4zzcW55ZlI4liJrTXiBJVBr4wvCJ877ijbcXZkmaRUxtk7CU7gcB5mLu8pKVddvghd%2Ben9iDIMa3CXTsOrs5euBbfXdgh%2F9snDK%2FEqW69Ye%2BUnvGL%2F8CfbQnBS%2FQS3z4QLW9aT1oBIws0j%2FGOyAb9%2FV34Dw5k779IBAAA%3D&RelayState=0043bfc1bc45110dae17004005b13a2b")
  ]
