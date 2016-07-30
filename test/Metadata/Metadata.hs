{-# LANGUAGE OverloadedStrings #-}
module Metadata.Metadata (tests) where

import Data.List.NonEmpty (NonEmpty(..))
import qualified Test.HUnit as U
import qualified Text.XML.HXT.DOM.XmlNode as HXT

import SAML2.XML
import qualified SAML2.XML.Signature as DS
import qualified SAML2.XML.Encryption as XEnc
import SAML2.Core.Identifiers
import qualified SAML2.Core.Assertions as SAML
import qualified SAML2.Core.Protocols as SAMLP
import SAML2.Metadata.Metadata

import XML

tests :: U.Test
tests = U.test
  [ testXML "test/Metadata/metadata-idp.xml" $
    EntityDescriptor
      (uri "https://IdentityProvider.com/SAML")
      Nothing
      Nothing
      (Just 31729999.8)
      []
      Nothing
      (Extensions [])
      (Descriptors $
        IDPSSODescriptor
          (RoleDescriptor
            Nothing
            Nothing
            Nothing
            [uri $ namespaceURI SAMLP.ns]
            Nothing
            []
            Nothing
            (Extensions [])
            [KeyDescriptor
              KeyTypeSigning
              (DS.KeyInfo
                Nothing
                (DS.KeyName "IdentityProvider.com SSO Key"
                :| []))
              []]
            Nothing
            [])
          (SSODescriptor
            [IndexedEndpoint
              (Endpoint
                (uri "urn:oasis:names:tc:SAML:2.0:bindings:SOAP")
                (uri "https://IdentityProvider.com/SAML/Artifact")
                Nothing
                []
                [])
              0
              True]
            [Endpoint
              (uri "urn:oasis:names:tc:SAML:2.0:bindings:SOAP")
              (uri "https://IdentityProvider.com/SAML/SLO/SOAP")
              Nothing
              []
              []
            ,Endpoint
              (uri "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
              (uri "https://IdentityProvider.com/SAML/SLO/Browser")
              (Just $ uri "https://IdentityProvider.com/SAML/SLO/Response")
              []
              []]
            []
            [Identified NameIDFormatX509
            ,Identified NameIDFormatPersistent
            ,Identified NameIDFormatTransient])
          True
          (Endpoint
            (uri "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
            (uri "https://IdentityProvider.com/SAML/SSO/Browser")
            Nothing
            []
            []
          :| [Endpoint
            (uri "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
            (uri "https://IdentityProvider.com/SAML/SSO/Browser")
            Nothing
            []
            []])
          []
          []
          []
          [ SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonPrincipalName")
            []
            []
          , SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonAffiliation")
            []
            [ [HXT.mkText "member"]
            , [HXT.mkText "student"]
            , [HXT.mkText "faculty"]
            , [HXT.mkText "employee"]
            , [HXT.mkText "staff"]
            ]]
        :| AttributeAuthorityDescriptor
          (RoleDescriptor
            Nothing
            Nothing
            Nothing
            [uri $ namespaceURI SAMLP.ns]
            Nothing
            []
            Nothing
            (Extensions [])
            [KeyDescriptor
              KeyTypeSigning
              (DS.KeyInfo
                Nothing
                (DS.KeyName "IdentityProvider.com AA Key"
                :| []))
              []]
            Nothing
            [])
          (Endpoint
            (uri "urn:oasis:names:tc:SAML:2.0:bindings:SOAP")
            (uri "https://IdentityProvider.com/SAML/AA/SOAP")
            Nothing
            []
            []
          :| [])
          [Endpoint
            (uri "urn:oasis:names:tc:SAML:2.0:bindings:URI")
            (uri "https://IdentityProvider.com/SAML/AA/URI")
            Nothing
            []
            []]
          [Identified NameIDFormatX509
          ,Identified NameIDFormatPersistent
          ,Identified NameIDFormatTransient]
          []
          [ SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonPrincipalName")
            []
            []
          , SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonAffiliation")
            []
            [ [HXT.mkText "member"]
            , [HXT.mkText "student"]
            , [HXT.mkText "faculty"]
            , [HXT.mkText "employee"]
            , [HXT.mkText "staff"]
            ]]
        : [])
      (Just $ Organization
        []
        (Extensions [])
        (Localized "en" "Identity Providers R US" :| [])
        (Localized "en" "Identity Providers R US, a Division of Lerxst Corp." :| [])
        (Localized "en" (uri "https://IdentityProvider.com") :| []))
      []
      []

  , testXML "test/Metadata/metadata-sp.xml" $
    EntityDescriptor
      (uri "https://ServiceProvider.com/SAML")
      Nothing
      Nothing
      Nothing
      []
      Nothing
      (Extensions [])
      (Descriptors $
        SPSSODescriptor
          (RoleDescriptor
            Nothing
            Nothing
            Nothing
            [uri $ namespaceURI SAMLP.ns]
            Nothing
            []
            Nothing
            (Extensions [])
            [ KeyDescriptor
              KeyTypeSigning
              (DS.KeyInfo
                Nothing
                (DS.KeyName "ServiceProvider.com SSO Key"
                :| []))
              []
            , KeyDescriptor
              KeyTypeEncryption
              (DS.KeyInfo
                Nothing
                (DS.KeyName "ServiceProvider.com Encrypt Key"
                :| []))
              [XEnc.EncryptionMethod
                (Identified XEnc.KeyTransportRSA1_5)
                Nothing
                Nothing
                Nothing
                []]
            ]
            Nothing
            [])
          (SSODescriptor
            []
            [Endpoint
              (uri "urn:oasis:names:tc:SAML:2.0:bindings:SOAP")
              (uri "https://ServiceProvider.com/SAML/SLO/SOAP")
              Nothing
              []
              []
            ,Endpoint
              (uri "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
              (uri "https://ServiceProvider.com/SAML/SLO/Browser")
              (Just $ uri "https://ServiceProvider.com/SAML/SLO/Response")
              []
              []]
            []
            [Identified NameIDFormatTransient])
          True
          False
          (IndexedEndpoint
            (Endpoint
              (uri "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact")
              (uri "https://ServiceProvider.com/SAML/SSO/Artifact")
              Nothing
              []
              [])
            0
            True
          :| IndexedEndpoint
            (Endpoint
              (uri "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
              (uri "https://ServiceProvider.com/SAML/SSO/POST")
              Nothing
              []
              [])
            1
            False
          : [])
          [ AttributeConsumingService
            0
            False
            (Localized "en" "Academic Journals R US" :| [])
            []
            (RequestedAttribute
              (SAML.Attribute
              "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
              (Identified AttributeNameFormatURI)
              (Just "eduPersonEntitlement")
              []
              [ [HXT.mkText "https://ServiceProvider.com/entitlements/123456789"]
              ])
              False
            :| [])
          ]
        :| [])
      (Just $ Organization
        []
        (Extensions [])
        (Localized "en" "Academic Journals R US" :| [])
        (Localized "en" "Academic Journals R US, a Division of Dirk Corp." :| [])
        (Localized "en" (uri "https://ServiceProvider.com") :| []))
      []
      []
  ]
