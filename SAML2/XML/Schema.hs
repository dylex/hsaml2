module SAML2.XML.Schema
  ( ns
  , module SAML2.XML.Schema.Datatypes
  ) where

import SAML2.XML.Types
import SAML2.XML.Schema.Datatypes

ns :: Namespace 
ns = Namespace "xs" "http://www.w3.org/2001/XMLSchema"
