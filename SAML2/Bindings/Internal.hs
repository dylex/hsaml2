module SAML2.Bindings.Internal where

import Control.Applicative ((<|>))
import Data.Proxy (Proxy)
import Data.String (IsString)

import qualified SAML2.Core.Protocols as SAMLP
import SAML2.Bindings.General

lookupProtocolParameter :: (SAMLP.SAMLProtocol m, IsString p) => Proxy m -> (p -> Maybe a) -> Maybe a
lookupProtocolParameter p f =
  case SAMLP.isSAMLResponse_ p of
    Just r -> f (protocolParameter r)
    Nothing -> f (protocolParameter False) <|> f (protocolParameter True)

