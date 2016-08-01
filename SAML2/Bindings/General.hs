-- |
-- General Considerations
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf saml-bindings-2.0-os> §3.1
module SAML2.Bindings.General where

import Data.ByteString (ByteString)
import Data.String (IsString(fromString))

type RelayState = ByteString

-- |The name of the parameter used by many protocols for the message itself for requests (False) or responses (True).  Often combined with 'SAML2.Core.Protocols.isSAMLResponse'.
protocolParameter :: IsString a => Bool -> a
protocolParameter False = fromString "SAMLRequest"
protocolParameter True = fromString "SAMLResponse"

relayStateParameter :: IsString a => a
relayStateParameter = fromString "RelayState"
