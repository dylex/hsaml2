-- |
-- General Considerations
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf saml-bindings-2.0-os> §3.1
module SAML2.Bindings.General where

import Data.ByteString (ByteString)

type RelayState = ByteString
