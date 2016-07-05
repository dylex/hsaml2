module SAML2.XML.Types where

import qualified Text.XML.HXT.DOM.TypeDefs as HXT

type Node = HXT.XmlTree
type Nodes = HXT.XmlTrees
type List1 a = [a] -- NonEmpty a

type IP = String
