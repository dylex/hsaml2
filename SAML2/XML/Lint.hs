-- |
-- Command-line interface to libxml through xmllint
--
-- Too lazy to provide real bindings or reimplement functionality yet.
-- XXX Assumes consistent encoding througout (really UTF-8).
module SAML2.XML.Lint where

import System.Exit (ExitCode(..))
import System.Process (readProcessWithExitCode)
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.DOM.ShowXml as HXTS

xmllintString :: [String] -> HXT.IOStateArrow s String String
xmllintString args =
  ret HXT.$< HXT.arrIO (readProcessWithExitCode "xmllint" (args ++ ["-"]))
  where
  ret (r, o, e) = HXT.constA o HXT.>>> HXT.isA (not . null) HXT.>>> iss r e
  iss (ExitFailure e) "" = HXT.perform $ HXT.constA e HXT.>>> HXT.setErrStatus
  iss ExitSuccess "" = HXT.this
  iss (ExitFailure _) e = HXT.issueErr e
  iss ExitSuccess e = HXT.issueWarn e

xmllintToString :: [String] -> HXT.IOStateArrow s HXT.XmlTree String
xmllintToString args =
  HXT.getChildren
  HXT.>. HXTS.xshow'' cq aq
  HXT.>>> xmllintString args
  where
  cq '&'   = ("&amp;"  ++)
  cq '<'   = ("&lt;"   ++)
  cq '>'   = ("&gt;"   ++)
  cq '\13' = ("&#xD;"  ++)
  cq c = (c:)
  aq '"'   = ("&quot;" ++)
  aq '\9'  = ("&#x9;"  ++)
  aq '\10' = ("&#xA;"  ++)
  aq c = cq c

xmllint :: [String] -> HXT.IOStateArrow s HXT.XmlTree HXT.XmlTree
xmllint args =
  xmllintToString args HXT.>>> HXT.readFromString [HXT.withCanonicalize HXT.no]
