module Main (main) where

import System.Exit (exitSuccess, exitFailure)
import qualified Test.HUnit as U

import qualified XML.Canonical
import qualified XML.Signature
import qualified XML.Encryption
import qualified Bindings.HTTPRedirect

tests :: U.Test
tests = U.test
  [ U.TestLabel "XML.Canonical" XML.Canonical.tests
  , U.TestLabel "XML.Signature" XML.Signature.tests
  , U.TestLabel "XML.Encryption" XML.Encryption.tests
  , U.TestLabel "Bindings.HTTPRedirect" Bindings.HTTPRedirect.tests
  ]

main :: IO ()
main = do
  r <- U.runTestTT tests
  if U.errors r == 0 && U.failures r == 0
    then exitSuccess
    else exitFailure
