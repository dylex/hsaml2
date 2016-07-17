{-# LANGUAGE ViewPatterns #-}
import Distribution.Simple
import Distribution.Simple.Program (Program(programFindVersion), simpleProgram, findProgramVersion)
import Data.List (stripPrefix)

xmllintProgram :: Program
xmllintProgram = (simpleProgram "xmllint")
  { programFindVersion = findProgramVersion "--version" $ \s -> case lines s of
    -- XXX doesn't work since version is on stderr
    (stripPrefix "xmllint: using libxml version " -> Just v) : (stripPrefix "   compiled with: " -> Just o) : _ ->
      v ++ concatMap ('-':) (words o)
    _ -> "unknown"
  }

main = defaultMainWithHooks simpleUserHooks
  { hookedPrograms = xmllintProgram : hookedPrograms simpleUserHooks
  }
