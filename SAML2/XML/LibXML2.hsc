module SAML2.XML.LibXML2
  ( Doc
  , fromXmlTrees
  , C14NMode(..)
  , c14n
  ) where

import Control.Exception (bracket, throwIO, Exception)
import Control.Monad ((<=<))
import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Unsafe as BSU
import Data.Maybe (fromMaybe, isJust)
import Data.String.Unicode (unicodeCharToUtf8')
import Data.Word (Word8)
import Foreign.C.Error (throwErrnoIf, throwErrnoIfNull, getErrno, resetErrno, eOK, eNOTTY, errnoToIOError)
import Foreign.C.String (CString, withCString)
import Foreign.C.Types (CInt(..))
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Marshal (alloca, withArray0, withMany, maybeWith)
import Foreign.Ptr (Ptr, FunPtr, nullPtr, castPtr)
import Foreign.Storable (peek, peekByteOff)
import System.IO.Silently (hCapture)
import System.IO (stdout, stderr)
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.DOM.ShowXml as HXTS

#include <libxml/parser.h>
#include <libxml/parser.h>
#include <libxml/c14n.h>

type XMLChar = #type xmlChar
data XMLDoc
data XMLXPathContext
data XMLXPathObject
data XMLNodeSet

foreign import ccall unsafe "libxml/parser.h xmlReadMemory"
  xmlReadMemory :: CString -> CInt -> CString -> CString -> CInt -> IO (Ptr XMLDoc)

foreign import ccall unsafe "libxml/tree.h &xmlFreeDoc"
  xmlFreeDoc :: FunPtr ((Ptr XMLDoc) -> IO ())

foreign import ccall unsafe "libxml/xpath.h xmlXPathNewContext"
  xmlXPathNewContext :: Ptr XMLDoc -> IO (Ptr XMLXPathContext)

foreign import ccall unsafe "libxml/xpath.h xmlXPathFreeContext"
  xmlXPathFreeContext :: Ptr XMLXPathContext -> IO ()

foreign import ccall unsafe "libxml/xpath.h xmlXPathEval"
  xmlXPathEval :: Ptr XMLChar -> Ptr XMLXPathContext -> IO (Ptr XMLXPathObject)

foreign import ccall unsafe "libxml/xpath.h xmlXPathFreeObject"
  xmlXPathFreeObject :: Ptr XMLXPathObject -> IO ()

foreign import ccall unsafe "libxml/c14n.h xmlC14NDocDumpMemory"
  xmlC14NDocDumpMemory :: Ptr XMLDoc -> Ptr XMLNodeSet -> CInt -> Ptr (Ptr XMLChar) -> CInt -> Ptr (Ptr XMLChar) -> IO CInt

foreign import ccall unsafe "xmlFree_stub"
  xmlFree :: Ptr a -> IO ()

newtype Doc = Doc{ unDoc :: ForeignPtr XMLDoc }

newDoc :: Ptr XMLDoc -> IO Doc
newDoc = fmap Doc . newForeignPtr xmlFreeDoc

data FromBytesError =
  FromBytesResult
    { fromBytesErr        :: Maybe IOError
    , fromBytesResultNull :: Bool
    , fromBytesNoise      :: String
    , fromBytesInput      :: BS.ByteString
    }
  deriving (Eq, Show)

instance Exception FromBytesError

-- | Call libxml2 parser and return the parsed C object, or throw an error.
fromBytes :: BS.ByteString -> IO Doc
fromBytes s = do
  resetErrno
  let config :: CInt
      config = #{const XML_PARSE_NOENT}   .|.
               #{const XML_PARSE_DTDLOAD} .|.
               #{const XML_PARSE_DTDATTR} .|.
               #{const XML_PARSE_NONET}   .|.
               #{const XML_PARSE_COMPACT}
  (noise, d) <- BSU.unsafeUseAsCStringLen s $ \(p, l) ->
    hCapture [stdout, stderr] $ xmlReadMemory p (fromIntegral l) nullPtr nullPtr config

  let canonicalizeBenignErrnos e =
        if e `elem` goodErrs
        then Nothing
        else Just $ errnoToIOError "fromBytes" e Nothing Nothing
      goodErrs =
        [ eOK
        , eNOTTY  -- libxml2 appears to do something one of the std handles that does not work
                  -- well with 'hCapture', but just ignoring this error here seems to do the
                  -- trick.
        ]
  err <- canonicalizeBenignErrnos <$> getErrno

  if d == nullPtr || isJust err || noise /= mempty
    then throwIO $ FromBytesResult
           { fromBytesErr        = err
           , fromBytesResultNull = d == nullPtr
           , fromBytesNoise      = noise
           , fromBytesInput      = s
           }
    else newDoc d

fromXmlTrees :: HXT.XmlTrees -> IO Doc
fromXmlTrees = fromBytes . BSL.toStrict . show_
  where
  show_ = HXTS.xshow' cq aq unicodeCharToUtf8'  -- TODO: why not just @show_ = HXTS.xshowBlob@?
  cq '&'   = ("&amp;"  ++)
  cq '<'   = ("&lt;"   ++)
  cq '>'   = ("&gt;"   ++)
  cq '\13' = ("&#xD;"  ++)
  cq c = (c:)
  aq '"'   = ("&quot;" ++)
  aq '\9'  = ("&#x9;"  ++)
  aq '\10' = ("&#xA;"  ++)
  aq c = cq c

withXMLXPathNodeList :: Ptr XMLDoc -> String -> (Ptr XMLNodeSet -> IO a) -> IO a
withXMLXPathNodeList d s f =
  bracket (xmlXPathNewContext d) xmlXPathFreeContext $ \c ->
  withCString s $ \p ->
  bracket
    (throwErrnoIfNull "xmlXPathEval" $ xmlXPathEval ((castPtr :: CString -> Ptr Word8) p) c)
    xmlXPathFreeObject
    $ f <=< #peek xmlXPathObject, nodesetval

data C14NMode
  = C14N_1_0
  | C14N_EXCLUSIVE_1_0
  | C14N_1_1

c14nmode :: C14NMode -> CInt
c14nmode C14N_1_0           = #{const XML_C14N_1_0}
c14nmode C14N_EXCLUSIVE_1_0 = #{const XML_C14N_EXCLUSIVE_1_0}
c14nmode C14N_1_1           = #{const XML_C14N_1_1}

c14n :: C14NMode -> Maybe [String] -> Bool -> Maybe String -> Doc -> IO BS.ByteString
c14n m i c s d =
  withForeignPtr (unDoc d) $ \dp ->
  withMany withCString (fromMaybe [] i) $ \il ->
  maybeWith (withArray0 nullPtr) (il <$ i) $ \ip ->
  maybeWith (withXMLXPathNodeList dp) s $ \sn ->
  alloca $ \p -> do
    r <- throwErrnoIf (< 0) "xmlC14NDocDumpMemory" $
      xmlC14NDocDumpMemory dp sn (c14nmode m) ((castPtr :: Ptr CString -> Ptr (Ptr Word8)) ip) (fromIntegral $ fromEnum c) p
    pp <- peek p
    BSU.unsafePackCStringFinalizer pp (fromIntegral r) (xmlFree pp)
