module SAML2.XML.LibXML2
  ( Doc
  , fromXmlTrees
  , C14NMode(..)
  , c14n
  ) where

import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Unsafe as BSU
import Data.Maybe (fromMaybe)
import Data.String.Unicode (unicodeCharToUtf8')
import Data.Word (Word8)
import Foreign.C.Error (throwErrnoIf, throwErrnoIfNull)
import Foreign.C.String (CString, withCString)
import Foreign.C.Types (CInt(..))
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Marshal (alloca, withArray0, withMany, maybeWith)
import Foreign.Ptr (Ptr, FunPtr, nullPtr, castPtr)
import Foreign.Storable (peek)
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.DOM.ShowXml as HXTS

#include <libxml/parser.h>
#include <libxml/c14n.h>

type XMLChar = #type xmlChar
data XMLDoc
data XMLNodeSet

foreign import ccall unsafe "libxml/parser.h xmlReadMemory"
  xmlReadMemory :: CString -> CInt -> CString -> CString -> CInt -> IO (Ptr XMLDoc)

foreign import ccall unsafe "libxml/tree.h &xmlFreeDoc"
  xmlFreeDoc :: FunPtr ((Ptr XMLDoc) -> IO ())

foreign import ccall unsafe "libxml/c14n.h xmlC14NDocDumpMemory"
  xmlC14NDocDumpMemory :: Ptr XMLDoc -> Ptr XMLNodeSet -> CInt -> Ptr (Ptr XMLChar) -> CInt -> Ptr (Ptr XMLChar) -> IO CInt

foreign import ccall unsafe "xmlFree_stub"
  xmlFree :: Ptr a -> IO ()

newtype Doc = Doc{ unDoc :: ForeignPtr XMLDoc }

newDoc :: Ptr XMLDoc -> IO Doc
newDoc = fmap Doc . newForeignPtr xmlFreeDoc

fromBytes :: BS.ByteString -> IO Doc
fromBytes s = do
  d <- BSU.unsafeUseAsCStringLen s $ \(p, l) ->
    throwErrnoIfNull "xmlReadMemory" $
      xmlReadMemory p (fromIntegral l) nullPtr nullPtr (#{const XML_PARSE_NOENT} .|. #{const XML_PARSE_DTDLOAD} .|. #{const XML_PARSE_DTDATTR} .|. #{const XML_PARSE_NONET} .|. #{const XML_PARSE_COMPACT})
  newDoc d

fromXmlTrees :: HXT.XmlTrees -> IO Doc
fromXmlTrees = fromBytes . BSL.toStrict . HXTS.xshow' cq aq unicodeCharToUtf8'
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

data C14NMode
  = C14N_1_0
  | C14N_EXCLUSIVE_1_0
  | C14N_1_1

c14nmode :: C14NMode -> CInt
c14nmode C14N_1_0           = #{const XML_C14N_1_0}
c14nmode C14N_EXCLUSIVE_1_0 = #{const XML_C14N_EXCLUSIVE_1_0}
c14nmode C14N_1_1           = #{const XML_C14N_1_1}

c14n :: C14NMode -> Maybe [String] -> Bool -> Doc -> IO BS.ByteString
c14n m i c d =
  withForeignPtr (unDoc d) $ \dp ->
  withMany withCString (fromMaybe [] i) $ \il ->
  maybeWith (withArray0 nullPtr) (il <$ i) $ \ip ->
  alloca $ \p -> do
    r <- throwErrnoIf (< 0) "xmlC14NDocDumpMemory" $
      xmlC14NDocDumpMemory dp nullPtr (c14nmode m) ((castPtr :: Ptr CString -> Ptr (Ptr Word8)) ip) (fromIntegral $ fromEnum c) p
    pp <- peek p
    BSU.unsafePackCStringFinalizer pp (fromIntegral r) (xmlFree pp)
