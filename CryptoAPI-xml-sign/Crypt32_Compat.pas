//
// Minimal Crypt32 declarations for Delphi 10.3 (small wrapper)
//
unit Crypt32_Compat;

interface

uses
  SysUtils,
  Windows,
  NetEncoding;

const
  crypt32 = 'crypt32.dll';
  advapi32 = 'advapi32.dll';

  CRYPT_STRING_BASE64HEADER        = $00000000;
  CRYPT_STRING_BASE64              = $00000001;
  CRYPT_STRING_BINARY              = $00000002;
  CRYPT_STRING_BASE64REQUESTHEADER = $00000003;
  CRYPT_STRING_HEX                 = $00000004;
  CRYPT_STRING_HEXASCII            = $00000005;
  CRYPT_STRING_BASE64_ANY          = $00000006;
  CRYPT_STRING_ANY                 = $00000007;
  CRYPT_STRING_HEX_ANY             = $00000008;
  CRYPT_STRING_BASE64X509CRLHEADER = $00000009;
  CRYPT_STRING_HEXADDR             = $0000000A;
  CRYPT_STRING_HEXASCIIADDR        = $0000000B;

  CRYPT_STRING_NOCRLF              = $40000000;
  CRYPT_STRING_NOCR                = $80000000;


  X509_ASN_ENCODING = $00000001;
  PKCS_7_ASN_ENCODING = $00010000;


  CRYPT_ENCODE_DECODE_NONE       = 0;
  X509_CERT                      = LPCSTR(1);
  X509_CERT_TO_BE_SIGNED         = LPCSTR(2);
  X509_CERT_CRL_TO_BE_SIGNED     = LPCSTR(3);
  X509_CERT_REQUEST_TO_BE_SIGNED = LPCSTR(4);
  X509_EXTENSIONS                = LPCSTR(5);
  X509_NAME_VALUE                = LPCSTR(6);
  X509_NAME                      = LPCSTR(7);
  X509_PUBLIC_KEY_INFO           = LPCSTR(8);

//  Predefined X509 certificate extension data structures that can be encoded / decoded.

  X509_AUTHORITY_KEY_ID      = LPCSTR(9);
  X509_KEY_ATTRIBUTES        = LPCSTR(10);
  X509_KEY_USAGE_RESTRICTION = LPCSTR(11);
  X509_ALTERNATE_NAME        = LPCSTR(12);
  X509_BASIC_CONSTRAINTS     = LPCSTR(13);
  X509_KEY_USAGE             = LPCSTR(14);
  X509_BASIC_CONSTRAINTS2    = LPCSTR(15);
  X509_CERT_POLICIES         = LPCSTR(16);

//  Additional predefined data structures that can be encoded / decoded.

  PKCS_UTC_TIME         = LPCSTR(17);
  PKCS_TIME_REQUEST     = LPCSTR(18);
  RSA_CSP_PUBLICKEYBLOB = LPCSTR(19);
  X509_UNICODE_NAME     = LPCSTR(20);

  X509_KEYGEN_REQUEST_TO_BE_SIGNED  = LPCSTR(21);
  PKCS_ATTRIBUTE                    = LPCSTR(22);
  PKCS_CONTENT_INFO_SEQUENCE_OF_ANY = LPCSTR(23);

//  Predefined primitive data structures that can be encoded / decoded.

  X509_UNICODE_NAME_VALUE = LPCSTR(24);
  X509_ANY_STRING         = X509_NAME_VALUE;
  X509_UNICODE_ANY_STRING = X509_UNICODE_NAME_VALUE;
  X509_OCTET_STRING       = LPCSTR(25);
  X509_BITS               = LPCSTR(26);
  X509_INTEGER            = LPCSTR(27);
  X509_MULTI_BYTE_INTEGER = LPCSTR(28);
  X509_ENUMERATED         = LPCSTR(29);
  X509_CHOICE_OF_TIME     = LPCSTR(30);

//  More predefined X509 certificate extension data structures that can be encoded / decoded.

  X509_AUTHORITY_KEY_ID2     = LPCSTR(31);
  X509_AUTHORITY_INFO_ACCESS = LPCSTR(32);
  X509_CRL_REASON_CODE       = X509_ENUMERATED;
  PKCS_CONTENT_INFO          = LPCSTR(33);
  X509_SEQUENCE_OF_ANY       = LPCSTR(34);
  X509_CRL_DIST_POINTS       = LPCSTR(35);
  X509_ENHANCED_KEY_USAGE    = LPCSTR(36);
  PKCS_CTL                   = LPCSTR(37);

  X509_MULTI_BYTE_UINT    = LPCSTR(38);
  X509_DSS_PUBLICKEY      = X509_MULTI_BYTE_UINT;
  X509_DSS_PARAMETERS     = LPCSTR(39);
  X509_DSS_SIGNATURE      = LPCSTR(40);
  PKCS_RC2_CBC_PARAMETERS = LPCSTR(41);
  PKCS_SMIME_CAPABILITIES = LPCSTR(42);

//  data structures for private keys

  PKCS_RSA_PRIVATE_KEY            = LPCSTR(43);
  PKCS_PRIVATE_KEY_INFO           = LPCSTR(44);
  PKCS_ENCRYPTED_PRIVATE_KEY_INFO = LPCSTR(45);

//  certificate policy qualifier

  X509_PKIX_POLICY_QUALIFIER_USERNOTICE = LPCSTR(46);

// Property ID for attaching key handle

  CERT_KEY_CONTEXT_PROP_ID = 5;
  CERT_NCRYPT_KEY_SPEC = 0;

  CERT_X500_NAME_STR   = 3;

  CERT_NAME_STR_REVERSE_FLAG = $02000000;

  CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG = $00080000;

  PROV_RSA_FULL      = 1;
  PROV_RSA_AES = 24;

  CRYPT_VERIFYCONTEXT = $F0000000;
  CRYPT_ENCODE_ALLOC_FLAG = $8000;
  CRYPT_DECODE_ALLOC_FLAG = $8000;

  PLAINTEXTKEYBLOB = $8;
  PRIVATEKEYBLOB   = $7;
  PUBLICKEYBLOB    = $6;

  KP_PADDING = 3;

  PKCS1_PADDING = $00000002;

  // Provider name for AES-capable CryptoAPI provider
  MS_ENH_RSA_AES_PROV = 'Microsoft Enhanced RSA and AES Cryptographic Provider';

  // Standard BLOB header version
  CUR_BLOB_VERSION = $02;

  // AES algorithm IDs (CryptoAPI CALG_*)
  CALG_AES_128 = $0000660E;
  CALG_AES_192 = $0000660F;
  CALG_AES_256 = $00006610;

  // Key parameter for setting IV on symmetric keys
  KP_IV = 1;

// Minimal CERT_CONTEXT structure
// Only fields needed by XAdESSigner

{ Basic CERT_CONTEXT and aliases }

type
// Forward declaration
  CRYPTOAPI_BLOB = record
    cbData: DWORD;
    pbData: PBYTE;
  end;

  CRYPT_OBJID_BLOB = CRYPTOAPI_BLOB;

  PCRYPT_ALGORITHM_IDENTIFIER = ^CRYPT_ALGORITHM_IDENTIFIER;
  CRYPT_ALGORITHM_IDENTIFIER = record
    pszObjId: LPSTR;
    Parameters: CRYPT_OBJID_BLOB;
  end;

  CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_INTEGER_BLOB = ^CRYPT_INTEGER_BLOB;

  CERT_NAME_BLOB = CRYPTOAPI_BLOB;
  PCERT_NAME_BLOB = ^CERT_NAME_BLOB;

  PFN_CRYPT_ALLOC = function(cbSize: size_t): LPVOID; stdcall;
  PFN_CRYPT_FREE = procedure(pv: LPVOID); stdcall;

  PCRYPT_DECODE_PARA = ^CRYPT_DECODE_PARA;
  CRYPT_DECODE_PARA = record
    cbSize: DWORD;
    pfnAlloc: PFN_CRYPT_ALLOC; // OPTIONAL
    pfnFree: PFN_CRYPT_FREE;   // OPTIONAL
  end;

  PCRYPT_BIT_BLOB = ^CRYPT_BIT_BLOB;
  CRYPT_BIT_BLOB = record
    cbData: DWORD;
    pbData: LPBYTE;
    cUnusedBits: DWORD;
  end;

  PCERT_PUBLIC_KEY_INFO = ^CERT_PUBLIC_KEY_INFO;
  CERT_PUBLIC_KEY_INFO = record
    Algorithm: CRYPT_ALGORITHM_IDENTIFIER;
    PublicKey: CRYPT_BIT_BLOB;
  end;

  PCERT_EXTENSION = ^CERT_EXTENSION;
  CERT_EXTENSION = record
    pszObjId: LPSTR;
    fCritical: BOOL;
    Value: CRYPT_OBJID_BLOB;
  end;

  PCERT_INFO = ^CERT_INFO;
  CERT_INFO = record
    dwVersion: DWORD;
    SerialNumber: CRYPT_INTEGER_BLOB;
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    Issuer: CERT_NAME_BLOB;
    NotBefore: FILETIME;
    NotAfter: FILETIME;
    Subject: CERT_NAME_BLOB;
    SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO;
    IssuerUniqueId: CRYPT_BIT_BLOB;
    SubjectUniqueId: CRYPT_BIT_BLOB;
    cExtension: DWORD;
    rgExtension: PCERT_EXTENSION;
  end;

  PCERT_CONTEXT = ^CERT_CONTEXT;
  PCCERT_CONTEXT = PCERT_CONTEXT; // common alias expected by many APIs
  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: PCERT_INFO; // previously Pointer, now full record
    hCertStore: Pointer;
  end;

// Key-context structure

  PCERT_KEY_CONTEXT = ^CERT_KEY_CONTEXT;
  CERT_KEY_CONTEXT = record
    cbSize: DWORD;
    dwKeySpec: DWORD;
    hNCryptKey: ULONG_PTR;
  end;

  HCRYPTPROV = ULONG_PTR;
  HCRYPTKEY  = ULONG_PTR;
  HCRYPTHASH = ULONG_PTR;

  // Minimal PUBLIC/PRIVATEKEYBLOB header
  BLOBHEADER = packed record
    bType: Byte;
    bVersion: Byte;
    reserved: Word;
    aiKeyAlg: LongWord;
  end;
  PBLOBHEADER = ^BLOBHEADER;

  RSAPUBKEY = record
    magic: DWORD; // Has to be RSA1
    bitlen: DWORD; // # of bits in modulus
    pubexp: DWORD; // public exponent
    //modulus: DWORD;
  end;
  PRSAPUBKEY = ^RSAPUBKEY;


// Functions from crypt32.dll
function CryptStringToBinaryA(pszString: LPCSTR; cchString: DWORD; dwFlags: DWORD; ppBinary: PBYTE; var ppcbBinary: DWORD; ppdwSkip: PDWORD): BOOL; stdcall; external crypt32 name 'CryptStringToBinaryA';
function CryptBinaryToStringA(const pBinary: PBYTE; cbBinary: DWORD; dwFlags: DWORD; pszString: LPSTR; var pchString: DWORD): BOOL; stdcall; external crypt32 name 'CryptBinaryToStringA';


function CryptMemAlloc(cbSize: ULONG): LPVOID; stdcall; external crypt32 name 'CryptMemAlloc';
function CryptMemRealloc(pv: LPVOID; cbSize: ULONG): LPVOID; stdcall; external crypt32 name 'CryptMemRealloc';
procedure CryptMemFree(pv: LPVOID); stdcall; external crypt32 name 'CryptMemFree';


function CertCreateCertificateContext(dwCertEncodingType: DWORD; pbCertEncoded: Pointer; cbCertEncoded: DWORD): PCERT_CONTEXT; stdcall; external crypt32 name 'CertCreateCertificateContext';
function CertFreeCertificateContext(pCertContext: PCERT_CONTEXT): BOOL; stdcall; external crypt32 name 'CertFreeCertificateContext';
function CertSetCertificateContextProperty(pCertContext: PCERT_CONTEXT; dwPropId: DWORD; dwFlags: DWORD; pvData: Pointer): BOOL; stdcall; external crypt32 name 'CertSetCertificateContextProperty';
function CertNameToStr(dwCertEncodingType: DWORD; pName: PCERT_NAME_BLOB; dwStrType: DWORD; psz: LPTSTR; csz: DWORD): DWORD; stdcall; external crypt32 name 'CertNameToStrA';
function CryptImportPublicKeyInfo(hCryptProv: HCRYPTPROV; dwCertEncodingType: DWORD; pInfo: PCERT_PUBLIC_KEY_INFO; var phKey: HCRYPTKEY): BOOL; stdcall; external crypt32 name 'CryptImportPublicKeyInfo';
function CryptDecodeObjectEx(dwCertEncodingType: DWORD; lpszStructType: LPCSTR; pbEncoded: Pointer; cbEncoded, dwFlags: DWORD; pDecodePara: PCRYPT_DECODE_PARA; pvStructInfo: Pointer; var pcbStructInfo: DWORD): BOOL; stdcall; external crypt32 name 'CryptDecodeObjectEx';


function CryptAcquireContext(out phProv: HCRYPTPROV; pszContainer: LPCWSTR; pszProvider: LPCWSTR; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall; external advapi32 name 'CryptAcquireContextW';
function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall; external advapi32 name 'CryptReleaseContext';
function CryptImportKey(hProv: HCRYPTPROV; pbData: PBYTE; dwDataLen: DWORD; hPubKey: HCRYPTKEY; dwFlags: DWORD; out phKey: HCRYPTKEY): BOOL; stdcall; external advapi32 name 'CryptImportKey';
function CryptSetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pbData: PBYTE; dwFlags: DWORD): BOOL; stdcall; external advapi32 name 'CryptSetKeyParam';
function CryptEncrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL; dwFlags: DWORD; pbData: LPBYTE; var pdwDataLen: DWORD; dwBufLen: DWORD): BOOL; stdcall; external advapi32 name 'CryptEncrypt';
function CryptDecrypt(hKey: HCRYPTKEY; hHash: ULONG_PTR; Final: BOOL; dwFlags: DWORD; pbData: PBYTE; var pdwDataLen: DWORD): BOOL; stdcall; external advapi32 name 'CryptDecrypt';
function CryptDestroyKey(hKey: HCRYPTKEY): BOOL; stdcall; external advapi32 name 'CryptDestroyKey';

procedure RaiseError(const AMessage: String; const AError: DWORD);
function BytesToBase64(const B: TBytes; const Wrap: Boolean = True): String;
function BlobToBytes(const Blob: CRYPT_INTEGER_BLOB): TBytes;
procedure ReverseBytes(var B: TBytes);
function BytesToHex(const B: TBytes): String;
function BytesToDecimal(const B: TBytes): String;
procedure MoveBytes(const SrcBytes: TBytes; var DestBytes: TBytes; var Offset: Integer); inline; overload;
procedure MoveBytes(const SrcBytes: TBytes; var DestBytes: TBytes); inline; overload;

implementation

uses
  BigInt;

procedure RaiseError(const AMessage: String; const AError: DWORD);
var
  E: Exception;
begin
  E := Exception.CreateFmt(AMessage + #13#10'0x%.8x - %s', [AError, SysErrorMessage(AError)]);
  raise E at ReturnAddress;
end;

function BytesToBase64(const B: TBytes; const Wrap: Boolean = True): String;
var
  base64: TBase64Encoding;
begin
  if Wrap then
    Result := TNetEncoding.Base64.EncodeBytesToString(B)
  else begin
    base64 := TBase64Encoding.Create(0);
    try
      Result := base64.EncodeBytesToString(B);
    finally
      base64.Free;
    end;
  end;
end;

function BlobToBytes(const Blob: CRYPT_INTEGER_BLOB): TBytes;
begin
  SetLength(Result, Blob.cbData);
  if Blob.cbData > 0 then
    Move(Blob.pbData^, Result[0], Blob.cbData);
end;

procedure ReverseBytes(var B: TBytes);
var
  i, j: Integer;
  tmp: Byte;
begin
  i := 0;
  j := Length(B)-1;
  while i < j do begin
    tmp := B[i];
    B[i] := B[j];
    B[j] := tmp;
    Inc(i);
    Dec(j);
  end;
end;

function BytesToHex(const B: TBytes): String;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to High(B) do
    Result := Result + IntToHex(B[i], 2);
end;

//function SerialToDecimal(const Serial: CRYPT_INTEGER_BLOB): string;
function BytesToDecimal(const B: TBytes): String;
var
  bi: TBigInt; // use System.Numerics.BigInteger (Delphi 12+) or your own TBigInt
//  i: Integer;
  bytes: TBytes;
begin
  // Convert little-endian Windows serial to big-endian bytes
//  SetLength(bytes, Serial.cbData);
//  for i := 0 to Serial.cbData - 1 do
//    bytes[i] := Serial.pbData[Serial.cbData - 1 - i];

  // Big integer from big-endian
  bytes := B;
//  ReverseBytes(bytes);
  bi := TBigInt.Create(bytes);
  try
    Result := bi.ToString; // decimal string
  finally
    bi.Free;
  end;
end;

procedure MoveBytes(const SrcBytes: TBytes; var DestBytes: TBytes; var Offset: Integer);
var
  len: Integer;
begin
  len := Length(SrcBytes);
  Move(SrcBytes[0], DestBytes[offset], len);
  Inc(Offset, len);
end;

procedure MoveBytes(const SrcBytes: TBytes; var DestBytes: TBytes);
var
  len: Integer;
begin
  len := Length(SrcBytes);
  SetLength(DestBytes, len);
  if len > 0 then
    Move(SrcBytes[0], DestBytes[0], len);
end;

end.

