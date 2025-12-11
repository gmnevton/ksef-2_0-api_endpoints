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

  PKCS1_PADDING = $00000002;

  // Provider name for AES-capable CryptoAPI provider
  MS_ENH_RSA_AES_PROV = 'Microsoft Enhanced RSA and AES Cryptographic Provider';

  // Standard BLOB header version
  CUR_BLOB_VERSION = $02;

// Key parameter for setting IV on symmetric keys
  KP_IV               = 1; // Initialization vector
  KP_SALT             = 2; // Salt value
  KP_PADDING          = 3; // Padding values
  KP_MODE             = 4; // Mode of the cipher
  KP_MODE_BITS        = 5; // Number of bits to feedback
  KP_PERMISSIONS      = 6; // Key permissions DWORD
  KP_ALGID            = 7; // Key algorithm
  KP_BLOCKLEN         = 8; // Block size of the cipher
  KP_KEYLEN           = 9; // Length of key in bits
  KP_SALT_EX          = 10; // Length of salt in bytes
  KP_P                = 11; // DSS/Diffie-Hellman P value
  KP_G                = 12; // DSS/Diffie-Hellman G value
  KP_Q                = 13; // DSS Q value
  KP_X                = 14; // Diffie-Hellman X value
  KP_Y                = 15; // Y value
  KP_RA               = 16; // Fortezza RA value
  KP_RB               = 17; // Fortezza RB value
  KP_INFO             = 18; // for putting information into an RSA envelope
  KP_EFFECTIVE_KEYLEN = 19; // setting and getting RC2 effective key length
  KP_SCHANNEL_ALG     = 20; // for setting the Secure Channel algorithms
  KP_CLIENT_RANDOM    = 21; // for setting the Secure Channel client random data
  KP_SERVER_RANDOM    = 22; // for setting the Secure Channel server random data
  KP_RP               = 23;
  KP_PRECOMP_MD5      = 24;
  KP_PRECOMP_SHA      = 25;
  KP_CERTIFICATE      = 26; // for setting Secure Channel certificate data (PCT1)
  KP_CLEAR_KEY        = 27; // for setting Secure Channel clear key data (PCT1)
  KP_PUB_EX_LEN       = 28;
  KP_PUB_EX_VAL       = 29;
  KP_KEYVAL           = 30;
  KP_ADMIN_PIN        = 31;
  KP_KEYEXCHANGE_PIN  = 32;
  KP_SIGNATURE_PIN    = 33;
  KP_PREHASH          = 34;

  KP_OAEP_PARAMS     = 36; // for setting OAEP params on RSA keys
  KP_CMS_KEY_INFO    = 37;
  KP_CMS_DH_KEY_INFO = 38;
  KP_PUB_PARAMS      = 39; // for setting public parameters
  KP_VERIFY_PARAMS   = 40; // for verifying DSA and DH parameters
  KP_HIGHEST_VERSION = 41; // for TLS protocol version setting


// KP_PADDING
  PKCS5_PADDING  = 1; // PKCS 5 (sec 6.2) padding method
  RANDOM_PADDING = 2;
  ZERO_PADDING   = 3;


// KP_MODE
  CRYPT_MODE_CBC = 1; // Cipher block chaining
  CRYPT_MODE_ECB = 2; // Electronic code book
  CRYPT_MODE_OFB = 3; // Output feedback mode
  CRYPT_MODE_CFB = 4; // Cipher feedback mode
  CRYPT_MODE_CTS = 5; // Ciphertext stealing mode


// KP_PERMISSIONS
  CRYPT_ENCRYPT    = $0001; // Allow encryption
  CRYPT_DECRYPT    = $0002; // Allow decryption
  CRYPT_EXPORT     = $0004; // Allow key to be exported
  CRYPT_READ       = $0008; // Allow parameters to be read
  CRYPT_WRITE      = $0010; // Allow parameters to be set
  CRYPT_MAC        = $0020; // Allow MACs to be used with key
  CRYPT_EXPORT_KEY = $0040; // Allow key to be used for exporting keys
  CRYPT_IMPORT_KEY = $0080; // Allow key to be used for importing keys

  HP_ALGID         = $0001; // Hash algorithm
  HP_HASHVAL       = $0002; // Hash value
  HP_HASHSIZE      = $0004; // Hash value size
  HP_HMAC_INFO     = $0005; // information for creating an HMAC
  HP_TLS1PRF_LABEL = $0006; // label for TLS1 PRF
  HP_TLS1PRF_SEED  = $0007; // seed for TLS1 PRF

  CRYPT_FAILED  = FALSE;
  CRYPT_SUCCEED = TRUE;


// Algorithm classes
  ALG_CLASS_ANY          = 0;
  ALG_CLASS_SIGNATURE    = 1 shl 13;
  ALG_CLASS_MSG_ENCRYPT  = 2 shl 13;
  ALG_CLASS_DATA_ENCRYPT = 3 shl 13;
  ALG_CLASS_HASH         = 4 shl 13;
  ALG_CLASS_KEY_EXCHANGE = 5 shl 13;
  ALG_CLASS_ALL          = 7 shl 13;


// Algorithm types
  ALG_TYPE_ANY           = 0;
  ALG_TYPE_DSS           = 1 shl 9;
  ALG_TYPE_RSA           = 2 shl 9;
  ALG_TYPE_BLOCK         = 3 shl 9;
  ALG_TYPE_STREAM        = 4 shl 9;
  ALG_TYPE_DH            = 5 shl 9;
  ALG_TYPE_SECURECHANNEL = 6 shl 9;


// Generic sub-ids
  ALG_SID_ANY = 0;


// Some RSA sub-ids
  ALG_SID_RSA_ANY      = 0;
  ALG_SID_RSA_PKCS     = 1;
  ALG_SID_RSA_MSATWORK = 2;
  ALG_SID_RSA_ENTRUST  = 3;
  ALG_SID_RSA_PGP      = 4;


// Some DSS sub-ids
  ALG_SID_DSS_ANY  = 0;
  ALG_SID_DSS_PKCS = 1;
  ALG_SID_DSS_DMS  = 2;


// Block cipher sub ids
// DES sub_ids
  ALG_SID_DES        = 1;
  ALG_SID_3DES       = 3;
  ALG_SID_DESX       = 4;
  ALG_SID_IDEA       = 5;
  ALG_SID_CAST       = 6;
  ALG_SID_SAFERSK64  = 7;
  ALG_SID_SAFERSK128 = 8;
  ALG_SID_3DES_112   = 9;
  ALG_SID_CYLINK_MEK = 12;
  ALG_SID_RC5        = 13;
  ALG_SID_AES_128    = 14;
  ALG_SID_AES_192    = 15;
  ALG_SID_AES_256    = 16;
  ALG_SID_AES        = 17;


// Fortezza sub-ids
  ALG_SID_SKIPJACK = 10;
  ALG_SID_TEK      = 11;


// KP_MODE
  CRYPT_MODE_CBCI    = 6; // ANSI CBC Interleaved
  CRYPT_MODE_CFBP    = 7; // ANSI CFB Pipelined
  CRYPT_MODE_OFBP    = 8; // ANSI OFB Pipelined
  CRYPT_MODE_CBCOFM  = 9; // ANSI CBC + OF Masking
  CRYPT_MODE_CBCOFMI = 10; // ANSI CBC + OFM Interleaved


// RC2 sub-ids
  ALG_SID_RC2 = 2;


// Stream cipher sub-ids
  ALG_SID_RC4  = 1;
  ALG_SID_SEAL = 2;


// Diffie-Hellman sub-ids
  ALG_SID_DH_SANDF       = 1;
  ALG_SID_DH_EPHEM       = 2;
  ALG_SID_AGREED_KEY_ANY = 3;
  ALG_SID_KEA            = 4;

// Hash sub ids
  ALG_SID_MD2        = 1;
  ALG_SID_MD4        = 2;
  ALG_SID_MD5        = 3;
  ALG_SID_SHA        = 4;
  ALG_SID_SHA1       = 4;
  ALG_SID_MAC        = 5;
  ALG_SID_RIPEMD     = 6;
  ALG_SID_RIPEMD160  = 7;
  ALG_SID_SSL3SHAMD5 = 8;
  ALG_SID_HMAC       = 9;
  ALG_SID_TLS1PRF    = 10;
  ALG_SID_SHA_256    = 12;
  ALG_SID_SHA_384    = 13;
  ALG_SID_SHA_512    = 14;


// secure channel sub ids
  ALG_SID_SSL3_MASTER          = 1;
  ALG_SID_SCHANNEL_MASTER_HASH = 2;
  ALG_SID_SCHANNEL_MAC_KEY     = 3;
  ALG_SID_PCT1_MASTER          = 4;
  ALG_SID_SSL2_MASTER          = 5;
  ALG_SID_TLS1_MASTER          = 6;
  ALG_SID_SCHANNEL_ENC_KEY     = 7;


// algorithm identifier definitions
  CALG_MD5                  = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD5;
  CALG_SHA                  = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA;
  CALG_SHA1                 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA1;
  CALG_MAC                  = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MAC;
  CALG_RSA_SIGN             = ALG_CLASS_SIGNATURE or ALG_TYPE_RSA or ALG_SID_RSA_ANY;
  CALG_DSS_SIGN             = ALG_CLASS_SIGNATURE or ALG_TYPE_DSS or ALG_SID_DSS_ANY;
  CALG_RSA_KEYX             = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_RSA or ALG_SID_RSA_ANY;
  CALG_DES                  = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DES;
  CALG_3DES_112             = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES_112;
  CALG_3DES                 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES;
  CALG_DESX                 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DESX;
  CALG_RC2                  = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC2;
  CALG_RC4                  = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_RC4;
  CALG_SEAL                 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_SEAL;
  CALG_DH_SF                = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_SANDF;
  CALG_DH_EPHEM             = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_EPHEM;
  CALG_AGREEDKEY_ANY        = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_AGREED_KEY_ANY;
  CALG_KEA_KEYX             = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_KEA;
  CALG_HUGHES_MD5           = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_ANY or ALG_SID_MD5;
  CALG_SKIPJACK             = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_SKIPJACK;
  CALG_TEK                  = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_TEK;
  CALG_CYLINK_MEK           = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_CYLINK_MEK;
  CALG_SSL3_SHAMD5          = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SSL3SHAMD5;
  CALG_SSL3_MASTER          = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL3_MASTER;
  CALG_SCHANNEL_MASTER_HASH = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MASTER_HASH;
  CALG_SCHANNEL_MAC_KEY     = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MAC_KEY;
  CALG_SCHANNEL_ENC_KEY     = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_ENC_KEY;
  CALG_PCT1_MASTER          = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_PCT1_MASTER;
  CALG_SSL2_MASTER          = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL2_MASTER;
  CALG_TLS1_MASTER          = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_TLS1_MASTER;
  CALG_RC5                  = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC5;
  CALG_HMAC                 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HMAC;
  CALG_TLS1PRF              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_TLS1PRF;
  CALG_AES_128              = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_128;
  CALG_AES_192              = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_192;
  CALG_AES_256              = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_256;
  CALG_AES                  = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES;
  CALG_SHA_256              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_256;
  CALG_SHA_384              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_384;
  CALG_SHA_512              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_512;


// dwFlag definitions for CryptExportKey
  CRYPT_Y_ONLY        = $00000001;
  CRYPT_SSL2_FALLBACK = $00000002;
  CRYPT_DESTROYKEY    = $00000004;
  CRYPT_OAEP          = $00000040; // used with RSA encryptions/decryptions
                                   // CryptExportKey, CryptImportKey,
                                   // CryptEncrypt and CryptDecrypt


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

  ALG_ID = Cardinal;


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
function CryptCreateHash(hProv: HCRYPTPROV; Algid: ALG_ID; hKey: HCRYPTKEY; dwFlags: DWORD; var phHash: HCRYPTHASH): BOOL; stdcall; external advapi32 name 'CryptCreateHash';
function CryptHashData(hHash: HCRYPTHASH; pbData: LPBYTE; dwDataLen, dwFlags: DWORD): BOOL; stdcall; external advapi32 name 'CryptHashData';
function CryptDeriveKey(hProv: HCRYPTPROV; Algid: ALG_ID; hBaseData: HCRYPTHASH; dwFlags: DWORD; var phKey: HCRYPTKEY): BOOL; stdcall; external advapi32 name 'CryptDeriveKey';
function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall; external advapi32 name 'CryptDestroyHash';

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

