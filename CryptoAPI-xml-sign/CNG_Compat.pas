//
// Minimal CNG declarations for Delphi 10.3 (small wrapper)
//
unit CNG_Compat;

interface

uses
  Windows,
  Crypt32_Compat;

const
  bcrypt = 'bcrypt.dll';

  BCRYPT_OBJECT_LENGTH = 'ObjectLength';
  BCRYPT_HASH_LENGTH   = 'HashDigestLength';

  // common algorithm identifiers
  BCRYPT_RSA_ALGORITHM: PWideChar = 'RSA';
  MS_PRIMITIVE_PROVIDER: PWideChar = 'Microsoft Primitive Provider';
  BCRYPT_SHA256_ALGORITHM: PWideChar = 'SHA256';

  BCRYPT_ECDSA_P256_ALGORITHM: PWideChar = 'ECDSA_P256';
  BCRYPT_ECDSA_P384_ALGORITHM: PWideChar = 'ECDSA_P384';
  BCRYPT_ECDSA_P521_ALGORITHM: PWideChar = 'ECDSA_P521';

  // blob types
  BCRYPT_PKCS8_PRIVATE_KEY_BLOB: PWideChar = 'PKCS8_PRIVATEKEY';

  BCRYPT_RSAPUBLIC_BLOB  = 'RSAPUBLICBLOB';
  BCRYPT_RSAPRIVATE_BLOB = 'RSAPRIVATEBLOB';

  BCRYPT_ECCPUBLIC_BLOB  = 'ECCPUBLICBLOB';
  BCRYPT_ECCPRIVATE_BLOB = 'ECCPRIVATEBLOB';

  // padding
  BCRYPT_PAD_PKCS1 = $00000002;

// Structures

type
  // Basic CNG handle types
  BCRYPT_HANDLE = type THandle;
  BCRYPT_ALG_HANDLE  = BCRYPT_HANDLE;
  BCRYPT_KEY_HANDLE  = BCRYPT_HANDLE;
  BCRYPT_HASH_HANDLE = BCRYPT_HANDLE;
  NTSTATUS = Longint;

  PBCRYPT_PKCS1_PADDING_INFO = ^BCRYPT_PKCS1_PADDING_INFO;
  BCRYPT_PKCS1_PADDING_INFO = record
    pszAlgId: PWideChar; // pointer to algorithm id e.g. BCRYPT_SHA256_ALGORITHM
  end;

  BCRYPT_RSAKEY_BLOB = record
    Magic: ULONG;
    BitLength: ULONG;
    cbPublicExp: ULONG;
    cbModulus: ULONG;
    cbPrime1: ULONG;
    cbPrime2: ULONG;
  end;
  PBCRYPT_RSAKEY_BLOB = ^BCRYPT_RSAKEY_BLOB;

  BCRYPT_ECCKEY_BLOB = record
    dwMagic: ULONG;
    cbKey: ULONG;
  end;
  PBCRYPT_ECCKEY_BLOB = ^BCRYPT_ECCKEY_BLOB;

  BCRYPT_OAEP_PADDING_INFO = record
    pszAlgId: LPCWSTR;
    pbLabel: PUCHAR;
    cbLabel: ULONG;
  end;
  PBCRYPT_OAEP_PADDING_INFO = ^BCRYPT_OAEP_PADDING_INFO;


const
  BCRYPT_RSAFULLPRIVATE_MAGIC = $32415352; // 'RSA2'
  BCRYPT_RSAPUBLIC_MAGIC = $31415352;  // RSA1
  BCRYPT_RSAPRIVATE_MAGIC = $32415352; // RSA2
  BCRYPT_SUCCESS = NTSTATUS($00000000);

  BCRYPT_ECDSA_PUBLIC_P256_MAGIC  = $31534345;  // ECS1
  BCRYPT_ECDSA_PRIVATE_P256_MAGIC = $32534345;  // ECS2
  BCRYPT_ECDSA_PUBLIC_P384_MAGIC  = $33534345;  // ECS3
  BCRYPT_ECDSA_PRIVATE_P384_MAGIC = $34534345;  // ECS4
  BCRYPT_ECDSA_PUBLIC_P521_MAGIC  = $35534345;  // ECS5
  BCRYPT_ECDSA_PRIVATE_P521_MAGIC = $36534345;  // ECS6

  BCRYPT_PAD_OAEP      = $00000004;


// Function declarations we need
function BCryptOpenAlgorithmProvider(out phAlgorithm: BCRYPT_ALG_HANDLE; pszAlgId: PWideChar; pszImplementation: PWideChar; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt name 'BCryptOpenAlgorithmProvider';
function BCryptCloseAlgorithmProvider(hAlgorithm: BCRYPT_ALG_HANDLE; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt name 'BCryptCloseAlgorithmProvider';
function BCryptImportKeyPair(hAlgorithm: BCRYPT_ALG_HANDLE; hImportKey: BCRYPT_KEY_HANDLE; pszBlobType: PWideChar; out phKey: BCRYPT_KEY_HANDLE; pbInput: Pointer; cbInput: ULONG; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt name 'BCryptImportKeyPair';
function BCryptSignHash(hKey: BCRYPT_KEY_HANDLE; pPaddingInfo: PBCRYPT_PKCS1_PADDING_INFO; pbHash: PByte; cbHash: ULONG; pbSignature: PByte; cbSignature: ULONG; out pcbResult: ULONG; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt name 'BCryptSignHash';
function BCryptDestroyKey(hKey: BCRYPT_KEY_HANDLE): NTSTATUS; stdcall; external bcrypt name 'BCryptDestroyKey';

function BCryptEncrypt(hKey: BCRYPT_KEY_HANDLE; pbInput: PUCHAR; cbInput: ULONG; pPaddingInfo: PBCRYPT_OAEP_PADDING_INFO; pbIV: PUCHAR; cbIV: ULONG; pbOutput: PUCHAR; cbOutput: ULONG; out pcbResult: ULONG; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt name 'BCryptEncrypt';

function BCryptGetProperty(hObject: BCRYPT_HANDLE; pszProperty: LPCWSTR; pbOutput: PUCHAR; cbOutput: ULONG; pcbResult: PULONG; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt;
function BCryptCreateHash(hAlgorithm: BCRYPT_ALG_HANDLE; out phHash: BCRYPT_HASH_HANDLE; pbHashObject: PUCHAR; cbHashObject: ULONG; pbSecret: PUCHAR; cbSecret: ULONG; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt;
function BCryptHashData(hHash: BCRYPT_HASH_HANDLE; pbInput: PUCHAR; cbInput: ULONG; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt;
function BCryptFinishHash(hHash: BCRYPT_HASH_HANDLE; pbOutput: PUCHAR; cbOutput: ULONG; dwFlags: ULONG): NTSTATUS; stdcall; external bcrypt;
function BCryptDestroyHash(hHash: BCRYPT_HASH_HANDLE): NTSTATUS; stdcall; external bcrypt;

function CryptImportPublicKeyInfoEx2(dwCertEncodingType: DWORD; pInfo: PCERT_PUBLIC_KEY_INFO; dwFlags: DWORD; pAuxInfo: Pointer; var phKey: BCRYPT_KEY_HANDLE): BOOL; stdcall; external crypt32 name 'CryptImportPublicKeyInfoEx2';

implementation

end.

