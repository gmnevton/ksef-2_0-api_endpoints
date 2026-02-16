unit CryptoAPI_ECDSA;

interface

uses
  SysUtils,
  Classes;

function CryptoAPI_Encrypt_ECDSA_P256(const Input: TBytes; const cert, pkey: TMemoryStream; const pkeyPasswd: String; const Base64Encoded: Boolean = True): String; overload;
function CryptoAPI_Encrypt_ECDSA_P256(const Input: TBytes; const CertBytes, pkeyBytes: TBytes; const pkeyPasswd: String): String; overload;

implementation

uses
  Windows,
  ActiveX,
//  Dialogs,
  IOUtils,
  StrUtils,
  EncdDecd,
  NetEncoding,
  CNG_Compat,
  Crypt32_Compat,
  CryptoAPI_Common,
  ASN1,
  PKCS8,
  CNGSign,
  uGMUtils,
  ExceptionJCLSupport;

const
  STATUS_SUCCESS = $00000000;
  CRYPT_DECODE_ENABLE_PUNYCODE_FLAG = $2000000;
  X509_RSAPUBLICKEY = LPCSTR(19);

// Custom exception type already present
type
  EECDSAEncryptionError = class(Exception);

  ThdrBlob = packed record
    Magic: ULONG;
    BitLength: ULONG;
    cbPublicExp: ULONG;
    cbModulus: ULONG;
  end;

// Helper: raise on Win32 BOOL failure
function WinError(const RetVal: BOOL; const FuncName: String): BOOL;
var
  dwResult: Integer;
begin
  Result:=RetVal;
  if not RetVal then begin
    dwResult:=GetLastError();
    raise EECDSAEncryptionError.CreateFmt('Error [x%x]: %s failed.'#13#10'%s', [dwResult, FuncName, SysErrorMessage(dwResult)]);
  end;
end;

// Helper: raise on NTSTATUS failure for CNG functions (BCrypt / NCrypt style)
procedure CheckNTStatus(Status: NTSTATUS; const FuncName: String);
begin
  if Status <> STATUS_SUCCESS then
    raise EECDSAEncryptionError.CreateFmt('CNG Error [x%x]: %s failed.', [Status, FuncName]);
end;

// Base64 encoding helper (simple)
// Note: EncodeStream used in original; using TNetEncoding would be nicer but keep simple
function BytesToBase64(const Data: TBytes): String;
var
  outLen: DWORD;
  Buffer: PAnsiChar;
begin
  // Uses original EncodeStream call placeholder: implement manual Base64 via Windows API
  // We'll use CryptBinaryToStringA for base64 conversion
  if Length(Data) = 0 then
    Exit('');
  //
  outLen := 0;
  WinError(CryptBinaryToStringA(@Data[0], Length(Data), CRYPT_STRING_BASE64 or CRYPT_STRING_NOCRLF, nil, outLen), 'CryptBinaryToStringA');

  GetMem(Buffer, outLen);
  try
    WinError(CryptBinaryToStringA(@Data[0], Length(Data), CRYPT_STRING_BASE64 or CRYPT_STRING_NOCRLF, Buffer, outLen), 'CryptBinaryToStringA');
    SetString(Result, Buffer, outLen);
  finally
    FreeMem(Buffer);
  end;
end;

function LoadCertificateContext(const CertFile: String): PCCERT_CONTEXT; overload;
var
  certBytes: TBytes;
begin
  Result := Nil;
  certBytes := TFile.ReadAllBytes(CertFile);
  if Length(certBytes) = 0 then
    Exit;
  Result := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, Pointer(certBytes), Length(certBytes));
end;

function LoadCertificateContext(const certBytes: TBytes): PCCERT_CONTEXT; overload;
begin
  Result := Nil;
  if Length(certBytes) = 0 then
    Exit;
  Result := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, Pointer(certBytes), Length(certBytes));
end;

function CryptoAPI_Encrypt_ECDSA_P256(const Input: TBytes; const cert, pkey: TMemoryStream; const pkeyPasswd: String; const Base64Encoded: Boolean = True): String;
var
  derCert: TBytes;
  derCertLen: DWORD;
  derPKey: TBytes;
  derPKeyLen: DWORD;
begin
  Result := '';
  // Load certificate bytes (support PEM with header/footer + Base64)
  if (cert = Nil) or (cert.Size = 0) then
    Exit;

  if (pkey = Nil) or (pkey.Size = 0) then
    Exit;

  if Base64Encoded then begin
    // convert PEM/Base64 to DER
    // Use CryptStringToBinaryA to decode base64 PEM header-inclusive
    //derCertLen := 0; // First call to get length
    //WinError(CryptStringToBinaryA(PAnsiChar(cert.Memory), cert.Size, CRYPT_STRING_BASE64HEADER, Nil, derCertLen, Nil), 'CryptStringToBinaryA (len)');
    SetLength(derCert, cert.Size);
    derCertLen := cert.Size;
    //SetLength(derCert, derCertLen);
    WinError(CryptStringToBinaryA(PAnsiChar(cert.Memory), cert.Size, CRYPT_STRING_BASE64HEADER, PByte(@derCert[0]), derCertLen, Nil), 'CryptStringToBinaryA (decode cert)');
    SetLength(derCert, derCertLen);
  end
  else begin
    cert.Position := 0;
    derCertLen := cert.Size;
    SetLength(derCert, derCertLen);
    cert.Read(derCert[0], derCertLen);
  end;

  if Base64Encoded then begin
    // convert PEM/Base64 to DER
    // Use CryptStringToBinaryA to decode base64 PEM header-inclusive
    //derCertLen := 0; // First call to get length
    //WinError(CryptStringToBinaryA(PAnsiChar(cert.Memory), cert.Size, CRYPT_STRING_BASE64HEADER, Nil, derCertLen, Nil), 'CryptStringToBinaryA (len)');
    SetLength(derPKey, pkey.Size);
    derPKeyLen := pkey.Size;
    //SetLength(derCert, derCertLen);
    WinError(CryptStringToBinaryA(PAnsiChar(pkey.Memory), pkey.Size, CRYPT_STRING_BASE64HEADER, PByte(@derPKey[0]), derPKeyLen, Nil), 'CryptStringToBinaryA (decode pkey)');
    SetLength(derCert, derCertLen);
  end
  else begin
    pkey.Position := 0;
    derCertLen := pkey.Size;
    SetLength(derPKey, derPKeyLen);
    cert.Read(derPKey[0], derPKeyLen);
  end;

  try
    Result := CryptoAPI_Encrypt_ECDSA_P256(Input, derCert, derPKey, pkeyPasswd);
  finally
    SetLength(derCert, 0);
    SetLength(derPKey, 0);
  end;
end;

function SignData(CertCtx: PCCERT_CONTEXT; keyHandle: BCRYPT_KEY_HANDLE; const AlgOID: String; InBytes: TBytes; out OutBytes: TBytes): Boolean;
var
  KeyContext: CERT_KEY_CONTEXT;
  i: Integer;
  sigHash: TBytes;
begin
  Result := False;
  try
    // attach key to cert (so KeyInfo can reference) - optional
    ZeroMemory(@KeyContext, SizeOf(KeyContext));
    KeyContext.cbSize := SizeOf(KeyContext);
    KeyContext.dwKeySpec := CERT_NCRYPT_KEY_SPEC;
    KeyContext.hNCryptKey := keyHandle;
    if not CertSetCertificateContextProperty(CertCtx, CERT_KEY_CONTEXT_PROP_ID, 0, @KeyContext) then
      ; // non-fatal

    sigHash := SHA256BytesWindows(InBytes);
    //TFile.WriteAllText('signed_info_canonical_hash.xml', BytesToBase64(sigHash, False));
    //ReverseBytes(signedInfoCanonical);

    // sign
    // ---- RSA ----
    if AlgOID = '1.2.840.113549.1.1.1' then begin
      OutBytes := SignHashWithRSA_PKCS1(keyHandle, sigHash)
    end
    else // ---- EC ----
      if AlgOID = '1.2.840.10045.2.1' then begin
        OutBytes := SignHashWithECDSA(keyHandle, sigHash);
      end
      else
        raise Exception.Create('Unsupported public key algorithm in certificate');

//    sigB64 := BytesToBase64(sigValue);
    //TFile.WriteAllText('signed_info_canonical_signed_hash.xml', sigB64);

    // save
//    OutBytes := TEncoding.UTF8.GetBytes(Doc.xml);

    Result := True;
  finally
    SetLength(sigHash, 0);
  end;
end;

function CryptoAPI_Encrypt_ECDSA_P256(const Input: TBytes; const CertBytes, pkeyBytes: TBytes; const pkeyPasswd: String): String;
var
  CertCtx: PCCERT_CONTEXT;
  keyBytes: TBytes;
  keyHandle: BCRYPT_KEY_HANDLE;
  AlgOID: String;
  OutBytes: TBytes;
begin
  CoInitialize(Nil);
  try
    // load cert
    CertCtx := LoadCertificateContext(CertBytes);
    if CertCtx = Nil then
      raise Exception.Create('Failed to load certificate');

    // load & decrypt key
    keyBytes := LoadPEMBytes(pkeyBytes, pkeyPasswd);
    if not ImportPrivateKey_CNG(keyBytes, keyHandle, AlgOID) then
      raise EECDSAEncryptionError.Create('Failed to import private key into CNG');

    // sign
    if not SignData(CertCtx, keyHandle, AlgOID, Input, OutBytes) then
      raise EECDSAEncryptionError.Create('Failed to import private key into CNG');

    Result := BytesToBase64(OutBytes);
  finally
    AlgOID := '';
    SetLength(OutBytes, 0);
    if CertCtx <> Nil then
      CertFreeCertificateContext(CertCtx);
    if keyHandle <> 0 then
      BCryptDestroyKey(keyHandle);
    CoUninitialize;
  end;
end;

(*
function CryptoAPI_Encrypt_RSA(const Input: TBytes; const cert: TMemoryStream; const Base64Encoded: Boolean = True): String;
var
  derCert: TBytes;
  derCertLen: Cardinal;
//  publicKeyInfo: PCERT_PUBLIC_KEY_INFO;
//  publicKeyInfoLen: Cardinal;
  hProv: HCRYPTPROV;
  certContext: PCCERT_CONTEXT;
  certPubKey: HCRYPTKEY;
//  sessionKey: HCRYPTKEY;
  len: LongWord;
  rsa: TBytes;
  ins: TMemoryStream;
  ous: TStringStream;
begin
  Result:='';
  try
    if (cert <> Nil) and (cert.Size > 0) then begin
      if Base64Encoded then begin
        SetLength(derCert, 8192); // 8 KiB
        FillChar(derCert[0], 8192, 0);
        // Convert from PEM format to DER format - removes header and footer and decodes from base64
        DebugOutputStrToFile('CryptoAPI_RSA.txt', 'CryptStringToBinaryA'); // init file
        WinError(CryptStringToBinaryA(PAnsiChar(cert.Memory), cert.Size, CRYPT_STRING_BASE64HEADER, PByte(@derCert[0]), derCertLen, Nil), 'CryptStringToBinaryA');
        SetLength(derCert, derCertLen);
      end
      else begin
        cert.Position := 0;
        derCertLen := cert.Size;
        SetLength(derCert, derCertLen);
        cert.Read(derCert, derCertLen);
      end;
      try
        // Get the certificate context structure from a certificate.
        DebugOutputStrToFile('CryptoAPI_RSA.txt', 'CertCreateCertificateContext', True);
        certContext:=CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, PByte(@derCert[0]), derCertLen);
        WinError(certContext <> Nil, 'CertCreateCertificateContext');
        try
          hProv:=0;
          DebugOutputStrToFile('CryptoAPI_RSA.txt', 'CryptAcquireContext', True);
          WinError(CryptAcquireContext(hProv, Nil, Nil{MS_DEF_PROV}, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT), 'CryptAcquireContext');
          try
            // Get the public key information for the certificate.
            certPubKey:=0;
            DebugOutputStrToFile('CryptoAPI_RSA.txt', 'CryptImportPublicKeyInfo', True);
            WinError(CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                              @certContext.pCertInfo.SubjectPublicKeyInfo, certPubKey), 'CryptImportPublicKeyInfo');
            len:=Length(Input);
            if len > 0 then begin
              SetLength(rsa, len + 512);
  //            FillChar(rsa, len + 512, 0);
              try
  //              SetString(rsa, PChar(Input), len + 512);
                CopyMemory(@rsa[0], @Input[0], len);
                DebugOutputStrToFile('CryptoAPI_RSA.txt', 'CryptEncrypt', True);
                WinError(CryptEncrypt(certPubKey, 0, True, 0, PByte(@rsa[0]), len, len + 512), 'CryptEncrypt');
                SetLength(rsa, len);
                reverse(rsa, len);
                ins:=TMemoryStream.Create;
                try
                  ins.Write(rsa[0], len);
                  ins.Position:=0;
                  ous:=TStringStream.Create;
                  try
                    EncodeStream(ins, ous);
                    ous.Position:=0;
                    Result:=ous.DataString;
                    Result:=ReplaceStr(Result, #13#10, '');
                  finally
                    ous.Free;
                  end;
                finally
                  ins.Free;
                end;
              finally
                SetLength(rsa, 0);
              end;
            end;
          finally
            DebugOutputStrToFile('CryptoAPI_RSA.txt', 'CryptReleaseContext', True);
            WinError(CryptReleaseContext(hProv, 0), 'CryptReleaseContext');
          end;
        finally
          DebugOutputStrToFile('CryptoAPI_RSA.txt', 'CertFreeCertificateContext', True);
          CertFreeCertificateContext(certContext);
        end;
      finally
        SetLength(derCert, 0);
      end;
    end;
  except
    on E: Exception do begin
      DebugOutputStrToFile('CryptoAPI_RSA.txt', 'Exception in CryptoAPI_Encrypt_RSA:'#13#10+GetDetailedExceptionTextInfo(E), True);
      raise;
    end;
  end;
end;
*)

end.

