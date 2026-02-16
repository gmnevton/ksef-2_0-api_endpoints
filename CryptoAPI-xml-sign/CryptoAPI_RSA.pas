unit CryptoAPI_RSA;

interface

uses
  SysUtils,
  Classes;

// wersja dla pelnego obiektu certyfikatu w cert
function CryptoAPI_Encrypt_RSA(const Input: TBytes; const cert: TMemoryStream; const Base64Encoded: Boolean = True): String;
// wersja dla obiektu klucza publicznego w cert
function CryptoAPI_Encrypt_RSA_PublicKey(const Input: TBytes; const cert: TMemoryStream; const Base64Encoded: Boolean = True): String;
// encrypt input with RSA OAEP using SHA-256 via CNG (BCrypt).
function CryptoAPI_Encrypt_RSA_OAEP_SHA256(const Input: TBytes; const cert: TMemoryStream; const Base64Encoded: Boolean = True): String;


implementation

uses
  Windows,
//  Dialogs,
  StrUtils,
  Crypt32_Compat,
  CNG_Compat,
  EncdDecd,
  NetEncoding,
  CryptoAPI_Common,
  ASN1,
  uGMUtils,
  ExceptionJCLSupport;

const
  STATUS_SUCCESS = $00000000;
  CRYPT_DECODE_ENABLE_PUNYCODE_FLAG = $2000000;
  X509_RSAPUBLICKEY = LPCSTR(19);

(*
// Decode from DER format to CERT_PUBLIC_KEY_INFO
  if not CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, @derCert, derCertLen, CRYPT_ENCODE_ALLOC_FLAG, Nil, @publicKeyInfo, publicKeyInfoLen) then begin
    dwResult:=GetLastError();
    raise Exception.CreateFmt('Error [x%x]: CryptDecodeObjectEx() failed.'#13#10'%s', [dwResult, SysErrorMessage(dwResult)]);
  end;
  if not CryptImportKey(hProv, certPubKey, , 0, 0, &hSessionKey) then begin
    dwResult:=GetLastError();
    raise Exception.CreateFmt('Error [x%x]: CryptImportKey() failed.'#13#10'%s', [dwResult, SysErrorMessage(dwResult)]);
  end;
  if WinError(CryptAcquireContext(hProv, Nil, Nil{MS_DEF_PROV}, PROV_RSA_FULL, 0), 'CryptAcquireContext') then begin
    dwResult:=GetLastError();
    if dwResult = NTE_BAD_KEYSET then begin
      if not CryptAcquireContext(hProv, Nil, Nil{MS_DEF_PROV}, PROV_RSA_FULL, CRYPT_NEWKEYSET) then begin
        dwResult:=GetLastError();
        raise Exception.CreateFmt('Error [x%x]: CryptAcquireContext() failed.'#13#10'%s', [dwResult, SysErrorMessage(dwResult)]);
      end;
    end
    else
      raise Exception.CreateFmt('Error [x%x]: CryptAcquireContext() failed.'#13#10'%s', [dwResult, SysErrorMessage(dwResult)]);
  end;

  if certContext = Nil then // CertCreateCertificateContext failed, try non-certificate
    certContext:=CertCreateContext(CERT_STORE_CERTIFICATE_CONTEXT, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @derCert[1], derCertLen, 0, Nil);
*)

// Custom exception type already present
type
  ERSAEncryptionError = class(Exception);

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
    raise ERSAEncryptionError.CreateFmt('Error [x%x]: %s failed.'#13#10'%s', [dwResult, FuncName, SysErrorMessage(dwResult)]);
  end;
end;

// Helper: raise on NTSTATUS failure for CNG functions (BCrypt / NCrypt style)
procedure CheckNTStatus(Status: NTSTATUS; const FuncName: String);
begin
  if Status <> STATUS_SUCCESS then
    raise ERSAEncryptionError.CreateFmt('CNG Error [x%x]: %s failed.', [Status, FuncName]);
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

function CryptoAPI_Encrypt_RSA_PublicKey(const Input: TBytes; const cert: TMemoryStream; const Base64Encoded: Boolean = True): String;
var
  derCert: TBytes;
  derCertLen: Cardinal;
//  Decoded: TBytes;
//  DecodedSize: Cardinal;
  publicKeyInfo: PCERT_PUBLIC_KEY_INFO;
  publicKeyInfoLen: Cardinal;
  hProv: HCRYPTPROV;
//  certContext: PCCERT_CONTEXT;
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
        SetLength(derCert, 8192);
        FillChar(derCert[0], 8192, 0);
        // Convert from PEM format to DER format - removes header and footer and decodes from base64
        DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'CryptStringToBinaryA'); // init file
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
        DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'CryptDecodeObjectEx', True);
//        DecodedSize := 0;
//        WinError(CryptDecodeObject(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
//                                   X509_PUBLIC_KEY_INFO,
//                                   PByte(@derCert[0]), derCertLen,
//                                   0, Nil, DecodedSize), 'CryptDecodeObject(size)');
//        SetLength(Decoded, DecodedSize);
//        WinError(CryptDecodeObject(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
//                                   X509_PUBLIC_KEY_INFO,
//                                   PByte(@derCert[0]), derCertLen,
//                                   0, @Decoded[0], DecodedSize), 'CryptDecodeObject');
//        publicKeyInfo := PCERT_PUBLIC_KEY_INFO(@Decoded[0]);
//        publicKeyInfoLen := DecodedSize;
        //if not CryptDecodeObject(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, PByte(@derCert[0]), derCertLen, CRYPT_ENCODE_ALLOC_FLAG, @publicKeyInfo, publicKeyInfoLen) then
        WinError(CryptDecodeObjectEx(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
                                     X509_PUBLIC_KEY_INFO,
                                     Pbyte(@derCert[0]), derCertLen,
                                     CRYPT_ENCODE_ALLOC_FLAG or CRYPT_DECODE_ENABLE_PUNYCODE_FLAG,
                                     Nil,
                                     @publicKeyInfo, publicKeyInfoLen), 'CryptDecodeObjectEx');
        try
          hProv:=0;
          DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'CryptAcquireContext', True);
          WinError(CryptAcquireContext(hProv, Nil, Nil{MS_DEF_PROV}, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT), 'CryptAcquireContext');
          try
            // Get the public key information for the certificate.
            certPubKey:=0;
            DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'CryptImportPublicKeyInfo', True);
            WinError(CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, publicKeyInfo, certPubKey), 'CryptImportPublicKeyInfo');
            len:=Length(Input);
            if len > 0 then begin
              SetLength(rsa, len + 512);
  //            FillChar(rsa, len + 512, 0);
              try
  //              SetString(rsa, PChar(Input), len + 512);
                CopyMemory(@rsa[0], @Input[0], len);
                DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'CryptEncrypt', True);
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
            DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'CryptReleaseContext', True);
            WinError(CryptReleaseContext(hProv, 0), 'CryptReleaseContext');
          end;
        finally
          DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'CryptMemFree', True);
          //CertFreeCertificateContext(certContext);
          CryptMemFree(@publicKeyInfo);
        end;
      finally
        SetLength(derCert, 0);
      end;
    end;
  except
    on E: Exception do begin
      DebugOutputStrToFile('CryptoAPI_RSA_PubKey.txt', 'Exception in CryptoAPI_Encrypt_RSA_PubKey:'#13#10+GetDetailedExceptionTextInfo(E), True);
      raise;
    end;
  end;
end;


// encrypt input with RSA OAEP using SHA-256 via CNG (BCrypt).
// Returns base64 string. Comments explain steps. No external explanation.
function CryptoAPI_Encrypt_RSA_OAEP_SHA256(const Input: TBytes; const cert: TMemoryStream; const Base64Encoded: Boolean = True): String;
var
  derCert: TBytes;
  derCertLen: DWORD;
  certContext: PCCERT_CONTEXT;
  // pointers used for decoding public key
  pPubKeyInfo: PCERT_PUBLIC_KEY_INFO;
  pbDecoded: PBYTE;
  cbDecoded: DWORD;
  hAlg: BCRYPT_ALG_HANDLE;
  hKey: BCRYPT_KEY_HANDLE;
  status: NTSTATUS;
  // padding info for OAEP with SHA-256
  oaepInfo: BCRYPT_OAEP_PADDING_INFO;
  // result buffer
  cbCipherText: ULONG;
  CipherText: TBytes;
  // temporary variables
  // Exponent as ULONG (big-endian to little-endian conversion)
  expVal: ULONG;
  modLenBytes, i: Integer;
  hdr: PBLOBHEADER;
  pk: PRSAPUBKEY;
  modPtr: PByte;
  modLen: DWORD;
  expBytes: TBytes;
  modulusBE: TBytes;
  hdrBlob: ThdrBlob;
  blob, data: TBytes;
begin
  Result := '';
  // basic validation
  if (cert = Nil) or (cert.Size = 0) then
    Exit;

  // Load certificate bytes (support PEM with header/footer + Base64)
  if Base64Encoded then begin
    // convert PEM/Base64 to DER
    // Use CryptStringToBinaryA to decode base64 PEM header-inclusive
    //derCertLen := 0; // First call to get length
    //WinError(CryptStringToBinaryA(PAnsiChar(cert.Memory), cert.Size, CRYPT_STRING_BASE64HEADER, Nil, derCertLen, Nil), 'CryptStringToBinaryA (len)');
    SetLength(derCert, cert.Size);
    derCertLen := cert.Size;
    //SetLength(derCert, derCertLen);
    WinError(CryptStringToBinaryA(PAnsiChar(cert.Memory), cert.Size, CRYPT_STRING_BASE64HEADER, PByte(@derCert[0]), derCertLen, Nil), 'CryptStringToBinaryA (decode)');
    SetLength(derCert, derCertLen);
  end
  else begin
    cert.Position := 0;
    derCertLen := cert.Size;
    SetLength(derCert, derCertLen);
    cert.Read(derCert[0], derCertLen);
  end;

  // Create CERT_CONTEXT   from DER bytes
  certContext := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @derCert[0], derCertLen);
  if certContext = nil then
    raise ERSAEncryptionError.Create('CertCreateCertificateContext failed.');
  try
    // Get pointer to the SubjectPublicKeyInfo structure
    pPubKeyInfo := @certContext.pCertInfo.SubjectPublicKeyInfo;

    // Decode the SubjectPublicKeyInfo's PublicKey (BIT STRING) to RSA public key structure
    // The inner RSA public key follows the RSAPublicKey ASN.1 sequence (modulus, exponent).
    pbDecoded := Nil;
    cbDecoded := 0;
    // CryptDecodeObject with X509_RSAPUBLICKEY to get a CRYPT_UINT_BLOB containing modulus and exponent as DER?
    // We will decode the whole subjectPublicKey into a sequence and then parse.
    // Use CryptDecodeObjectEx to allocate buffer for decoded RSAPUBLICKEY as CRYPT_UINT_BLOB array via X509_RSAPUBLICKEY constant.
//    if not CryptDecodeObjectEx(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
//                               X509_RSAPUBLICKEY,
//                               pPubKeyInfo^.PublicKey.pbData,
//                               pPubKeyInfo^.PublicKey.cbData,
//                               CRYPT_DECODE_ALLOC_FLAG,
//                               Nil,
//                               @pbDecoded,
//                               cbDecoded) then
//      raise ERSAEncryptionError.Create('CryptDecodeObjectEx(X509_RSAPUBLICKEY) failed.');
    hAlg := 0;
    hKey := 0;

    if not CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, pPubKeyInfo, 0, Nil, hKey) then
      raise ERSAEncryptionError.Create('CryptImportPublicKeyInfoEx2 failed.');

    try
      // Open RSA algorithm provider
//      status := BCryptOpenAlgorithmProvider(hAlg, BCRYPT_RSA_ALGORITHM, nil, 0);
//      CheckNTStatus(status, 'BCryptOpenAlgorithmProvider');

      try
        // Import public key blob to create key handle
//        status := BCryptImportKeyPair(hAlg, 0, BCRYPT_RSAPUBLIC_BLOB, hKey, @blob[0], Length(blob), 0);
//        CheckNTStatus(status, 'BCryptImportKeyPair');
        data := Copy(Input, 0);
        //reverse(data, Length(data));
        try
          // Prepare OAEP padding info to use SHA-256
          oaepInfo.pszAlgId := PChar(BCRYPT_SHA256_ALGORITHM);
          oaepInfo.pbLabel := nil;
          oaepInfo.cbLabel := 0;

          // Determine required buffer size for ciphertext
          cbCipherText := 0;
          status := BCryptEncrypt(hKey, @Input[0], Length(Input), @oaepInfo, nil, 0, nil, 0, cbCipherText, BCRYPT_PAD_OAEP);
          CheckNTStatus(status, 'BCryptEncrypt (size)');
          SetLength(CipherText, cbCipherText);

          // Do encryption
          status := BCryptEncrypt(hKey, @data[0], Length(data), @oaepInfo, nil, 0, @CipherText[0], cbCipherText, cbCipherText, BCRYPT_PAD_OAEP);
          CheckNTStatus(status, 'BCryptEncrypt (encrypt)');

          // Resize to actual size and return base64
          SetLength(CipherText, cbCipherText);
          //Result := BytesToBase64(CipherText);
          Result := ReplaceStr(ReplaceStr(TNetEncoding.Base64.EncodeBytesToString(CipherText), #10, ''), #13, '');
        finally
          SetLength(data, 0);
          // Destroy key handle
          if hKey <> 0 then
            BCryptDestroyKey(hKey);
        end;
      finally
//        BCryptCloseAlgorithmProvider(hAlg, 0);
      end;
    finally
//      if pbDecoded <> nil then
//        LocalFree(HLOCAL(pbDecoded));
    end;
  finally
    CertFreeCertificateContext(certContext);
    // clear DER memory
    Finalize(derCert);
  end;
end;

end.

