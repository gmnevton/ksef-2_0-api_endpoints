unit CryptoAPI_AES;

interface

uses
  SysUtils,
  Classes;

procedure CryptoAPI_Encrypt_AES(const InStream, CipherStream: TMemoryStream; const CipherKey, CipherIV: String);
procedure CryptoAPI_Decrypt_AES(const CipherStream, OutStream: TMemoryStream; const CipherKey, CipherIV: String);
procedure CryptoAPI_Decrypt_AES_CBC_PKCS7(const CipherStream, OutStream: TMemoryStream; const CipherKey, CipherIV: String);

implementation

uses
  Windows,
  Math,
  StrUtils,
  NetEncoding,
  Crypt32_Compat,
  CryptoAPI_Common;

type
  EAESEncryptionError = class(Exception);

function WinError(const RetVal: BOOL; const FuncName: String): BOOL;
var
  dwResult: Integer;
begin
  Result:=RetVal;
  if not RetVal then begin
    dwResult:=GetLastError();
    raise EAESEncryptionError.CreateFmt('Error [x%x]: %s failed.'#13#10'%s', [dwResult, FuncName, SysErrorMessage(dwResult)]);
  end;
end;

function ImportAES256Key(hProv: HCRYPTPROV; const Key: TBytes): HCRYPTKEY;
type
  TAESKeyBlob = packed record
    Header: BLOBHEADER;
    KeySize: DWORD;
    KeyData: array[0..31] of Byte;
  end;
var
  Blob: TAESKeyBlob;
  BlobSize: DWORD;
  hKey: HCRYPTKEY;
begin
  if Length(Key) <> 32 then
    raise Exception.Create('AES-256 key must be 32 bytes');

  Blob.Header.bType := PLAINTEXTKEYBLOB;
  Blob.Header.bVersion := CUR_BLOB_VERSION;
  Blob.Header.reserved := 0;
  Blob.Header.aiKeyAlg := CALG_AES_256;

  Blob.KeySize := 32;
  Move(Key[0], Blob.KeyData[0], 32);

  BlobSize := SizeOf(Blob);

  WinError(CryptImportKey(hProv, @Blob, BlobSize, 0, 0, hKey), 'CryptImportKey');

  Result := hKey;
end;

procedure Init(const CipherKey, CipherIV: TBytes; const PlainKey: Boolean; const mode: DWORD; padding: DWORD; var hProv: HCRYPTPROV; var hKey: HCRYPTKEY);
var
  hHash: HCRYPTHASH;
//  cbData: DWORD;
//  dwBlockLen, dwDataLen: DWORD;
begin
  hProv:=0;
  hKey:=0;
//  if not CryptAcquireContext(hProv, Nil, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) then
    //WinError(CryptAcquireContext(hProv, Nil, MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, 0), 'CryptAcquireContext(XP)');
  WinError(CryptAcquireContext(hProv, Nil, Nil{MS_ENH_RSA_AES_PROV_XP}, PROV_RSA_AES, 0), 'CryptAcquireContext');
  //
  if PlainKey then
    hKey := ImportAES256Key(hProv, CipherKey)
  else begin
    WinError(CryptCreateHash(hProv, CALG_SHA_512, 0, 0, hHash), 'CryptCreateHash');
    try
      if Length(CipherKey) = 0 then
        raise EAESEncryptionError.Create('Error: CipherKey length must be greater then 0!');
      WinError(CryptHashData(hHash, @CipherKey[0], Length(CipherKey), 0), 'CryptHashData');
      WinError(CryptDeriveKey(hProv, CALG_AES_256, hHash, 0{CRYPT_EXPORTABLE}, hKey), 'CryptDeriveKey');
    finally
      CryptDestroyHash(hHash);
    end;
  end;
  //
  if mode <> 0 then
    WinError(CryptSetKeyParam(hKey, KP_MODE, @mode, 0), 'CryptSetKeyParam(KP_MODE)');
  if padding <> 0 then
    WinError(CryptSetKeyParam(hKey, KP_PADDING, @padding, 0), 'CryptSetKeyParam(KP_PADDING)');
  if Length(CipherIV) = 0 then
    raise EAESEncryptionError.Create('Error: CipherIV length must be greater then 0!');
  WinError(CryptSetKeyParam(hKey, KP_IV, @CipherIV[0], 0), 'CryptSetKeyParam(KP_IV)');
//  dwDataLen:=SizeOf(dwBlockLen);
//  WinError(CryptGetKeyParam(hKey, KP_BLOCKLEN, @dwBlockLen, dwDataLen, 0), 'CryptGetKeyParam(KP_BLOCKLEN)');
//  dwBlockLen:=dwBlockLen div 8;
end;

procedure Deinit(const hProv: HCRYPTPROV; const hKey: HCRYPTKEY);
begin
  WinError(CryptDestroyKey(hKey), 'CryptDestroyKey');
  WinError(CryptReleaseContext(hProv, 0), 'CryptReleaseContext');
end;

function Encrypt(const Input, CipherKey, CipherIV: TBytes; const PlainKey: Boolean; const mode: DWORD; padding: DWORD): TBytes;
var
  hProv: HCRYPTPROV;
  hKey: HCRYPTKEY;
  len, cnt{, block, read}: LongWord;
//  eof: Boolean;
  rsa: TBytes;
//  ms: TMemoryStream;
begin
  SetLength(Result, 0);
  len:=Length(Input);
  if len = 0 then
    Exit;

  Init(CipherKey, CipherIV, PlainKey, mode, padding, hProv, hKey);
  try
    cnt:=len + (16 - (len mod 16));
    SetLength(rsa, cnt);
    try
      FillChar(rsa[0], cnt, 0);
      CopyMemory(@rsa[0], @Input[0], len);
      WinError(CryptEncrypt(hKey, 0, True, CRYPT_OAEP, @rsa[0], len, cnt), 'CryptEncrypt');
      SetLength(Result, len);
      CopyMemory(@Result[0], @rsa[0], len);
    finally
      SetLength(rsa, 0);
    end;
//-----------------------------------------------------------------------------------------------
{
    ms:=TMemoryStream.Create;
    try
      eof:=False;
      read:=0;
      repeat
        cnt:=Min(len, 16);
        if (cnt < 16) or (len <= 16) then
          eof:=True;
        block:=cnt;
        WinError(CryptEncrypt(hKey, 0, eof, CRYPT_OAEP, Nil, block, cnt), 'CryptEncrypt(length)');
//        if eof and (block = cnt) then
//          Inc(block, 16);
        SetLength(rsa, block);
        try
          FillChar(rsa[0], block, 0);
          CopyMemory(@rsa[0], @Input[read], block);
          WinError(CryptEncrypt(hKey, 0, eof, CRYPT_OAEP, @rsa[0], cnt, block), 'CryptEncrypt');
          Inc(read, cnt);
          Dec(len, cnt);
          ms.Write(rsa[0], cnt);
        finally
          SetLength(rsa, 0);
        end;
      until eof;
      ms.Position:=0;
      SetLength(Result, ms.Size);
      ms.Read(Result[0], ms.Size);
//      reverse(Result, ms.Size);
    finally
      ms.Free;
    end;
}
  finally
    Deinit(hProv, hKey);
  end;
end;

function Decrypt(const Input, CipherKey, CipherIV: TBytes; const PlainKey: Boolean; const mode: DWORD; padding: DWORD): TBytes;
var
  hProv: HCRYPTPROV;
  hKey: HCRYPTKEY;
  len: LongWord;
begin
  SetLength(Result, 0);
  len:=Length(Input);
  if len = 0 then
    Exit;

  Init(CipherKey, CipherIV, PlainKey, mode, padding, hProv, hKey);
  try
    Result := Copy(Input, 0);
    WinError(CryptDecrypt(hKey, 0, True, 0, @Result[0], len), 'CryptDecrypt');
    SetLength(Result, len);
  finally
    Deinit(hProv, hKey);
  end;
end;

procedure CryptoAPI_Encrypt_AES(const InStream, CipherStream: TMemoryStream; const CipherKey, CipherIV: String);
var
  input, output, key, iv: TBytes;
  cKey, cIV: AnsiString;
begin
  CipherStream.Size:=0;
  CipherStream.Position:=0;
  SetLength(input, InStream.Size);
  InStream.Position:=0;
  InStream.Read(input[0], InStream.Size);
  cKey:=AnsiString(CipherKey);
  cIV:=AnsiString(CipherIV);
  if Length(cKey) > 32 then
    key:=DecodeBase64(cKey);
//  reverse(key, Length(key));
  if Length(cIV) > 16 then
    iv:=DecodeBase64(cIV);
//  reverse(iv, Length(iv));
//  key:=BytesOf(cKey);
//  iv:=BytesOf(cIV);
  if Length(key) <> 32 then
    raise EAESEncryptionError.Create('Key length mismatch 32 bytes!');
  if Length(iv) <> 16 then
    raise EAESEncryptionError.Create('IV length mismatch 16 bytes!');

  output:=Encrypt(input, key, iv, True, 0, 0);
  if Length(output) > 0 then begin
    CipherStream.Write(output[0], Length(output));
    CipherStream.Position:=0;
  end;

  cKey:='';
  cIV:='';
  SetLength(input, 0);
  SetLength(key, 0);
  SetLength(iv, 0);
end;

procedure CryptoAPI_Decrypt_AES(const CipherStream, OutStream: TMemoryStream; const CipherKey, CipherIV: String);
var
  input, output, key, iv: TBytes;
  b64: TBase64Encoding;
begin
  OutStream.Size:=0;
  OutStream.Position:=0;
  SetLength(input, CipherStream.Size);
  CipherStream.Position:=0;
  CipherStream.Read(input[0], CipherStream.Size);
  b64:=TBase64Encoding.Create(0);
  if Length(CipherKey) > 32 then
    key:=b64.DecodeStringToBytes(CipherKey)
  else
    key:=BytesOf(CipherKey);
  if Length(CipherIV) > 16 then
    iv:=b64.DecodeStringToBytes(CipherIV)
  else
    iv:=BytesOf(CipherIV);
  b64.Free;
  if Length(key) <> 32 then
    raise EAESEncryptionError.Create('Key length mismatch 32 bytes!');
  if Length(iv) <> 16 then
    raise EAESEncryptionError.Create('IV length mismatch 16 bytes!');

  output:=Decrypt(input, key, iv, True, 0, 0);
  if Length(output) > 0 then begin
    OutStream.Write(output[0], Length(output));
    OutStream.Position:=0;
  end;

  SetLength(input, 0);
  SetLength(key, 0);
  SetLength(iv, 0);
end;

procedure CryptoAPI_Decrypt_AES_CBC_PKCS7(const CipherStream, OutStream: TMemoryStream; const CipherKey, CipherIV: String);
var
  input, output, key, iv: TBytes;
  b64: TBase64Encoding;
begin
  OutStream.Size:=0;
  OutStream.Position:=0;
  SetLength(input, CipherStream.Size);
  CipherStream.Position:=0;
  CipherStream.Read(input[0], CipherStream.Size);
  b64:=TBase64Encoding.Create(0);
  if Length(CipherKey) > 32 then
    key:=b64.DecodeStringToBytes(CipherKey)
  else
    key:=BytesOf(CipherKey);
  if Length(CipherIV) > 16 then
    iv:=b64.DecodeStringToBytes(CipherIV)
  else
    iv:=BytesOf(CipherIV);
  b64.Free;
  if Length(key) <> 32 then
    raise EAESEncryptionError.Create('Key length mismatch 32 bytes!');
  if Length(iv) <> 16 then
    raise EAESEncryptionError.Create('IV length mismatch 16 bytes!');

  output:=Decrypt(input, key, iv, True, CRYPT_MODE_CBC, PKCS5_PADDING);
  if Length(output) > 0 then begin
    OutStream.Write(output[0], Length(output));
    OutStream.Position:=0;
  end;

  SetLength(input, 0);
  SetLength(key, 0);
  SetLength(iv, 0);
end;

end.
