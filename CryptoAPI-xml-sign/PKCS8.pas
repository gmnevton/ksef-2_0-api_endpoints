//
// Password-protected PKCS#8 (PBES2 PBKDF2 + AES-CBC) decryption
// Minimal ASN.1 parser + PBKDF2 (HMAC-SHA1/SHA256) + AES-CBC decrypt using CryptoAPI
//
unit PKCS8;

interface

uses
  SysUtils, 
  Classes, 
  Windows,
  Types,
  IOUtils, 
  NetEncoding, 
  Crypt32_Compat,
  CNG_Compat;

function DecryptEncryptedPKCS8(const EncryptedDER: TBytes; const Password: String): TBytes;
function LoadPEMBytes(const FileName: String; const Password: String = ''): TBytes; overload;
function LoadPEMBytes(const FileBytes: TBytes; const Password: String = ''): TBytes; overload;

function SHA256BytesWindows(const A: TBytes): TBytes;

implementation

uses
  ASN1;

{ -- crypto helpers for SHA1 implementation (for HMAC-SHA1) -- }

type
  TSHA1Context = record
    state: array[0..4] of Cardinal;
    count: UInt64;
    buffer: array[0..63] of Byte;
  end;

procedure SHA1Init(var ctx: TSHA1Context);
const
  initState: array[0..4] of Cardinal = ($67452301, $EFCDAB89, $98BADCFE, $10325476, $C3D2E1F0);
begin
  Move(initState, ctx.state, SizeOf(initState));
  ctx.count := 0;
  FillChar(ctx.buffer, SizeOf(ctx.buffer), 0);
end;

procedure SHA1Transform(var state: array of Cardinal; const data: array of Byte);

  function rol(x: Cardinal; n: Integer): Cardinal; inline;
  begin
    Result := ((x shl n) or (x shr (32-n)));
  end;

var
  w: Array[0..79] of Cardinal;
  a,b,c,d,e,f,k,temp: Cardinal;
  i: Integer;
begin
  for i := 0 to 15 do begin
    w[i] := (Cardinal(data[i*4]) shl 24) or (Cardinal(data[i*4+1]) shl 16) or (Cardinal(data[i*4+2]) shl 8) or Cardinal(data[i*4+3]);
  end;
  for i := 16 to 79 do
    w[i] := rol(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16], 1);

  a := state[0]; b := state[1]; c := state[2]; d := state[3]; e := state[4];

  for i := 0 to 79 do begin
    if i < 20 then begin
      f := (b and c) or ((not b) and d);
      k := $5A827999;
    end
    else if i < 40 then begin
      f := b xor c xor d;
      k := $6ED9EBA1;
    end
    else if i < 60 then begin
      f := (b and c) or (b and d) or (c and d);
      k := $8F1BBCDC;
    end
    else begin
      f := b xor c xor d;
      k := $CA62C1D6;
    end;
    temp := rol(a,5) + f + e + k + w[i];
    e := d; d := c; c := rol(b,30); b := a; a := temp;
  end;

  state[0] := (state[0] + a);
  state[1] := (state[1] + b);
  state[2] := (state[2] + c);
  state[3] := (state[3] + d);
  state[4] := (state[4] + e);
end;

procedure SHA1Update(var ctx: TSHA1Context; const data: TBytes);
var
  i, index, partLen: Integer;
begin
  if Length(data) = 0 then Exit;
  index := (ctx.count div 8) and $3F;
  ctx.count := ctx.count + UInt64(Length(data)) * 8;
  partLen := 64 - index;
  i := 0;
  if Length(data) >= partLen then begin
    if index > 0 then begin
      Move(data[0], ctx.buffer[index], partLen);
      SHA1Transform(ctx.state, ctx.buffer);
      inc(i, partLen);
    end;
    while (i + 63) < Length(data) do begin
      Move(data[i], ctx.buffer[0], 64);
      SHA1Transform(ctx.state, ctx.buffer);
      inc(i, 64);
    end;
    index := 0;
  end;
  if i < Length(data) then begin
    Move(data[i], ctx.buffer[index], Length(data)-i);
  end;
end;

function SHA1Final(var ctx: TSHA1Context): TBytes;
var
  bits: TBytes;
  index, padLen, i: Integer;
  pad: TBytes;
begin
  SetLength(bits, 8);
  bits[0] := Byte((ctx.count shr 56) and $FF);
  bits[1] := Byte((ctx.count shr 48) and $FF);
  bits[2] := Byte((ctx.count shr 40) and $FF);
  bits[3] := Byte((ctx.count shr 32) and $FF);
  bits[4] := Byte((ctx.count shr 24) and $FF);
  bits[5] := Byte((ctx.count shr 16) and $FF);
  bits[6] := Byte((ctx.count shr 8) and $FF);
  bits[7] := Byte((ctx.count) and $FF);

  index := (ctx.count div 8) and $3f;
  if index < 56 then
    padLen := 56 - index
  else
    padLen := 120 - index;

  SetLength(pad, padLen);
  pad[0] := $80;
  for i := 1 to padLen-1 do
    pad[i] := 0;
  SHA1Update(ctx, pad);
  SHA1Update(ctx, bits);

  SetLength(Result, 20);
  for i := 0 to 4 do begin
    Result[i*4+0] := Byte((ctx.state[i] shr 24) and $FF);
    Result[i*4+1] := Byte((ctx.state[i] shr 16) and $FF);
    Result[i*4+2] := Byte((ctx.state[i] shr 8) and $FF);
    Result[i*4+3] := Byte((ctx.state[i]) and $FF);
  end;
end;

{ -- HMAC-SHA1 and HMAC-SHA256 -- }

function HMAC_SHA1(const Key, Data: TBytes): TBytes;
const
  BLOCK_SIZE = 64;
var
  k: TBytes;
  i: Integer;
  okeypad, ikeypad: TBytes;
  ctx: TSHA1Context;
  innerHash: TBytes;
begin
  if Length(Key) > BLOCK_SIZE then begin
    SHA1Init(ctx);
    SHA1Update(ctx, Key);
    k := SHA1Final(ctx);
  end
  else
    k := Key;

  SetLength(k, BLOCK_SIZE);
  for i := Length(k) to BLOCK_SIZE-1 do
    k[i] := 0;

  SetLength(ikeypad, BLOCK_SIZE);
  SetLength(okeypad, BLOCK_SIZE);
  for i := 0 to BLOCK_SIZE-1 do begin
    ikeypad[i] := Byte(k[i] xor $36);
    okeypad[i] := Byte(k[i] xor $5c);
  end;

  SHA1Init(ctx);
  SHA1Update(ctx, ikeypad);
  SHA1Update(ctx, Data);
  innerHash := SHA1Final(ctx);

  SHA1Init(ctx);
  SHA1Update(ctx, okeypad);
  SHA1Update(ctx, innerHash);
  Result := SHA1Final(ctx);
end;

function SHA256BytesWindows(const A: TBytes): TBytes;
var
  hAlg: BCRYPT_ALG_HANDLE;
  hHash: BCRYPT_HASH_HANDLE;
  digestLen, resLen: ULONG;
  st: NTSTATUS;
  digest: TBytes;
begin
  Result := Nil;
  hAlg := 0;
  hHash := 0;
  st := BCryptOpenAlgorithmProvider(hAlg, BCRYPT_SHA256_ALGORITHM, nil, 0);
  if st <> 0 then
    Exit;
  st := BCryptGetProperty(hAlg, 'HashDigestLength', @digestLen, SizeOf(digestLen), @resLen, 0);
  if st <> 0 then begin
    BCryptCloseAlgorithmProvider(hAlg,0);
    Exit;
  end;
  st := BCryptCreateHash(hAlg, hHash, nil, 0, nil, 0, 0);
  if st <> 0 then begin
    BCryptCloseAlgorithmProvider(hAlg,0);
    Exit;
  end;
  if Length(A) > 0 then begin
    st := BCryptHashData(hHash, @A[0], Length(A), 0);
    if st <> 0 then begin
      BCryptDestroyHash(hHash);
      BCryptCloseAlgorithmProvider(hAlg, 0);
      Exit;
    end;
  end;
  SetLength(digest, digestLen);
  st := BCryptFinishHash(hHash, @digest[0], digestLen, 0);
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  if st = 0 then
    Result := digest;
end;

function HMAC_SHA256(const Key, Data: TBytes): TBytes;
var
  blockSize: Integer;
  k: TBytes;
  i: Integer;
  ikeypad, okeypad, innerHash, outerHash: TBytes;
begin
  blockSize := 64;
  if Length(Key) > blockSize then
    k := SHA256BytesWindows(Key)
  else
    k := Key;
  SetLength(k, blockSize);
  for i := Length(k) to blockSize-1 do
    k[i] := 0;
  SetLength(ikeypad, blockSize); SetLength(okeypad, blockSize);
  for i := 0 to blockSize-1 do begin
    ikeypad[i] := Byte(k[i] xor $36);
    okeypad[i] := Byte(k[i] xor $5c);
  end;
  innerHash := SHA256BytesWindows(ikeypad + Data);
  outerHash := SHA256BytesWindows(okeypad + innerHash);
  Result := outerHash;
end;

function PBKDF2_HMAC(const Password: TBytes; const Salt: TBytes; Iterations, KeyLen: Integer; UseSHA256: Boolean): TBytes;
var
  hLen, l, r, i, j, k: Integer;
  Tblock, U, saltPlus, derived: TBytes;
begin
  if UseSHA256 then
    hLen := 32
  else
    hLen := 20;
  l := (KeyLen + hLen - 1) div hLen;
  r := KeyLen - (l - 1) * hLen;
  SetLength(derived, l * hLen);
  for i := 1 to l do begin
    SetLength(saltPlus, Length(Salt) + 4);
    if Length(Salt) > 0 then
      Move(Salt[0], saltPlus[0], Length(Salt));
    saltPlus[Length(Salt)+0] := Byte((i shr 24) and $FF);
    saltPlus[Length(Salt)+1] := Byte((i shr 16) and $FF);
    saltPlus[Length(Salt)+2] := Byte((i shr 8) and $FF);
    saltPlus[Length(Salt)+3] := Byte((i) and $FF);
    if UseSHA256 then
      U := HMAC_SHA256(Password, saltPlus)
    else
      U := HMAC_SHA1(Password, saltPlus);
    SetLength(Tblock, Length(U)); Move(U[0], Tblock[0], Length(U));
    for j := 2 to Iterations do begin
      if UseSHA256 then
        U := HMAC_SHA256(Password, U)
      else
        U := HMAC_SHA1(Password, U);
      for k := 0 to Length(U)-1 do
        Tblock[k] := Byte(Tblock[k] xor U[k]);
    end;
    Move(Tblock[0], derived[(i-1)*hLen], Length(Tblock));
  end;
  SetLength(Result, KeyLen);
  Move(derived[0], Result[0], KeyLen);
end;

function AES_CBC_Decrypt(const Key, IV, CipherText: TBytes): TBytes;
var
  hProv: HCRYPTPROV;
  hKey: HCRYPTKEY;
  blobSize: DWORD;
  blob: Pointer;
  hdr: BLOBHEADER;
  keyLenBytes: DWORD;
  outLen: DWORD;
  error: DWORD;
begin
  Result := nil;
  if not CryptAcquireContext(hProv, nil, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    RaiseError('CryptAcquireContext failed!', GetLastError);
  try
    hdr.bType := PLAINTEXTKEYBLOB;
    hdr.bVersion := CUR_BLOB_VERSION;
    hdr.reserved := 0;
    hdr.aiKeyAlg := CALG_AES_256;
    keyLenBytes := Length(Key);
    if keyLenBytes = 16 then
      hdr.aiKeyAlg := CALG_AES_128
    else if keyLenBytes = 24 then
      hdr.aiKeyAlg := CALG_AES_192
    else if keyLenBytes = 32 then
      hdr.aiKeyAlg := CALG_AES_256
    else
      raise Exception.Create('AES_CBC_Decrypt: unsupported key length');
    blobSize := SizeOf(BLOBHEADER) + SizeOf(DWORD) + keyLenBytes;
    GetMem(blob, blobSize);
    try
      // | 8 bytes    | 4 bytes     | n bytes |
      // --------------------------------------
      // | BLOBHEADER | keyLenBytes | Key     |
      Move(hdr, blob^, SizeOf(hdr));
      PCardinal(Cardinal(blob) + SizeOf(hdr))^ := keyLenBytes;
      Move(Key[0], PByte(Cardinal(blob) + SizeOf(hdr) + SizeOf(DWORD))^, keyLenBytes);
      if not CryptImportKey(hProv, blob, blobSize, 0, 0, hKey) then
        RaiseError('CryptImportKey failed!', GetLastError);
      try
        if (Length(IV) > 0) then
          if not CryptSetKeyParam(hKey, KP_IV, @IV[0], 0) then
            RaiseError('CryptSetKeyParam(KP_IV) failed!', GetLastError);
        SetLength(Result, Length(CipherText));
        Move(CipherText[0], Result[0], Length(CipherText));
        outLen := Length(Result);
        if not CryptDecrypt(hKey, 0, True, 0, @Result[0], outLen) then
          RaiseError('CryptDecrypt failed!', GetLastError);
        SetLength(Result, outLen);
      finally
        CryptDestroyKey(hKey);
      end;
    finally
      FreeMem(blob);
    end;
  finally
    CryptReleaseContext(hProv, 0);
  end;
end;

function DecryptEncryptedPKCS8(const EncryptedDER: TBytes; const Password: String): TBytes;
var
  r: TASN1Reader;
  tmpTag: Byte;
  tmpLen: Integer;
  algReader, pbes2, kdfReader, pbkdf2Reader, encSchemeReader, prfAlgReader: TASN1Reader;
  algOID, kdfOID, prfOID, cipherOID: String;
  pbkdf2Salt, iv, encData: TBytes;
  iterCount: Integer;
  keyLen, dkLen: Integer;
  useSHA256PRF: Boolean;
  pw: TBytes;
  derivedKey: TBytes;
begin
  Result := Nil;
  r := ASN1Init(EncryptedDER);

  if ASN1PeekTag(r) <> $30 then
    raise Exception.Create('Not ASN.1 SEQUENCE at top');

  ASN1ReadTagAndLength(r, tmpTag, tmpLen);

  algReader := ASN1GetSubreader(r);
  algOID := ASN1ReadOID(algReader);

  if algOID <> '1.2.840.113549.1.5.13' then
    raise Exception.CreateFmt('Unsupported encryption algorithm OID: %s (expected PBES2)', [algOID]);

  pbes2 := ASN1GetSubreader(algReader);

  // keyDerivationFunc
  kdfReader := ASN1GetSubreader(pbes2);
  kdfOID := ASN1ReadOID(kdfReader);
  if kdfOID <> '1.2.840.113549.1.5.12' then
    raise Exception.CreateFmt('Unsupported KDF OID: %s (expected pbkdf2)', [kdfOID]);

  pbkdf2Reader := ASN1GetSubreader(kdfReader);

  // salt
  if ASN1PeekTag(pbkdf2Reader) = $04 then
    pbkdf2Salt := ASN1ReadBytes(pbkdf2Reader, $04)
  else
    raise Exception.Create('Unsupported PBKDF2 salt format');

  // iteration count
  iterCount := ASN1ReadInteger(pbkdf2Reader);

  // optional keyLength
  keyLen := 0;
  if (pbkdf2Reader.Pos < Length(pbkdf2Reader.Buf)) and (ASN1PeekTag(pbkdf2Reader) = $02) then
    keyLen := ASN1ReadInteger(pbkdf2Reader);

  // optional prf AlgorithmIdentifier
  prfOID := '1.2.840.113549.2.7'; // default HMAC-SHA1
  if (pbkdf2Reader.Pos < Length(pbkdf2Reader.Buf)) then begin
    prfAlgReader := ASN1GetSubreader(pbkdf2Reader);
    prfOID := ASN1ReadOID(prfAlgReader);
  end;
  useSHA256PRF := (prfOID = '1.2.840.113549.2.9') or (Pos('sha256', LowerCase(prfOID)) > 0);

  // encryptionScheme
  encSchemeReader := ASN1GetSubreader(pbes2);
  cipherOID := ASN1ReadOID(encSchemeReader);

  // IV (OCTET STRING)
  if ASN1PeekTag(encSchemeReader) = $04 then
    iv := ASN1ReadBytes(encSchemeReader, $04)
  else
    raise Exception.Create('Unsupported encryptionScheme params');

  // encryptedData (OCTET STRING)
  encData := ASN1ReadBytes(r, $04);

  // determine derived key length
  if keyLen = 0 then begin
    // Map common AES CBC OIDs to key lengths:
    //  aes-128-cbc:  2.16.840.1.101.3.4.1.2   -> 16
    //  aes-192-cbc:  2.16.840.1.101.3.4.1.22  -> 24
    //  aes-256-cbc:  2.16.840.1.101.3.4.1.42  -> 32
    if Pos('2.16.840.1.101.3.4.1.2', cipherOID) > 0 then
      dkLen := 16
    else if Pos('2.16.840.1.101.3.4.1.22', cipherOID) > 0 then
      dkLen := 24
    else if Pos('2.16.840.1.101.3.4.1.42', cipherOID) > 0 then
      dkLen := 32
    //else if Pos('2.16.840.1.101.3.4.1.46', cipherOID) > 0 then
    //  dkLen := 32
    else
      //dkLen := 32;
      // fallback: default to 32 bits (AES-256) if unknown — but safer to raise
      raise Exception.CreateFmt('Unsupported PBES2 cipher OID: %s', [cipherOID]);
  end
  else
    dkLen := keyLen;

  // IV sanity check (AES block size)
  if Length(iv) <> 16 then
    raise Exception.CreateFmt('Unexpected IV length: %d (expected 16)', [Length(iv)]);

  // derive key and decrypt
  pw := TEncoding.UTF8.GetBytes(Password);
  try
    derivedKey := PBKDF2_HMAC(pw, pbkdf2Salt, iterCount, dkLen, useSHA256PRF);
  finally
    FillChar(pw[0], Length(pw), 0);
    SetLength(pw, 0);
  end;

  Result := AES_CBC_Decrypt(derivedKey, iv, encData);

  // zero sensitive buffers
  FillChar(derivedKey[0], Length(derivedKey), 0);
  SetLength(derivedKey, 0);
end;

function LoadPEMBytes(const FileName: String; const Password: String = ''): TBytes;
var
  SL: TStringList;
  i: Integer;
  base64, hdr: String;
  b: TBytes;
begin
  SL := TStringList.Create;
  try
    SL.LoadFromFile(FileName, TEncoding.ASCII);
    hdr := Trim(SL[0]);
    base64 := '';
    for i := 0 to SL.Count - 1 do
      if Pos('-----', SL[i]) = 0 then base64 := base64 + Trim(SL[i]);

    b := TNetEncoding.Base64.DecodeStringToBytes(base64);
    if Pos('ENCRYPTED', hdr) > 0 then begin
      if Password = '' then
        raise Exception.Create('Private key is encrypted, but no password was supplied.');
      Result := DecryptEncryptedPKCS8(b, Password);
    end
    else
      Result := b;
  finally
    SL.Free;
  end;
end;

function LoadPEMBytes(const FileBytes: TBytes; const Password: String = ''): TBytes;
var
  i: Integer;
begin
  if Length(Password) > 0 then
    Result := DecryptEncryptedPKCS8(FileBytes, Password)
  else
    Result := FileBytes;
end;

end.

