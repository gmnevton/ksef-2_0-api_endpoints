//
// Cryptography: Next Gen (CNG) RSA key import and signing helpers
//
unit CNGSign;

interface

uses
  SysUtils,
  Classes,
  Types,
  Windows,
  CNG_Compat;

procedure ParsePKCS8(const Data: TBytes; out AlgOID: String; out PKCS1: TBytes; var ECcurveOID: string);
function ImportPrivateKey_CNG(const PKCS8: TBytes; out hKey: BCRYPT_KEY_HANDLE; out AlgOID: String): Boolean;
function SignHashWithRSA_PKCS1(hKey: BCRYPT_KEY_HANDLE; const HashBytes: TBytes): TBytes;
function SignHashWithECDSA(hKey: BCRYPT_KEY_HANDLE; const HashBytes: TBytes): TBytes;

implementation

uses
//  IOUtils,
  ASN1,
  BigInt,
  Crypt32_Compat;

// parse PKCS#8 PrivateKeyInfo
procedure ParsePKCS8(const Data: TBytes; out AlgOID: String; out PKCS1: TBytes; var ECcurveOID: string);
var
  R: TASN1Reader;
  SeqLen: Integer;
  tmp: TBytes;
  tag: Byte;
begin
  R := ASN1Init(Data);

  SeqLen := ASN1ReadSeqLen(R);

  tmp := ASN1ReadAny(R, tag);
  if tag <> $02 then
    raise Exception.Create('ASN.1 INTEGER expected');
  if (Length(tmp) <> 1) or (tmp[0] <> 0) then
    raise Exception.Create('Unsupported PrivateKeyInfo version');

  // AlgorithmIdentifier
  ASN1ReadSeqLen(R);
  AlgOID := ASN1ReadOID(R);

  ECcurveOID := '';

  // RSA OID
  if AlgOID = '1.2.840.113549.1.1.1' then begin
    // OPTIONAL params
    if ASN1PeekTag(R) = $05 then begin
      Inc(R.Pos);
      ASN1ReadLength(R); // ignore parameters if present
    end
    else if ASN1PeekTag(R) = $30 then
      ASN1ReadSeqLen(R); // ignore parameters if present

    // Extract privateKey (PKCS#1)
    PKCS1 := ASN1ReadOctetString(R); // PKCS#1
    Exit;
  end;

  // EC OID
  if AlgOID = '1.2.840.10045.2.1' then begin
    // parameters = curve OID
    ECcurveOID := ASN1ReadOID(R);

    // ECPrivateKey OCTET STRING
    PKCS1 := ASN1ReadOctetString(R);   // actually RFC5915 ECPrivateKey
    Exit;
  end;

  raise Exception.Create('Not an RSA or EC key algorithm (AlgOID = "' + AlgOID + '")');
end;

// parse PKCS#1 -> BCRYPT_RSAPRIVATE_BLOB
function PKCS1ToCNGBlob(const Data: TBytes): TBytes;
var
  V: TBytes;
  Modulus, PubExp, PrivExp, P, Q, DP, DQ, QInv: TBytes;
  BlobLen, Pos: Integer;
  Header: PBCRYPT_RSAKEY_BLOB;
  r: TASN1Reader;
  tag: Byte;
begin
  r := ASN1Init(Data);

  ASN1ReadSeqLen(r);

  V := ASN1ReadAny(r, tag);

  Modulus := ASN1ReadAny(r, tag);
  PubExp  := ASN1ReadAny(r, tag);
  PrivExp := ASN1ReadAny(r, tag);
  P := ASN1ReadAny(r, tag);
  Q := ASN1ReadAny(r, tag);
  DP := ASN1ReadAny(r, tag);
  DQ := ASN1ReadAny(r, tag);
  QInv := ASN1ReadAny(r, tag);

  BlobLen :=
    SizeOf(BCRYPT_RSAKEY_BLOB) +
    Length(Modulus) +
    Length(PubExp) +
    Length(PrivExp) +
    Length(P) +
    Length(Q) +
    Length(DP) +
    Length(DQ) +
    Length(QInv);

  SetLength(Result, BlobLen);

  Header := PBCRYPT_RSAKEY_BLOB(@Result[0]);
  Header^.Magic := BCRYPT_RSAPRIVATE_MAGIC;
  Header^.BitLength := Length(Modulus) * 8;
  Header^.cbPublicExp := Length(PubExp);
  Header^.cbModulus := Length(Modulus);
  Header^.cbPrime1 := Length(P);
  Header^.cbPrime2 := Length(Q);

  Pos := SizeOf(BCRYPT_RSAKEY_BLOB);

  MoveBytes(PubExp,  Result, Pos);
  MoveBytes(Modulus, Result, Pos);
  MoveBytes(PrivExp, Result, Pos);
  MoveBytes(P,       Result, Pos);
  MoveBytes(Q,       Result, Pos);
  MoveBytes(DP,      Result, Pos);
  MoveBytes(DQ,      Result, Pos);
  MoveBytes(QInv,    Result, Pos);
end;

// --- Big integer helpers for EC decompression ---

function BytesToBigInt(const B: TBytes): TBigInt;
begin
  Result := TBigInt.Create(B);
end;

function BigIntMod(const A, Modulus: TBigInt): TBigInt;
begin
  Result := A.Modulo(Modulus);
end;

function BigIntAdd(const A, B, Modulus: TBigInt): TBigInt;
begin
  Result := A.Add(B).Modulo(Modulus);
end;

function BigIntSub(const A, B, Modulus: TBigInt): TBigInt;
begin
  Result := A.Subtract(B).Modulo(Modulus);
end;

function BigIntMul(const A, B, Modulus: TBigInt): TBigInt;
begin
  Result := A.Multiply(B).Modulo(Modulus);
end;

function BigIntPow(const A, E, Modulus: TBigInt): TBigInt;
begin
  Result := A.ModPow(E, Modulus);
end;

function SqrtModP(const A, P: TBigInt): TBigInt;
var
  E: TBigInt;
begin
  // p ≡ 3 mod 4 for all NIST curves
  // y = a^((p+1)/4)  mod p
  E := P.AddInt(1).DivInt(4);
  Result := A.ModPow(E, P);
end;

// Decompress X -> (X,Y)
function DecompressPoint(const ECPoint: TBytes; KeySize: Integer; const CurveOID: string): TBytes;
var
  Prefix: Byte;
  X, Y, P, B, Z, X3, Tmp: TBigInt;
  Xbytes, Ybytes: TBytes;
  ExpectedParity: Boolean;
begin
  Prefix := ECPoint[0];
  if not (Prefix in [$02, $03]) then
    raise Exception.Create('Unsupported compressed EC point prefix');

  SetLength(Xbytes, KeySize);
  Move(ECPoint[1], Xbytes[0], KeySize);
  X := BytesToBigInt(Xbytes);

  // ---- Curve parameters ----
  if CurveOID = '1.2.840.10045.3.1.7' then begin
    // P-256
    P := TBigInt.Create('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16);
    B := TBigInt.Create('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B', 16);
  end
  else if CurveOID = '1.3.132.0.34' then begin
    // P-384
    P := TBigInt.Create('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF', 16);
    B := TBigInt.Create('B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF', 16);
  end
  else if CurveOID = '1.3.132.0.35' then begin
    // P-521
    P := TBigInt.Create('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
    B := TBigInt.Create('0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF07BB3C9B8899C47AEBB6FB71E91386409', 16);
  end
  else
    raise Exception.Create('Unsupported EC curve for decompression');

  // ---- y² = x³ − 3x + b mod p ----
  X3 := BigIntMul(BigIntMul(X, X, P), X, P); // x³
  Tmp := BigIntMul(X, TBigInt.Create(3), P); // 3x
  Z := BigIntSub(X3, Tmp, P);
  Z := BigIntAdd(Z, B, P); // Z = x³ − 3x + b

  // y = sqrt(Z) mod p
  Y := SqrtModP(Z, P);

  // choose correct parity
  ExpectedParity := (Prefix = $03); // odd
  if (Y.AsBytes[KeySize-1] and 1) <> Ord(ExpectedParity) then
    Y := P.Subtract(Y).Modulo(P);   // take negative root

  // output uncompressed point
  Ybytes := Y.AsBytesPadded(KeySize);

  SetLength(Result, 1 + 2*KeySize);
  Result[0] := $04;
  Move(Xbytes[0], Result[1], KeySize);
  Move(Ybytes[0], Result[1+KeySize], KeySize);
end;

function ImportECPrivateKey_CNG(const ECPrivate: TBytes; const CurveOID: String; out hKey: BCRYPT_KEY_HANDLE): Boolean;
var
  r: TASN1Reader;
  tag: Byte;
  SeqLen: Integer;
  Version: TBytes;
  PrivateKey: TBytes;
  ECPoint: TBytes;
  MagicVal: Cardinal;
  KeySize: Integer;
  Blob: TBytes;
  Status: NTSTATUS;
  hAlg: BCRYPT_ALG_HANDLE;
  pCurve: LPCWSTR;
  Offset: Integer;
  dPadded, X, Y: TBytes;
begin
  Result := False;

  r := ASN1Init(ECPrivate);

  // ECPrivateKey ::= SEQUENCE
  SeqLen := ASN1ReadSeqLen(r);

  // version
  Version := ASN1ReadAny(r, tag);
  if (Length(Version) <> 1) or (Version[0] <> 1) then
    raise Exception.Create('Unsupported ECPrivateKey version');

  // privateKey OCTET STRING
  PrivateKey := ASN1ReadOctetString(r);
//  ReverseBytes(PrivateKey);

  // optional parameters (ignored, we have parameters from PKCS#8)
  if ASN1PeekTag(r) = $A0 then begin
    ASN1ReadAny(r, tag);
  end;

  //
  // Determine curve
  //
  if CurveOID = '1.2.840.10045.3.1.7' then begin
    MagicVal := BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    KeySize := 32;
    pCurve := BCRYPT_ECDSA_P256_ALGORITHM;
  end
  else if CurveOID = '1.3.132.0.34' then begin
    MagicVal := BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
    KeySize := 48;
    pCurve := BCRYPT_ECDSA_P384_ALGORITHM;
  end
  else if CurveOID = '1.3.132.0.35' then begin
    MagicVal := BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
    KeySize := 66;
    pCurve := BCRYPT_ECDSA_P521_ALGORITHM;
  end
  else
    raise Exception.Create('Unsupported EC curve OID: ' + CurveOID);

  // publicKey optional
  ECPoint := Nil;
  if ASN1PeekTag(r) = $A1 then begin
    ECPoint := ASN1ReadAny(r, tag); // BIT STRING
    // strip leading 00 from BIT STRING (unused bits count)
    if (Length(ECPoint) > 0) and (ECPoint[0] = 0) then
      ECPoint := Copy(ECPoint, 1, Length(ECPoint) - 1);

    // ---- FIX FOR NESTED OCTET STRING ----
    if (Length(ECPoint) > 2) and (ECPoint[0] = $04) and (ECPoint[1] = Length(ECPoint) - 2) then begin // OCTET STRING tag
      // remove OCTET STRING wrapper
      ECPoint := Copy(ECPoint, 2, Length(ECPoint) - 2);
    end;

    // Normalize BIT STRING content.
    // Some encoders wrap the point inside an inner BIT STRING structure:
    // [unusedBits][len][unusedBits][pointTag][coords...]
    if Length(ECPoint) >= 4 then begin
      // If ECPoint[2] is the correct unusedBits = 0 AND ECPoint[3] = 02,03,04
      if (ECPoint[0] in [0, 1, 2, 3]) and // outer unused bits (any small value)
         (ECPoint[2] = 0) and             // inner unused bits
         (ECPoint[3] in [$02, $03, $04]) then begin
        // strip the leading: OUTER_UNUSED, LENGTH, INNER_UNUSED
        ECPoint := Copy(ECPoint, 3, Length(ECPoint)-3);
      end;
    end;

    // ECPoint = 04 | X | Y        (uncompressed)
    // or
    // ECPoint = 02 | X            (compressed even-y)
    // or
    // ECPoint = 03 | X            (compressed odd-y)
    //
    // ---- compressed EC point support ----
    if (Length(ECPoint) = 1 + KeySize) and (ECPoint[0] in [$02, $03]) then
      ECPoint := DecompressPoint(ECPoint, KeySize, CurveOID);
  end;

  // Normalize / pad private scalar d to exact KeySize bytes
  if Length(PrivateKey) > KeySize then begin
    // allow a leading zero (ASN.1 integer may include it)
    if (Length(PrivateKey) = KeySize + 1) and (PrivateKey[0] = 0) then
      dPadded := Copy(PrivateKey, 1, KeySize)
    else
      raise Exception.Create('EC private key too long for curve');
  end
  else begin
    SetLength(dPadded, KeySize); // left-pad with zeros
    FillChar(dPadded[0], KeySize, 0);
    Move(PrivateKey[0], dPadded[KeySize - Length(PrivateKey)], Length(PrivateKey));
  end;

  // Require public key point (X,Y). If missing, fail — computing it requires full EC math.
  if (ECPoint = Nil) then
    raise Exception.Create('EC PrivateKey missing public key coordinates (publicKey [1] BIT STRING) — required for CNG import');

  // ECPoint must be uncompressed form: 0x04 || X || Y
  if (Length(ECPoint) <> (1 + KeySize * 2)) or (ECPoint[0] <> $04) then
    raise Exception.CreateFmt('Invalid EC public key point format or length: %d (expected %d)', [Length(ECPoint), 1 + KeySize * 2]);

//  // Fill X and Y from public point
//  if Length(ECPoint) = (1 + KeySize*2) then begin // 04 | X | Y
//    Move(ECPoint[1], Blob[Offset], KeySize*2);
//    Inc(Offset, KeySize*2);
//  end
//  else
//    FillChar(Blob[Offset], KeySize*2, 0);  // allow missing public key

  // Extract X and Y
  SetLength(X, KeySize);
  SetLength(Y, KeySize);
  Move(ECPoint[1], X[0], KeySize);
  Move(ECPoint[1 + KeySize], Y[0], KeySize);

  // coordinates (X, Y) and private D are in big-endian fixed-length fields
//  ReverseBytes(X);
//  ReverseBytes(Y);
//  ReverseBytes(dPadded);

//  if Length(PrivateKey) < KeySize then
//    raise Exception.Create('EC private key too short for curve');

  //
  // Build CNG ECBLOBHEADER + X + Y + d
  //
  SetLength(Blob, SizeOf(BCRYPT_ECCKEY_BLOB) + KeySize * 3); // X,Y,d each KeySize

  // fill header correctly (no shadowing)
  PBCRYPT_ECCKEY_BLOB(@Blob[0])^.dwMagic := MagicVal;
  PBCRYPT_ECCKEY_BLOB(@Blob[0])^.cbKey := KeySize;

  // Offsets: After header -> X, Y, d
  Offset := SizeOf(BCRYPT_ECCKEY_BLOB);

  // copy X
  MoveBytes(X, Blob, Offset);

  // copy Y
  MoveBytes(Y, Blob, Offset);

  // copy d (padded)
  MoveBytes(dPadded, Blob, Offset);

//  TFile.WriteAllText('X_curve.txt', 'b64: ' + BytesToBase64(X) + #13#10 + 'hex: ' + BytesToHex(X));
//  TFile.WriteAllText('Y_curve.txt', 'b64: ' + BytesToBase64(Y) + #13#10 + 'hex: ' + BytesToHex(Y));

  //
  // Import
  //
  hAlg := 0;
  hKey := 0;

  Status := BCryptOpenAlgorithmProvider(hAlg, pCurve, Nil, 0);
  if Status <> 0 then
    Exit;

  Status := BCryptImportKeyPair(hAlg, 0, BCRYPT_ECCPRIVATE_BLOB, hKey, @Blob[0], Length(Blob), 0);
//  if Status <> 0 then
//    RaiseError('BCryptImportKeyPair(EC) failed!', Status);

  BCryptCloseAlgorithmProvider(hAlg, 0);

  // zero sensitive data
  if Length(dPadded) > 0 then begin
    FillChar(dPadded[0], Length(dPadded), 0);
    SetLength(dPadded, 0);
  end;
  if Length(Y) > 0 then begin
    FillChar(Y[0], Length(Y), 0);
    SetLength(Y, 0);
  end;
  if Length(X) > 0 then begin
    FillChar(X[0], Length(X), 0);
    SetLength(X, 0);
  end;
  Result := (Status = 0);
end;

//  Status := BCryptOpenAlgorithmProvider(@hAlg, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
//  if Status <> 0 then
//    //Exit(False);
//    RaiseError('BCryptOpenAlgorithmProvider failed!', Status);
//
//  Status := BCryptImportKeyPair(hAlg, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, @hKey, Pointer(@Pkcs8[0]), Length(Pkcs8), 0);
//  if Status <> 0 then
//    RaiseError('BCryptImportKeyPair failed!', Status);

function ImportPrivateKey_CNG(const PKCS8: TBytes; out hKey: BCRYPT_KEY_HANDLE; out AlgOID: String): Boolean;
var
  PKCS1: TBytes;
  Status: NTSTATUS;
  hAlg: BCRYPT_ALG_HANDLE;
  CngBlob: TBytes;
  CurveOID: String;
begin
  Result := False;
  hKey := 0;

  // parse PKCS#8 -> RSA PKCS#1 or ECPrivateKey
  ParsePKCS8(PKCS8, AlgOID, PKCS1, CurveOID);

  // ---- RSA ----
  if AlgOID = '1.2.840.113549.1.1.1' then begin
    // convert PKCS#1 -> CNG blob
    CngBlob := PKCS1ToCNGBlob(PKCS1);

    // import CNG blob
    hAlg := 0;

    Status := BCryptOpenAlgorithmProvider(hAlg, BCRYPT_RSA_ALGORITHM, nil, 0);
    if Status <> 0 then
      Exit(False);

    Status := BCryptImportKeyPair(hAlg, 0, BCRYPT_RSAPRIVATE_BLOB, hKey, @CngBlob[0], Length(CngBlob), 0);
//    if Status <> 0 then
//      RaiseError('BCryptImportKeyPair(RSA) failed!', Status);

    BCryptCloseAlgorithmProvider(hAlg, 0);

    Exit(Status = 0);
  end;

  // ---- EC ----
  if AlgOID = '1.2.840.10045.2.1' then begin
    // import CNG blob
    Result := ImportECPrivateKey_CNG(PKCS1, CurveOID, hKey);
    Exit;
  end;

  raise Exception.Create('Unsupported PKCS#8 algorithm: ' + AlgOID);
end;

// sign hash with PKCS1 padded RSA
function SignHashWithRSA_PKCS1(hKey: BCRYPT_KEY_HANDLE; const HashBytes: TBytes): TBytes;
var
  cbSig: ULONG;
  status: NTSTATUS;
  PaddingInfo: BCRYPT_PKCS1_PADDING_INFO;
  pcbResult: ULONG;
begin
  Result := Nil;
  if hKey = 0 then
    Exit;
  if Length(HashBytes) = 0 then
    Exit;

  PaddingInfo.pszAlgId := PWideChar(BCRYPT_SHA256_ALGORITHM);

  // first call to get required signature size
  status := BCryptSignHash(hKey, @PaddingInfo, @HashBytes[0], Length(HashBytes), nil, 0, cbSig, BCRYPT_PAD_PKCS1);
  if status <> 0 then
    Exit;

  SetLength(Result, cbSig);
  status := BCryptSignHash(hKey, @PaddingInfo, @HashBytes[0], Length(HashBytes), @Result[0], cbSig, pcbResult, BCRYPT_PAD_PKCS1);
  if status <> 0 then begin
    SetLength(Result, 0);
    Exit;
  end;
  if pcbResult <> cbSig then
    SetLength(Result, pcbResult);
end;

// encode ASN.1 INTEGER (add leading zero if high bit set)
function ASN1EncodeInteger(const Bytes: TBytes): TBytes;
var
  i, startIndex: Integer;
  outLen: Integer;
begin
  // strip leading zeroes
  startIndex := 0;
  while (startIndex < Length(Bytes)-1) and (Bytes[startIndex] = 0) do Inc(startIndex);

  outLen := Length(Bytes) - startIndex;
  // if high bit set, add a 0x00 prefix
  if (outLen > 0) and ((Bytes[startIndex] and $80) <> 0) then begin
    SetLength(Result, 2 + outLen + 1);
    Result[0] := $02;
    Result[1] := Byte(outLen + 1);
    Result[2] := 0;
    Move(Bytes[startIndex], Result[3], outLen);
    Exit;
  end;

  SetLength(Result, 2 + outLen);
  Result[0] := $02;
  Result[1] := Byte(outLen);
  if outLen > 0 then
    Move(Bytes[startIndex], Result[2], outLen);
end;

// build ASN.1 SEQUENCE from two INTEGERs (r,s) where rawSig is r||s fixed-length
function ECDsaRawSignatureToDer(const RawSig: TBytes): TBytes;
var
  rLen, sLen, half: Integer;
  rRaw, sRaw, rEnc, sEnc: TBytes;
  seqLen: Integer;
begin
  Result := Nil;
  if Length(RawSig) mod 2 <> 0 then
    Exit;
  half := Length(RawSig) div 2;
  rRaw := Copy(RawSig, 0, half);
  sRaw := Copy(RawSig, half, half);

  rEnc := ASN1EncodeInteger(rRaw);
  sEnc := ASN1EncodeInteger(sRaw);

  seqLen := Length(rEnc) + Length(sEnc);
  SetLength(Result, 2 + seqLen);
  Result[0] := $30; // SEQUENCE
  Result[1] := Byte(seqLen);
  Move(rEnc[0], Result[2], Length(rEnc));
  Move(sEnc[0], Result[2 + Length(rEnc)], Length(sEnc));
end;

// function that converts an ASN.1/DER encoded ECDSA signature (SEQUENCE of two INTEGERs) into the required P1363 raw r || s format.
//
//- Handles short/long ASN.1 lengths
//- Handles INTEGER sign-padding (leading 00)
//- Enforces fixed-length output (based on curve bits)
//- Raises clear exceptions for malformed signatures
function ASN1ToP1363(const DerSig: TBytes; CurveBits: Integer): TBytes;

  function ReadASN1Length(const Data: TBytes; var Offset: Integer): Integer;
  var
    Len, NumBytes, I: Integer;
  begin
    if Offset >= Length(Data) then
      raise Exception.Create('ASN1 length: offset past end');

    if Data[Offset] < $80 then
    begin
      // Short form
      Result := Data[Offset];
      Inc(Offset);
    end
    else
    begin
      // Long form
      NumBytes := Data[Offset] and $7F;
      Inc(Offset);

      if (NumBytes = 0) or (NumBytes > 4) then
        raise Exception.Create('ASN1 length: invalid long-form length');

      if Offset + NumBytes > Length(Data) then
        raise Exception.Create('ASN1 length: truncated long-form');

      Len := 0;
      for I := 0 to NumBytes - 1 do
        Len := (Len shl 8) or Data[Offset + I];

      Inc(Offset, NumBytes);
      Result := Len;
    end;
  end;

  function ReadASN1Integer(const Data: TBytes; var Offset: Integer): TBytes;
  var
    Len: Integer;
  begin
    if (Offset >= Length(Data)) or (Data[Offset] <> $02) then
      raise Exception.Create('Expected ASN1 INTEGER tag');

    Inc(Offset); // skip tag

    Len := ReadASN1Length(Data, Offset);

    if Offset + Len > Length(Data) then
      raise Exception.Create('ASN1 INTEGER length exceeds buffer');

    SetLength(Result, Len);
    Move(Data[Offset], Result[0], Len);
    Inc(Offset, Len);

    // Strip leading zero sign byte
    while (Length(Result) > 1) and (Result[0] = $00) do
      Result := Copy(Result, 1, Length(Result) - 1);
  end;

  function LeftPad(const Data: TBytes; Total: Integer): TBytes;
  var
    Pad: Integer;
  begin
    if Length(Data) > Total then
      raise Exception.Create('Data longer than expected fixed size');

    Pad := Total - Length(Data);

    SetLength(Result, Total);

    if Pad > 0 then
      FillChar(Result[0], Pad, 0);

    if Length(Data) > 0 then
      Move(Data[0], Result[Pad], Length(Data));
  end;

var
  Offset: Integer;
  SeqLen: Integer;
  R, S: TBytes;
  B: Integer;
begin
  Offset := 0;

  // SEQUENCE tag
  if (Length(DerSig) < 2) or (DerSig[Offset] <> $30) then
    raise Exception.Create('ECDSA DER signature must start with SEQUENCE');

  Inc(Offset);
  SeqLen := ReadASN1Length(DerSig, Offset);

  if Offset + SeqLen <> Length(DerSig) then
    raise Exception.Create('ASN1 SEQUENCE length mismatch');

  // Read r and s
  R := ReadASN1Integer(DerSig, Offset);
  S := ReadASN1Integer(DerSig, Offset);

  // Determine fixed component size
  B := (CurveBits + 7) div 8;

  // Convert to fixed-length padded r||s
  R := LeftPad(R, B);
  S := LeftPad(S, B);

  // Output = R || S
  SetLength(Result, B * 2);
  Move(R[0], Result[0], B);
  Move(S[0], Result[B], B);
end;

//Output format
//For example:
//P-256 -> 32-byte R + 32-byte S -> 64 bytes
//P-384 -> 48-byte R + 48-byte S -> 96 bytes
//P-521 -> 66-byte R + 66-byte S -> 132 bytes

// sign hash with ECDSA (returns DER-encoded signature)
function SignHashWithECDSA(hKey: BCRYPT_KEY_HANDLE; const HashBytes: TBytes): TBytes;
var
  status: NTSTATUS;
  outSize: ULONG;
  rawSig: TBytes;
  // we must open the appropriate algorithm provider? hKey must be an EC key imported via BCryptImportKeyPair.
begin
  Result := Nil;
  if hKey = 0 then
    Exit;
  if Length(HashBytes) = 0 then
    Exit;

  // first call to get required signature size. For ECDSA, BCryptSignHash returns raw r||s signature.
  status := BCryptSignHash(hKey, Nil, @HashBytes[0], Length(HashBytes), nil, 0, outSize, 0);
  if status <> 0 then
    Exit;

  SetLength(rawSig, outSize);
  status := BCryptSignHash(hKey, Nil, @HashBytes[0], Length(HashBytes), @rawSig[0], outSize, outSize, 0);
  if status <> 0 then begin
    SetLength(rawSig, 0);
    Exit;
  end;

  if outSize <> Length(rawSig) then
    SetLength(rawSig, outSize);

//  TFile.WriteAllText('SignHashWithECDSA.txt', 'b64: ' + BytesToBase64(rawSig) + #13#10 + 'hex: ' + BytesToHex(rawSig));

//  ReverseBytes(rawSig);
  if (outSize > 0) and (rawSig[0] = $30) then begin // it’s DER: convert DER -> P1363 then base64
    Result := ASN1ToP1363(rawSig, (outSize div 2) * 8);
  end
  else begin
    // convert raw R||S to ASN.1 DER sequence
    //Result := ECDsaRawSignatureToDer(rawSig);

    SetLength(Result, outSize);
    Move(rawSig[0], Result[0], outSize);
  end;

  // zero sensitive buffer
  FillChar(rawSig[0], Length(rawSig), 0);
  SetLength(rawSig, 0);
end;

end.

