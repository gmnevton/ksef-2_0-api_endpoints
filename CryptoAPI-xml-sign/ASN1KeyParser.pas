unit ASN1KeyParser;

interface

uses
  SysUtils,
  Classes,
  Types,
  IOUtils,
  NetEncoding;

type
  TKeyType = (
    ktUnknown,
    ktRSA,
    ktDSA,
    ktEC,
    ktEd25519, // EdDSA
    ktEd448,   // EdDSA
    ktX25519,
    ktX448,
    ktPBES2,
    ktPBKDF2,
    ktPBE_SHA1_DES_CBC,
    ktPBE_SHA1_RC2_128,
    ktPBE_SHA1_RC2_40,
    ktPBE_MD5_DES_CBC,
    ktPBE_MD5_RC2_64
  );

  TPrivateKeyInfo = record
    Version: Integer;
    AlgOID: String;        // algorithm OID (eg. 1.2.840.10045.2.1)
    CurveOID: String;      // curve OID if present
    KeyType: TKeyType;
    D: TBytes;             // private scalar (big-endian, padded to key size)
    Pub_X: TBytes;         // public X if present (big-endian)
    Pub_Y: TBytes;         // public Y if present (big-endian)
    RawDER: TBytes;        // original DER input
  end;


function DetectKeyType(const AlgOID, ParamOID: String): TKeyType;
function ParsePrivateKeyFromPKCS8DER(const DER: TBytes): TPrivateKeyInfo;
function ParseECPrivateKeyFromRFC5915(const DER: TBytes): TPrivateKeyInfo;

function ParsePrivateKeyFromFile(const FileName: String): TPrivateKeyInfo;

implementation

uses
  DateUtils,
  ASN1,
  Crypt32_Compat,
  Crypt32_Info;


//PKCS#8 PrivateKeyInfo
//PrivateKeyInfo ::= SEQUENCE {
//    version                   Version,
//    privateKeyAlgorithm       AlgorithmIdentifier,
//    privateKey                OCTET STRING,
//    attributes           [0]  IMPLICIT SET OF Attribute OPTIONAL
//}
//Version ::= INTEGER  -- must be 0

//AlgorithmIdentifier ::= SEQUENCE {
//    algorithm               OBJECT IDENTIFIER,
//    parameters              ANY DEFINED BY algorithm OPTIONAL
//}

//Key Type          OID                   Parameters
//-----------------------------------------------------
//RSA               1.2.840.113549.1.1.1	NULL
//EC Key (generic)  1.2.840.10045.2.1     curve OID
//Ed25519           1.3.101.112           NO parameters
//Ed448             1.3.101.113           NO parameters

//RSAPrivateKey ::= SEQUENCE {
//    version           Version,
//    modulus           INTEGER, -- n
//    publicExponent    INTEGER, -- e
//    privateExponent   INTEGER, -- d
//    prime1            INTEGER, -- p
//    prime2            INTEGER, -- q
//    exponent1         INTEGER,
//    exponent2         INTEGER,
//    coefficient       INTEGER,
//    otherPrimeInfos   OtherPrimeInfos OPTIONAL
//}

//ECPrivateKey ::= SEQUENCE {
//    version        INTEGER (1),
//    privateKey     OCTET STRING,
//    parameters [0] EXPLICIT ECParameters OPTIONAL,
//    publicKey  [1] EXPLICIT BIT STRING OPTIONAL
//}

//PKCS#8 PrivateKeyInfo
//  SEQUENCE {
//      INTEGER 0
//      SEQUENCE {
//          OID <algorithm>
//          <parameters>
//      }
//      OCTET STRING {  <-- contains inner key structure
//           <RSAPrivateKey or ECPrivateKey...>
//      }
//      [0] OPTIONAL attributes
//  }

//--- Typical Examples ---

//RSA PrivateKeyInfo
//30 xx        ; SEQUENCE
//   02 01 00  ; version = 0
//   30 xx     ; AlgorithmIdentifier
//      06 09 2A 86 48 86 F7 0D 01 01 01   ; rsaEncryption OID
//      05 00                               ; NULL
//   04 xx     ; OCTET STRING (RSAPrivateKey DER)
//      30 ... ; RSAPrivateKey SEQUENCE

//EC PrivateKeyInfo (P-256)
//30 xx
//   02 01 00
//   30 xx
//      06 07 2A 86 48 CE 3D 02 01   ; id-ecPublicKey
//      06 08 2A 86 48 CE 3D 03 01 07 ; prime256v1
//   04 xx
//      30 ... ; ECPrivateKey

//Ed25519 PrivateKeyInfo
//30 xx
//   02 01 00
//   30 xx
//      06 03 2B 65 70  ; Ed25519
//   04 20 xx..xx       ; 32-byte private key seed



//Uses PBES2 -> PBKDF2 -> AES-CBC

//  ECPrivateKey ::= SEQUENCE {
//    version        INTEGER,
//    privateKey     OCTET STRING, // --> scalar d
//    parameters [0] ECParameters OPTIONAL,
//    publicKey  [1] BIT STRING OPTIONAL // --> public key
//  }

//PKCS#8 PrivateKeyInfo
//  Version:          0
//  Algorithm:        1.2.840.10045.2.1 (id-ecPublicKey)
//  Curve:            1.2.840.10045.3.1.7 (P-256)
//  PrivateKey:       ECPrivateKey SEQUENCE

//ECPrivateKey (RFC 5915)
//  Version:          1
//  D (private key):  823D7E0729A20910FFDBAC8328C7D09A77EA1B3E3BFD434CA...
//  Public key:       04 | X | Y (uncompressed)

//  Encrypted PKCS#8 (30 82 ...)
//  Encrypted PKCS#1 (30 82 ...)
//  PBES2 wrapper (30 82 ... 30 0d 06 09 2a 86 48 86 f7 0d 01 05 0d)
//  PKCS#12 PFX (30 82 ... 02 01 03)
//  Microsoft CNG BCRYPT_PRIVATE_KEY_BLOB (45 43 4B 32 ...)


//30 77
//   02 01 01
//   04 20 <32-byte private scalar>
//   A1 44
//      03 42 00 <65-byte public key>

function DetectKeyType(const AlgOID, ParamOID: String): TKeyType;
begin
  Result := ktUnknown;
  if (Length(AlgOID) = 0) and (Length(ParamOID) = 0) then
    Exit;

  // RSA family
  if AlgOID = '1.2.840.113549.1.1.1'  then Exit(ktRSA); // RSA
  if AlgOID = '1.2.840.113549.1.1.5'  then Exit(ktRSA); // sha1WithRSAEncryption
  if AlgOID = '1.2.840.113549.1.1.11' then Exit(ktRSA); // sha256WithRSAEncryption
  if AlgOID = '1.2.840.113549.1.1.12' then Exit(ktRSA); // sha384WithRSAEncryption
  if AlgOID = '1.2.840.113549.1.1.13' then Exit(ktRSA); // sha512WithRSAEncryption
  if AlgOID = '1.2.840.113549.1.1.14' then Exit(ktRSA); // sha224WithRSAEncryption
  if AlgOID = '1.2.840.113549.1.1.15' then Exit(ktRSA); // sha512-224WithRSAEncryption
  if AlgOID = '1.2.840.113549.1.1.16' then Exit(ktRSA); // sha512-256WithRSAEncryption
  if AlgOID = '1.2.840.113549.1.1.10' then Exit(ktRSA); // RSASSA-PSS
  if AlgOID = '1.2.840.113549.1.1.7'  then Exit(ktRSA); // RSAES-OAEP

  // DSA
  if AlgOID = '1.2.840.10040.4.1'      then Exit(ktDSA); // DSA
  if AlgOID = '1.2.840.10040.4.3'      then Exit(ktDSA); // sha1WithDSA
  if AlgOID = '2.16.840.1.101.3.4.3.2' then Exit(ktDSA); // sha384WithDSA
  if AlgOID = '2.16.840.1.101.3.4.3.3' then Exit(ktDSA); // sha512WithDSA

  // EC (Elliptic Curve)
  if AlgOID = '1.2.840.10045.2.1'   then Exit(ktEC); // EC
  if AlgOID = '1.2.840.10045.4.1'   then Exit(ktEC); // ecdsa-with-SHA1
  if AlgOID = '1.2.840.10045.4.3.2' then Exit(ktEC); // ecdsa-with-SHA256
  if AlgOID = '1.2.840.10045.4.3.3' then Exit(ktEC); // ecdsa-with-SHA384
  if AlgOID = '1.2.840.10045.4.3.4' then Exit(ktEC); // ecdsa-with-SHA512

  // EC curves (ANSI-NIST / SECG)
  if AlgOID = '1.2.840.10045.3.1.7' then Exit(ktEC); // prime256v1 (secp256r1)
  if AlgOID = '1.3.132.0.34'        then Exit(ktEC); // secp384r1
  if AlgOID = '1.3.132.0.35'        then Exit(ktEC); // secp521r1
  if AlgOID = '1.3.132.0.10'        then Exit(ktEC); // secp256k1

  // EdDSA (modern signature algorithms)
  if AlgOID = '1.3.101.112' then Exit(ktEd25519); // Ed25519
  if AlgOID = '1.3.101.113' then Exit(ktEd448); // Ed448

  // X25519 / X448 key exchange
  if AlgOID = '1.3.101.110' then Exit(ktX25519); // X25519
  if AlgOID = '1.3.101.111' then Exit(ktX448); // X448

  // ktCS#8 private key wrappers
  if AlgOID = '1.2.840.113549.1.5.13' then Exit(ktPBES2); // PBES2
  if AlgOID = '1.2.840.113549.1.5.12' then Exit(ktPBKDF2); // PBKDF2
  if AlgOID = '1.2.840.113549.1.5.3'  then Exit(ktPBE_SHA1_DES_CBC); // PBE-SHA1-DES-CBC
  if AlgOID = '1.2.840.113549.1.5.10' then Exit(ktPBE_SHA1_RC2_128); // PBE-SHA1-RC2-128
  if AlgOID = '1.2.840.113549.1.5.11' then Exit(ktPBE_SHA1_RC2_40); // PBE-SHA1-RC2-40
  if AlgOID = '1.2.840.113549.1.5.6'  then Exit(ktPBE_MD5_DES_CBC); // PBE-MD5-DES-CBC
  if AlgOID = '1.2.840.113549.1.5.9'  then Exit(ktPBE_MD5_RC2_64); // PBE-MD5-RC2-64
end;

// Parses RFC5915 ECPrivateKey
function ParseECPrivateKeyFromRFC5915(const DER: TBytes): TPrivateKeyInfo;
var
  PKI: TPrivateKeyInfo;
  R, S, T, U: TASN1Reader;
  seq, tmp: TBytes;
  tag: Byte;
  oid: String;
  privOctet, pk: TBytes;
  pkBit, bpBytes, inSeq: TBytes;
  ks: Integer;
begin
  PKI.RawDER := Copy(DER, 0);
  R := ASN1Init(DER);

  seq := ASN1ReadSequence(R);
  S := ASN1Init(seq);
  // version
  tmp := ASN1ReadAny(S, tag);
  SetLength(tmp, 0);
  // privateKey OCTET STRING
  privOctet := ASN1ReadOctetString(S);
  // parameters [0] EXPLICIT OPTIONAL OR publicKey [1] OPTIONAL - these are tagged
  pkBit := Nil;
  while ASN1PosInsideBuffer(S) do begin
    tag := ASN1PeekTag(S);
    if (tag and $E0) = $A0 then begin
      tmp := ASN1ReadAny(S, tag);
      T := ASN1Init(tmp);
      // tag is context-specific; check if it contains OID (params) or BIT STRING (publicKey)
      tag := ASN1PeekTag(T);
      if tag = $06 then begin // parse OID
        oid := ASN1ReadOID(T);
        PKI.CurveOID := oid;
      end
      // not OID, maybe BIT STRING wrapper
      else if tag = $03 then begin
        pkBit := ASN1ReadBitString(T);
      end
      else begin
        SetLength(tmp, 0);
        ASN1Free(T);
        ASN1ErrorFmt('unexpected TAG: %.2x', [tag]);
      end;
      SetLength(tmp, 0);
      ASN1Free(T);
    end
    else
      Break;
  end;
  SetLength(tmp, 0);
  ASN1Free(T);
  ASN1Free(S);
  // privateKey octet may itself contain an inner ECPrivateKey SEQUENCE (sometimes double-wrapped)
  // If privOctet starts with 0x04|len.. it's OCTET STRING raw; but RFC5915 privateKey is octet containing ECPrivateKey SEQ
  if Length(privOctet) > 0 then begin
    S := ASN1Init(privOctet);
    // if innerSeq looks like SEQ: start with 0x30
    if (ASN1PeekTag(S) = $30) then begin
      // parse inner ECPrivateKey
      inSeq := ASN1ReadSequence(S);
      T := ASN1Init(inSeq);
      // version
      tmp := ASN1ReadAny(T, tag);
      SetLength(tmp, 0);
      // privateKey OCTET STRING
      pk := ASN1ReadOctetString(T);
      PKI.D := pk;
      // optional parameters/publicKey inside inner seq
      while ASN1PosInsideBuffer(T) do begin
        if (ASN1PeekTag(T) and $E0) = $A0 then begin
          tmp := ASN1ReadAny(T, tag);
          U := ASN1Init(tmp);
          tag := ASN1PeekTag(U);
          if tag = $06 then begin // parse OID
            oid := ASN1ReadOID(U);
            PKI.CurveOID := oid;
          end
          // not OID, maybe BIT STRING wrapper
          else if tag = $03 then begin
            bpBytes := ASN1ReadBitString(U);
            if Length(bpBytes)>0 then
              pkBit := bpBytes;
          end
          else begin
            SetLength(tmp, 0);
            ASN1Free(U);
            ASN1ErrorFmt('unexpected TAG: %.2x', [tag]);
          end;
          SetLength(tmp, 0);
          ASN1Free(U);
        end
        else
          Break;
      end;
    // if pkBit still Nil, maybe outer context had it - leave as is
    end
    else begin
      // if privOctet didn't contain SEQ, treat privOctet as raw private scalar
      PKI.D := privOctet;
    end;
  end;
  SetLength(tmp, 0);
  ASN1Free(T);
  ASN1Free(S);

  // if public key found as BIT STRING, extract X/Y
  if (pkBit = Nil) and (Length(privOctet) > 0) and (privOctet[0] = $04) then begin
    pkBit := privOctet; // maybe direct point
  end;
  if (pkBit <> Nil) and (Length(pkBit) > 0) then begin
    if pkBit[0] = $04 then begin
      ks := (Length(pkBit) - 1) div 2;
      SetLength(PKI.Pub_X, ks);
      SetLength(PKI.Pub_Y, ks);
      Move(pkBit[1   ], PKI.Pub_X[0], ks);
      Move(pkBit[1+ks], PKI.Pub_Y[0], ks);
    end
    else if (pkBit[0] in [$02, $03]) then begin
      SetLength(PKI.Pub_X, Length(pkBit) - 1);
      Move(pkBit[1], PKI.Pub_X[0], Length(pkBit) - 1);
      SetLength(PKI.Pub_Y, 0);
    end;
  end;

  Result := PKI;
end;

//PrivateKeyInfo ::= SEQUENCE {
//    version                   Version,
//    privateKeyAlgorithm       AlgorithmIdentifier,
//    privateKey                OCTET STRING,
//    attributes           [0]  IMPLICIT SET OF Attribute OPTIONAL
//}

//  ECPrivateKey ::= SEQUENCE {
//      version        INTEGER,
//      privateKey     OCTET STRING,
//      parameters [0] ECParameters OPTIONAL,
//      publicKey  [1] BIT STRING OPTIONAL
//  }
function ParsePrivateKeyFromPKCS8DER(const DER: TBytes): TPrivateKeyInfo;
var
  PKI: TPrivateKeyInfo;
  R, S, T: TASN1Reader;
  seq, tmp, algSeq, pkOct: TBytes;
  tag: Byte;
  key_type: TKeyType;
begin
  PKI.RawDER := Copy(DER, 0);
  R := ASN1Init(DER);

  // we start as PrivateKeyInfo
  seq := ASN1ReadSequence(R);
  S := ASN1Init(seq);

  // version = 0 or 1; 0 - RSA, 1 - EC
  PKI.Version := ASN1ReadInteger(S);

  // algorithm identifier (SEQUENCE)
  algSeq := ASN1ReadSequence(S);
  T := ASN1Init(algSeq);

  PKI.AlgOID := ASN1ReadOID(T);
  // optional params OID?
  if ASN1PosInsideBuffer(T) then
    PKI.CurveOID := ASN1ReadOID(T)
  else
    PKI.CurveOID := '';

  // privateKey OCTET STRING
  pkOct := ASN1ReadOctetString(S);

  // pkOct now contains RFC5915 ECPrivateKey SEQUENCE bytes (most common) or raw PKCS1 for RSA
  key_type := DetectKeyType(PKI.AlgOID, PKI.CurveOID);
  if key_type = ktEC then begin // Try parsing as ECPrivateKey
    Result := ParseECPrivateKeyFromRFC5915(pkOct);
    // propagate algorithm and curve if missing
    Result.Version := PKI.Version;
    if Result.AlgOID = '' then
      Result.AlgOID := PKI.AlgOID;
    if (Result.CurveOID = '') and (PKI.CurveOID <> '') then
      Result.CurveOID := PKI.CurveOID;
    Result.KeyType := key_type;
    // set RawDER to original PKCS8 input
    Result.RawDER := PKI.RawDER;
  end
  else begin
    // If parsing failed, return minimal info
    Result := PKI;
  end;
end;

function ParsePrivateKeyFromFile(const FileName: String): TPrivateKeyInfo;
begin
  Result := ParsePrivateKeyFromPKCS8DER(TFile.ReadAllBytes(FileName));
end;

end.

