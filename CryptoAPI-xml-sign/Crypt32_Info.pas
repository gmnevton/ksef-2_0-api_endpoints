unit Crypt32_Info;

interface

uses
  SysUtils;

type
  // Supported ASN.1 key/cert container types
  TCryptInfoDataType = (
    kdtUnknown,

    // X509
    kdtX509Certificate,

    // PKCS#1 RSA
    kdtRSAPrivate,
    kdtRSAPublic,
    kdtRSASignatureSHA1,
    kdtRSASignatureSHA256,
    kdtRSASignatureSHA384,
    kdtRSASignatureSHA512,

    // EC RFC5915 / SPKI / (generic)
    kdtECPrivate,
    kdtECPublic,

    // EC curves
    kdtECP256,
    kdtECP384,
    kdtECP521,

    // EC signatures
    kdtECDSASHA1,
    kdtECDSASHA256,
    kdtECDSASHA384,
    kdtECDSASHA512,

    // PKCS containers
    kdtPKCS8Private,
    kdtPKCS8EncryptedPrivate,
    kdtPKCS12,
    kdtCSR
  );

const
  extnID_KeyUsage = '2.5.29.15'; // OID for KeyUsage
  extnID_BasicConstraints = '2.5.29.19'; // OID for BasicConstraints
  extnID_QCStatements = '1.3.6.1.5.5.7.1.3'; // OID for QCStatements
  extnID_QCPolicies = '2.5.29.32'; // OID for QCPolicies


function CryptDataTypeToString(T: TCryptInfoDataType): String;
function CryptDetectDataTypePEM(const B: TBytes): TCryptInfoDataType;
function CryptDetectDataTypeDER(const B: TBytes): TCryptInfoDataType;
function CryptDetectRSAType(const B: TBytes): TCryptInfoDataType;
function CryptDetectECCurveType(const B: TBytes): TCryptInfoDataType;
function StripPEMEnvelope(const B: TBytes): TBytes;

procedure RegisterKnownRSAOIDs(out List: TArray<TBytes>);
procedure RegisterKnownECOIDs(out List: TArray<TBytes>);

implementation

uses
  Generics.Collections;

function CryptDataTypeToString(T: TCryptInfoDataType): String;
begin
  case T of
    kdtUnknown              : Result := 'unknown';
    kdtX509Certificate      : Result := 'x509-certificate';
    kdtRSAPrivate           : Result := 'rsa-private';
    kdtRSAPublic            : Result := 'rsa-public';
    kdtRSASignatureSHA1     : Result := 'sha1-with-rsa';
    kdtRSASignatureSHA256   : Result := 'sha256-with-rsa';
    kdtRSASignatureSHA384   : Result := 'sha384-with-rsa';
    kdtRSASignatureSHA512   : Result := 'sha512-with-rsa';
    kdtECPrivate            : Result := 'ec-private';
    kdtECPublic             : Result := 'ec-public';
    kdtECP256               : Result := 'secp256r1';
    kdtECP384               : Result := 'secp384r1';
    kdtECP521               : Result := 'secp521r1';
    kdtECDSASHA1            : Result := 'ecdsa-with-sha1';
    kdtECDSASHA256          : Result := 'ecdsa-with-sha256';
    kdtECDSASHA384          : Result := 'ecdsa-with-sha384';
    kdtECDSASHA512          : Result := 'ecdsa-with-sha512';
    kdtPKCS8Private         : Result := 'pkcs8-private';
    kdtPKCS8EncryptedPrivate: Result := 'pkcs8-encrypted';
    kdtPKCS12               : Result := 'pkcs12-pfx';
    kdtCSR                  : Result := 'pkcs10-csr';
  end;
end;

// Fast OID scanner that only checks for a byte subsequence.
// It is intentionally simple (no ASN.1 decoding) and returns true
// if the exact OID byte pattern appears anywhere in the buffer.
function HasOID(const B: TBytes; const O: Array of Byte): Boolean;
var
  i, j, LB, LO: Integer;
begin
  LB := Length(B);
  LO := Length(O);
  if (LB = 0) or (LO = 0) or (LB < LO) then
    Exit(False);
  for i := 0 to LB - LO do begin
    j := 0;
    while (j < LO) and (B[i + j] = O[j]) do Inc(j);
    if j = LO then
      Exit(True);
  end;
  Result := False;
end;

// Safe byte access helper: returns -1 when index out of range.
// This prevents out-of-bounds reads in subsequent checks.
function SafeByteAt(const Arr: TBytes; Index: Integer): Integer; inline;
begin
  if (Index >= 0) and (Index < Length(Arr)) then
    Result := Arr[Index]
  else
    Result := -1;
end;

function CryptDetectDataTypePEM(const B: TBytes): TCryptInfoDataType;
var
  S: String;
begin
  // --- Try detecting PEM based on well-known headers ----------------
  // Converts byte array to ASCII text for PEM header scanning.
  // Safe because PEM sections are pure ASCII.
  S := TEncoding.ASCII.GetString(B);

  // Certificate (X.509)
  if S.Contains('-----BEGIN CERTIFICATE-----') then
    Exit(kdtX509Certificate);

  // RSA private key (PKCS#1)
  if S.Contains('-----BEGIN RSA PRIVATE KEY-----') then
    Exit(kdtRSAPrivate);

  // RSA public key (PKCS#1)
  if S.Contains('-----BEGIN RSA PUBLIC KEY-----') then
    Exit(kdtRSAPublic);

  // EC private key in RFC 5915 format
  if S.Contains('-----BEGIN EC PRIVATE KEY-----') then
    Exit(kdtECPrivate);

  // Generic PKCS#8 private key
  if S.Contains('-----BEGIN PRIVATE KEY-----') then
    Exit(kdtPKCS8Private);

  // Encrypted PKCS#8 private key
  if S.Contains('-----BEGIN ENCRYPTED PRIVATE KEY-----') then
    Exit(kdtPKCS8EncryptedPrivate);

  // Public key in SPKI structure
  if S.Contains('-----BEGIN PUBLIC KEY-----') then
    Exit(kdtECPublic);

  // CSR (PKCS#10)
  if S.Contains('-----BEGIN CERTIFICATE REQUEST-----') or
     S.Contains('-----BEGIN NEW CERTIFICATE REQUEST-----') then
    Exit(kdtCSR);

  // PKCS#12 never uses PEM, usually always DER-only, so no PEM header.

  // Fall back to pure DER detection
  Result := CryptDetectDataTypeDER(B);
end;

function CryptDetectDataTypeDER(const B: TBytes): TCryptInfoDataType;
var
  // local convenience values for quick pattern checks
  b0, b1, b2, b3, b4, b5, b6: Integer;
begin
  Result := kdtUnknown;

  // minimal sanity: need at least an ASN.1 SEQUENCE header
  if Length(B) < 4 then
    Exit;
  if B[0] <> $30 then
    Exit; // many DER containers start with SEQUENCE

  // read a few bytes safely for version-like pattern matching
  b0 := SafeByteAt(B, 0);
  b1 := SafeByteAt(B, 1);
  b2 := SafeByteAt(B, 2);
  b3 := SafeByteAt(B, 3);
  b4 := SafeByteAt(B, 4);
  b5 := SafeByteAt(B, 5);
  b6 := SafeByteAt(B, 6);

  // --- X.509 CERTIFICATE ----------------------------------------
  // Look for common OIDs or attributes that appear inside certificates.
  // This is a heuristic: presence of these OIDs strongly suggests a cert.
  if (HasOID(B, [$2A, $86, $48, $86, $F7, $0D, $01, $01]) or // all rsaEncryption
      HasOID(B, [$2A, $86, $48, $CE, $3D, $04, $03])) and    // all ecdsa-with-SHA*
     HasOID(B, [$55, $04, $03]) then                         // commonName attr
    Exit(kdtX509Certificate);

  // --- RSA PRIVATE (PKCS#1) -------------------------------------
  // PKCS#1 private often contains rsaEncryption OID and version=0 in the first bytes.
  if (b4 = $02) and (b5 = $01) and (b6 = $00) and               // SEQUENCE, version=0, AlgorithmIdentifier follows
     HasOID(B, [$2A, $86, $48, $86, $F7, $0D, $01, $01, $01]) then // rsa
    Exit(kdtRSAPrivate);

  // --- RSA PUBLIC (SPKI) ---------------------------------------
  // Presence of rsaEncryption OID without PKCS#1 version pattern points to SPKI (public).
  if HasOID(B, [$2A, $86, $48, $86, $F7, $0D, $01, $01, $01]) then
    Exit(kdtRSAPublic);

  // --- PKCS#8 PRIVATE KEY ---------------------------------------
  // PrivateKeyInfo version is INTEGER 0 at specific offsets in many DER encodings.
  // Check length/indices before addressing to avoid OOB.
  if (b2 = $02) and (b3 = $01) and (b4 = $00) and                 // SEQUENCE, version=0, AlgorithmIdentifier follows
     (HasOID(B, [$2A, $86, $48, $86, $F7, $0D, $01, $01, $01]) or // rsa
      HasOID(B, [$2A, $86, $48, $CE, $3D, $02, $01])) then        // id-ecPublicKey
    Exit(kdtPKCS8Private);

  // --- ENCRYPTED PKCS#8 (PBES2) ---------------------------------
  if HasOID(B, [$2A, $86, $48, $86, $F7, $0D, $01, $05, $0D]) then
    Exit(kdtPKCS8EncryptedPrivate);

  // --- EC PRIVATE (RFC 5915) ------------------------------------
  // ECPrivateKey often encodes version=1 in the inner SEQ; look for that pattern safely.
  if (b2 = $02) and (b3 = $01) and (b4 = $01) and     // SEQUENCE, version=1, then OCTET STRING
     HasOID(B, [$2A, $86, $48, $CE, $3D, $03, $01]) then // EC curve OIDs
    Exit(kdtECPrivate);

  // --- EC PUBLIC (SPKI) -----------------------------------------
  // id-ecPublicKey OID present -> SPKI with EC public key
  if HasOID(B, [$2A, $86, $48, $CE, $3D, $02, $01]) then
    Exit(kdtECPublic);

  // --- PKCS#12 (PFX) --------------------------------------------
  if HasOID(B, [$2A, $86, $48, $86, $F7, $0D, $0C, $0A]) then
    Exit(kdtPKCS12);

  // --- PKCS#10 CSR ----------------------------------------------
  if HasOID(B, [$2A, $86, $48, $86, $F7, $0D, $01, $09, $10]) then
    Exit(kdtCSR);

  // fallback
  Result := kdtUnknown;
end;

function CryptDetectRSAType(const B: TBytes): TCryptInfoDataType;
var
  RSAOIDs: TArray<TBytes>;
  I: Integer;
begin
  Result := kdtUnknown;

  if Length(B) < 4 then
    Exit;
  if B[0] <> $30 then
    Exit; // DER SEQUENCE

  RegisterKnownRSAOIDs(RSAOIDs);

  // --- RSA checks ------------------------------------------------------------
  for I := 0 to High(RSAOIDs) do
    if HasOID(B, RSAOIDs[I]) then begin
      case I of
        0: Exit(kdtRSAPublic);         // rsaEncryption
        1: Exit(kdtRSASignatureSHA1);  // md5+rsa (legacy)
        2: Exit(kdtRSASignatureSHA1);
        3: Exit(kdtRSASignatureSHA256);
        4: Exit(kdtRSASignatureSHA384);
        5: Exit(kdtRSASignatureSHA512);
      end;
    end;
end;

function CryptDetectECCurveType(const B: TBytes): TCryptInfoDataType;
var
  ECOIDs: TArray<TBytes>;
  I: Integer;
begin
  Result := kdtUnknown;

  if Length(B) < 4 then
    Exit;
  if B[0] <> $30 then
    Exit; // DER SEQUENCE

  RegisterKnownECOIDs(ECOIDs);

  // --- EC checks -------------------------------------------------------------
  for I := 0 to High(ECOIDs) do
    if HasOID(B, ECOIDs[I]) then begin
      case I of
        0: Exit(kdtECPublic);      // id-ecPublicKey
        1: Exit(kdtECP256);
        2: Exit(kdtECP384);
        3: Exit(kdtECP521);
        4: Exit(kdtECDSASHA1);
        5: Exit(kdtECDSASHA256);
        6: Exit(kdtECDSASHA384);
        7: Exit(kdtECDSASHA512);
      end;
    end;
end;

//  This function removes all known PEM header/footer lines
//  such as:
//      -----BEGIN XXX-----
//      -----END XXX-----
//  and returns only the Base64 payload as TBytes.
//  It does NOT decode Base64 - it only removes PEM wrappers.
//  Caller may perform Base64 decode afterward.
function StripPEMEnvelope(const B: TBytes): TBytes;
var
  S, Line: String;
  Lines: TArray<String>;
  OutLines: TList<String>;
  I: Integer;
begin
  // Convert byte stream into ASCII text for line processing
  S := TEncoding.ASCII.GetString(B);

  // Split text into separate lines
  Lines := S.Replace(#13, '').Split([#10]);
  OutLines := TList<String>.Create;
  try
    for I := 0 to High(Lines) do begin
      Line := Trim(Lines[I]);

      // Skip all PEM header/footer lines
      if Line.StartsWith('-----BEGIN ') then
        Continue;
      if Line.StartsWith('-----END ') then
        Continue;

      // Skip empty lines
      if Line = '' then
        Continue;

      // Everything else is Base64 payload -> preserve it
      OutLines.Add(Line);
    end;

    // Join remaining lines and convert back to bytes
    S := String.Join('', OutLines.ToArray);
    Result := TEncoding.ASCII.GetBytes(S);
  finally
    OutLines.Free;
  end;
end;

// -----------------------------------------------------------------------------
// Known RSA OIDs
// -----------------------------------------------------------------------------
procedure RegisterKnownRSAOIDs(out List: TArray<TBytes>);
begin
  List := [
    // rsaEncryption
    [$2A,$86,$48,$86,$F7,$0D,$01,$01,$01],

    // PKCS#1 digest+RSA signatures
    [$2A,$86,$48,$86,$F7,$0D,$01,$01,$04], // md5WithRSA (rare but legacy)
    [$2A,$86,$48,$86,$F7,$0D,$01,$01,$05], // sha1WithRSA
    [$2A,$86,$48,$86,$F7,$0D,$01,$01,$0B], // sha256WithRSA
    [$2A,$86,$48,$86,$F7,$0D,$01,$01,$0C], // sha384WithRSA
    [$2A,$86,$48,$86,$F7,$0D,$01,$01,$0D]  // sha512WithRSA
  ];
end;

// -----------------------------------------------------------------------------
// Known EC OIDs (keys + curves + signatures)
// -----------------------------------------------------------------------------
procedure RegisterKnownECOIDs(out List: TArray<TBytes>);
begin
  List := [
    // id-ecPublicKey
    [$2A,$86,$48,$CE,$3D,$02,$01],

    // NIST curves
    [$2A,$86,$48,$CE,$3D,$03,$01,$07], // prime256v1 / secp256r1
    [$2B,$81,$04,$00,$22],             // secp384r1
    [$2B,$81,$04,$00,$23],             // secp521r1

    // ecdsa-with-SHAx signatures
    [$2A,$86,$48,$CE,$3D,$04,$01],        // sha1
    [$2A,$86,$48,$CE,$3D,$04,$03,$02],    // sha256
    [$2A,$86,$48,$CE,$3D,$04,$03,$03],    // sha384
    [$2A,$86,$48,$CE,$3D,$04,$03,$04]     // sha512
  ];
end;

end.

