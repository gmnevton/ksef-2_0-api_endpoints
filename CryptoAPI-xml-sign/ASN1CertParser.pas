unit ASN1CertParser;

interface

uses
  SysUtils,
  Classes,
  Types,
  IOUtils,
  NetEncoding;

type
  TCertInfo = record
    Version: Integer;
    SerialNumberHex: String;
    Issuer: String;
    Subject: String;
    NotBefore: TDateTime;
    NotAfter: TDateTime;
    SigAlgOID: String;
    PubKeyAlgOID: String;
    PubKeyParamsOID: String; // e.g. curve OID for EC
    PublicKeyBytes: TBytes;  // BIT STRING payload (04|X|Y or compressed)
    ECPub_X: TBytes;         // if EC -> X coordinate (big-endian)
    ECPub_Y: TBytes;         // if EC -> Y coordinate (big-endian); empty if compressed not decompressed
    KeyUsage: String;
    BasicConstraints: String;
    QCStatements: TBytes; // is there Qualified Certificate Statements extension ??
    QCPolicies: TBytes;   // is there Certificate Policies extension ??
    Extensions: TArray<String>;
    RawDER: TBytes;
  end;

function ParseCertificateFromDER(const DER: TBytes): TCertInfo;
function ParseCertificateFromFile(const FileName: String): TCertInfo;
function ParseCertificateFromXMLFile(const XMLFileName: String): TCertInfo;

implementation

uses
  DateUtils,
  ASN1,
  Crypt32_Compat,
  Crypt32_Info;

function DecodeUTCTimeStr(const S: String): TDateTime;
var
  Y, M, D, hh, mm, ss: Word;
begin
  if Length(S) < 10 then
    ASN1Error('Bad UTCTime');
  Y := StrToInt(Copy(S, 1, 2));
  if Y >= 50 then
    Y := 1900 + Y
  else
    Y := 2000 + Y;
  M := StrToInt(Copy(S, 3, 2));
  D := StrToInt(Copy(S, 5, 2));
  hh := StrToInt(Copy(S, 7, 2));
  mm := StrToInt(Copy(S, 9, 2));
  ss := 0;
  if Length(S) >= 12 then
    ss := StrToInt(Copy(S, 11, 2));
  Result := EncodeDateTime(Y, M, D, hh, mm, ss, 0);
end;

function DecodeGenTimeStr(const S: String): TDateTime;
begin
  if Length(S) < 14 then
    ASN1Error('Bad GeneralizedTime');
  Result := EncodeDateTime(
    StrToInt(Copy(S, 1,  4)),
    StrToInt(Copy(S, 5,  2)),
    StrToInt(Copy(S, 7,  2)),
    StrToInt(Copy(S, 9,  2)),
    StrToInt(Copy(S, 11, 2)),
    StrToInt(Copy(S, 13, 2)),
    0
  );
end;

procedure ParseSubjectPublicKeyInfo(const Data: TBytes; out AlgOID, ParamsOID: String; out PubKeyBytes: TBytes);
var
  R, S, T: TASN1Reader;
  seq: TBytes;
  algSeq: TBytes;
  tag: Byte; val: TBytes;
  afterAlgP: Integer;
begin
  R := ASN1Init(Data);
  seq := ASN1ReadSequence(R);
  // parse algorithm sequence
  S := ASN1Init(seq);
  algSeq := ASN1ReadSequence(S);
  T := ASN1Init(algSeq);
  AlgOID := ASN1ReadOID(T);
  if T.Pos <= High(T.Buf) then
    ParamsOID := ASN1ReadOID(T)
  else
    ParamsOID := '';
  // remaining in outer seq is BIT STRING
  PubKeyBytes := ASN1ReadBitString(S);
  ASN1Free(R);
  ASN1Free(S);
  ASN1Free(T);
end;

procedure DecompressECPointIfNeeded(const CurveOID: String; const PubKeyBytes: TBytes; out X, Y: TBytes);
var
  KeySize: Integer;
begin
  // only handle uncompressed 04|X|Y here; compressed points return X and empty Y
  if (Length(PubKeyBytes) >= 1) and (PubKeyBytes[0] = $04) then begin
    KeySize := (Length(PubKeyBytes) - 1) div 2;
    SetLength(X, KeySize);
    SetLength(Y, KeySize);
    Move(PubKeyBytes[1], X[0], KeySize);
    Move(PubKeyBytes[1 + KeySize], Y[0], KeySize);
  end
  else if (Length(PubKeyBytes) >= 1) and (PubKeyBytes[0] in [$02, $03]) then begin
    SetLength(X, Length(PubKeyBytes) - 1);
    Move(PubKeyBytes[1], X[0], Length(X));
    SetLength(Y, 0); // not decompressed here
  end
  else begin
    SetLength(X, 0);
    SetLength(Y, 0);
  end;
end;

//function ParseCertificateFromDER(const DER: TBytes): TCertInfo;
//var
//  cert: TCertInfo;
//  R: TASN1Reader;
//  tag: Byte;
//  seqVal, tbsVal, algVal, sigVal, tmp: TBytes;
//  seqValR, tbsValR, algValR: TASN1Reader;
//  maybeTag: Byte;
//  v: TBytes;
//  serialRaw: TBytes;
//  issuerSeq, subjectSeq, validitySeq, spkiSeq: TBytes;
//  issuerSeqR, subjectSeqR, validitySeqR, spkiSeqR: TASN1Reader;
//  spkiAlgOID, spkiParams: String;
//begin
//  cert.RawDER := DER;
//  R := ASN1Init(DER);
//  // Read outer certificate SEQUENCE
//  seqVal := ASN1ReadAny(R, tag);
//  if tag <> $30 then
//    ASN1Error('Certificate: expected SEQUENCE');
//  // tbsCertificate (SEQUENCE)
//  seqValR := ASN1Init(seqVal);
//  tbsVal := ASN1ReadAny(seqValR, tag);
//  if tag <> $30 then
//    ASN1Error('Certificate: expected tbs SEQUENCE');
//  // optional version [0] EXPLICIT
//  tbsValR := ASN1Init(tbsVal);
//  if ASN1PosInsideBuffer(tbsValR) and (ASN1PeekTag(tbsValR) = $A0) then begin
//    tmp := ASN1ReadAny(tbsValR, tag); // [0] wrapper
//    SetLength(tmp, 0);
//    // inside tmp is INTEGER version - ignore
//  end;
//  // Serial number
//  serialRaw := ASN1ReadIntegerBytes(tbsValR);
//  cert.SerialNumberHex := BytesToHex(serialRaw);
//  // signature algorithm sequence (skip detailed parsing here)
//  algVal:= ASN1ReadAny(tbsValR, tag);
//  // algVal is SEQUENCE; extract OID inside
//  algValR := ASN1Init(algVal);
//  tmp := ASN1ReadAny(algValR, tag); // tag should be SEQUENCE/ or might be direct OID - handle both
//  // Try reading OID from algVal directly
//  try
//    cert.SigAlgOID := ASN1ReadOID(algValR);
//  except
//    cert.SigAlgOID := '';
//  end;
//  // Issuer
//  issuerSeq := ASN1ReadAny(tbsValR, tag);
//  if tag <> $30 then
//    ASN1Error('Issuer expected SEQUENCE');
//  issuerSeqR := ASN1Init(issuerSeq);
//  cert.Issuer := ASN1ParseName(issuerSeqR);
//  ASN1Free(issuerSeqR);
//  // Validity
//  validitySeq := ASN1ReadAny(tbsValR, tag );
//  if tag <> $30 then
//    ASN1Error('Validity expected SEQUENCE');
//  // notBefore
//  validitySeqR := ASN1Init(validitySeq);
//  tag := ASN1PeekTag(validitySeqR);
//  if tag = $17 then // UTCTime
//    cert.NotBefore := DecodeUTCTimeStr(ASN1ReadPrintableOrUTF8(validitySeqR))
//  else if tag = $18 then
//    cert.NotBefore := DecodeGenTimeStr(ASN1ReadPrintableOrUTF8(validitySeqR))
//  else
//    ASN1Error('unknown notBefore time');
//  // notAfter
//  tag := ASN1PeekTag(validitySeqR);
//  if tag = $17 then
//    cert.NotAfter := DecodeUTCTimeStr(ASN1ReadPrintableOrUTF8(validitySeqR))
//  else if tag = $18 then
//    cert.NotAfter := DecodeGenTimeStr(ASN1ReadPrintableOrUTF8(validitySeqR))
//  else
//    ASN1Error('unknown notAfter time');
//  ASN1Free(validitySeqR);
//  // Subject
//  subjectSeq := ASN1ReadAny(tbsValR, tag);
//  if tag <> $30 then
//    ASN1Error('Subject expected SEQUENCE');
//  subjectSeqR := ASN1Init(subjectSeq);
//  cert.Subject := ASN1ParseName(subjectSeqR);
//  ASN1Free(subjectSeqR);
//  // SubjectPublicKeyInfo
//  spkiSeq := ASN1ReadAny(tbsValR, tag);
//  if tag <> $30 then
//    ASN1Error('SPKI expected SEQUENCE');
//  spkiSeqR := ASN1Init(spkiSeq);
//  ParseSubjectPublicKeyInfo(spkiSeq, cert.PubKeyAlgOID, cert.PubKeyParamsOID, cert.PublicKeyBytes);
//  DecompressECPointIfNeeded(cert.PubKeyParamsOID, cert.PublicKeyBytes, cert.ECPub_X, cert.ECPub_Y);
//  ASN1Free(spkiSeqR);
//  Result := cert;
//end;

//  TBSCertificate ::= SEQUENCE { // A0
//      version         [0] EXPLICIT Version DEFAULT v1,
//      serialNumber            INTEGER,
//      signature               AlgorithmIdentifier,
//      issuer                  Name,
//      validity                Validity,
//      subject                 Name,
//      subjectPublicKeyInfo    SubjectPublicKeyInfo,
//      ...
//  }

//  30 82 02 5D       SEQUENCE (605 bytes)
//     A0 03          [0] EXPLICIT (3 bytes)
//        02 01 02    INTEGER 2 - version 2 ==> X.509 version 3 certificate

// example
//  49, 11,
//    48, 9,
//      06, 3, 85, 4, 6,
//      19, 2, 80, 76,
//  49, 31,
//    48, 29,
//      06, 3, 85, 4, 10,
//      12, 22, 77,105,110,105,115,116,101,114,115,116,119,111,32,70,105,110,97,110,115,195,179,119,
//  49, 39,
//    48, 37,
//      06, 3, 85, 4, 11,
//      12, 30, 75,114,97,106,111,119,97,32,65,100,109,105,110,105,115,116,114,97,99,106,97,32,83,107,97,114,98,111,119,97,
//  49, 22,
//    48, 20,
//      06, 3, 85, 4, 3,
//      12, 13, 84,69,83,84,32,67,67,75,32,75,83,101,70

//  Decoded meanings (TLV → semantic):
//  49 (0x31) = SET (one RDN)
//    11 = length 11
//    48 (0x30) = SEQUENCE (RDN: SEQ of AttributeTypeAndValue)
//      9 = length 9
//      06 03 55 04 06 = OID 2.5.4.6 -> countryName (C)
//      19 02 50 4C = PrintableString length 2 -> ASCII P L -> "PL"
//
//  Next RDN:
//  31 1F = SET length 31
//    30 1D = SEQUENCE length 29
//      06 03 55 04 0A = OID 2.5.4.10 -> organizationName (O)
//      0C 16 = UTF8String length 22
//      Bytes: 77 105 110 105 115 116 101 114 115 116 119 111 32 70 105 110 97 110 115 195 179 119
//      UTF-8 decode -> "Ministerstwo Finansów" (195,179 = ó)
//
//  Next RDN:
//  31 27 = SET length 39
//    30 25 = SEQUENCE length 37
//      06 03 55 04 0B = OID 2.5.4.11 -> organizationalUnitName (OU)
//      0C 1E = UTF8String length 30
//      Bytes decode -> "Krajowa Administracja Skarbowa"
//
//  Next RDN:
//  31 16 = SET length 22
//    30 14 = SEQUENCE length 20
//      06 03 55 04 03 = OID 2.5.4.3 -> commonName (CN)
//      0C 0D = UTF8String length 13
//      Bytes decode -> "TEST CCK KSeF"

function ParseCertificateFromDER(const DER: TBytes): TCertInfo;
var
  C: TCertInfo;
  R: TASN1Reader;
  tag, len: Byte;
  CertSeq,
  Tbs,
  SigAlg,
  SigVal,
  AlgInner,
  Valid,
  Spki: TBytes;
  CertSeqR,
  TbsR,
  AlgInnerR,
  ValidR: TASN1Reader;
  serial: TBytes;
  temp_bytes: TBytes;
  KS: Integer;
  extensions: TStringList;
  i: Integer;
  temp: String;
begin
  C.RawDER := Copy(DER, 0);
  R := ASN1Init(DER);

  CertSeq := ASN1ReadSequence(R);
  CertSeqR := ASN1Init(CertSeq);

  Tbs    := ASN1ReadSequence(CertSeqR);
  SigAlg := ASN1ReadSequence(CertSeqR);
  SigVal := ASN1ReadBitString(CertSeqR);

  TbsR := ASN1Init(Tbs);
  if ASN1ReadByte(TbsR) <> $A0 then
    ASN1Error('expected TBS certificate SEQUENCE');

  len := ASN1ReadByte(TbsR);
  C.Version := ASN1ReadInteger(TbsR);

  serial := ASN1ReadIntegerBytes(TbsR);
  C.SerialNumberHex := BytesToHex(serial);

  AlgInner := ASN1ReadSequence(TbsR);
  AlgInnerR := ASN1Init(AlgInner);
  C.SigAlgOID := ASN1ReadOID(AlgInnerR);

  C.Issuer := ASN1ParseName(TbsR);

  Valid := ASN1ReadSequence(TbsR);
  ValidR := ASN1Init(Valid);
  C.NotBefore := ASN1ReadTime(ValidR);
  C.NotAfter  := ASN1ReadTime(ValidR);

  C.Subject := ASN1ParseName(TbsR);

  Spki := ASN1ReadSequence(TbsR); // SubjectPublicKeyInfo
  ASN1ParseSPKI(Spki, C.PubKeyAlgOID, C.PubKeyParamsOID, C.PublicKeyBytes);
  DecompressECPointIfNeeded(C.PubKeyParamsOID, C.PublicKeyBytes, C.ECPub_X, C.ECPub_Y);

  CertSeqR.Pos := 0;
  temp_bytes := ASN1FindExtension(CertSeqR, extnID_KeyUsage);
  C.KeyUsage := ASN1KeyUsageToText(temp_bytes);
  SetLength(temp_bytes, 0);

  CertSeqR.Pos := 0;
  temp_bytes := ASN1FindExtension(CertSeqR, extnID_BasicConstraints);
  C.BasicConstraints := ASN1BasicConstraintsToText(temp_bytes);
  SetLength(temp_bytes, 0);

  CertSeqR.Pos := 0;
  C.QCStatements := ASN1FindExtension(CertSeqR, extnID_QCStatements);

  CertSeqR.Pos := 0;
  C.QCPolicies := ASN1FindExtension(CertSeqR, extnID_QCPolicies);

  CertSeqR.Pos := 0;
  extensions := ASN1ListExtensions(CertSeqR);
  try
    C.Extensions := extensions.ToStringArray;
  finally
    extensions.Free;
  end;
  ASN1Free(R);

  SetLength(CertSeq, 0);
  SetLength(Tbs, 0);
  SetLength(SigAlg, 0);
  SetLength(SigVal, 0);
  SetLength(AlgInner, 0);
//  SetLength(Iss, 0);
  SetLength(Valid, 0);
//  SetLength(Subj, 0);
  SetLength(Spki, 0);
  SetLength(serial, 0);
  ASN1Free(CertSeqR);
  ASN1Free(TbsR);
  ASN1Free(AlgInnerR);
//  ASN1Free(IssR);
  ASN1Free(ValidR);
//  ASN1Free(SubjR);

  Result := C;
end;

function ParseCertificateFromFile(const FileName: String): TCertInfo;
begin
  Result := ParseCertificateFromDER(TFile.ReadAllBytes(FileName));
end;

function ExtractBase64FromXML(const XMLFileName: String): TBytes;
var
  s: String;
  startTag, endTag: Integer;
  b64: String;
begin
  s := TFile.ReadAllText(XMLFileName, TEncoding.UTF8);
  //
  startTag := Pos('<X509Certificate>', s);
  if startTag = 0 then
    startTag := Pos('<ds:X509Certificate>', s);
  if startTag = 0 then
    ASN1Error('X509Certificate tag not found in XML');
  startTag := startTag + Length('<X509Certificate>');
  //
  endTag := Pos('</X509Certificate>', s);
  if endTag = 0 then
    endTag := Pos('</ds:X509Certificate>', s);
  if endTag = 0 then
    ASN1Error('X509Certificate end tag not found');
  //
  b64 := Trim(Copy(s, startTag, endTag - startTag));
  Result := TNetEncoding.Base64.DecodeStringToBytes(b64);
  s := '';
  b64 := '';
end;

function ParseCertificateFromXMLFile(const XMLFileName: String): TCertInfo;
begin
  Result := ParseCertificateFromDER(ExtractBase64FromXML(XMLFileName));
end;

end.

