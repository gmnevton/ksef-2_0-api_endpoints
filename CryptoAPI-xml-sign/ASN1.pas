//
// Minimal ASN.1 reader
//
unit ASN1;

interface

uses
  SysUtils,
  Classes,
  Windows,
  Types;

// QC (Qualified Certificate) Support
//   - Extract QC policy OIDs    (ASN1ListQCPolicies)
//   - Convert QC policy OIDs    (ASN1QCPolicyOIDToName)
//   - Determine qualification   (IsQualifiedCertificate)

type
  TASN1Reader = record
    Len,
    Pos: Integer;
    Buf: TBytes;
  end;

// QCType classifier + human-readable converter based on ETSI EN 319 412-5
type
  TQualifiedCertType = (
    qcUnknown,
    qcESign,   // Qualified Electronic Signature (QES)
    qcESeal,   // Qualified Electronic Seal (QESeal)
    qcWeb      // Qualified Web Authentication (QWAC)
  );


function ASN1Init(const B: TBytes): TASN1Reader;
procedure ASN1Free(var R: TASN1Reader);

function ASN1PosInsideBuffer(var R: TASN1Reader): Boolean; inline;
function ASN1ReadByte(var R: TASN1Reader): Byte;
function ASN1ReadLength(var R: TASN1Reader): Integer;
function ASN1PeekTag(var R: TASN1Reader): Byte;

procedure ASN1SkipNext(var R: TASN1Reader);

function ASN1ReadSeqLen(var R: TASN1Reader): Integer;
function ASN1ReadSequence(var R: TASN1Reader): TBytes;
function ASN1ReadTagAndLength(var R: TASN1Reader; out Tag: Byte; out Len: Integer): Integer;
function ASN1ReadBytes(var R: TASN1Reader; ExpectedTag: Byte): TBytes;
function ASN1ReadAny(var R: TASN1Reader; out Tag: Byte): TBytes;
function ASN1ReadInteger(var R: TASN1Reader): Int64;
function ASN1ReadIntegerBytes(var R: TASN1Reader): TBytes;
function ASN1ReadOctetString(var R: TASN1Reader): TBytes;
function ASN1ReadOctetStringRaw(var R: TASN1Reader): TBytes;
function ASN1ReadOID(var R: TASN1Reader): String;
function ASN1GetSubreader(var R: TASN1Reader): TASN1Reader;
function ASN1ParseName(var R: TASN1Reader): String;
function ASN1ReadPrintableOrUTF8(var R: TASN1Reader): String;
function ASN1ReadBitString(var R: TASN1Reader): TBytes;
function ASN1ReadTime(var R: TASN1Reader): TDateTime;
function ASN1ListExtensions(var R: TASN1Reader): TStringList;
function ASN1FindExtension(var R: TASN1Reader; const TargetOID: String): TBytes;
function ASN1ListQCStatements(const ExtValue: TBytes): TStringList;
function ASN1ListQCPolicies(const ExtValue: TBytes): TStringList;
function ASN1QCTypeOIDToName(const OID: String): String;
function ASN1ClassifyQCType(const ExtValue_QCStatements: TBytes): TQualifiedCertType;


function ASN1OIDToName(const OID: String): String;
function ASN1AttributeOIDToName(const OID: String): String;
function ASN1ParameterOIDToName(const OID: String): String;
function ASN1SignatureOIDToName(const OID: String): String;
function ASN1AlgorithmOIDToName(const OID: String): String;
function ASN1ExtensionOIDToName(const OID: String): String;
function ASN1OIDToUniversalName(const OID: string): string;
function ASN1KeyUsageToText(const ExtValue: TBytes): string;
function ASN1BasicConstraintsToText(const ExtValue: TBytes): String;
//function ASN1QCStatementsToText(const QCExtValue: TBytes; ): String;
function ASN1QCPolicyOIDToName(const OID: String): String;
function ASN1ExtractQCTypeOID(const ExtValue_QCStatements: TBytes): String;
function ASN1QCTypeToText(const T: TQualifiedCertType): String;


function ASN1IsQualifiedCertificate(const ExtList: TArray<String>; const ExtValue_QCStatements: TBytes; const ExtValue_QCPolicies: TBytes): Boolean; overload;
function ASN1IsQualifiedCertificate(const ExtList: TStringList; const ExtValue_QCStatements: TBytes; const ExtValue_QCPolicies: TBytes): Boolean; overload;
function ASN1AnalyzeQualification(const ExtValue_QCStatements: TBytes; const ExtValue_QCPolicies: TBytes): String;

// SubjectPublicKeyInfo
procedure ASN1ParseSPKI(const Raw: TBytes; var AlgOID, ParamOID: String; var PubKey: TBytes);


procedure ASN1Error(const Msg: String);
procedure ASN1ErrorFmt(const Msg: String; const Values: Array of const);

implementation

uses
  DateUtils;

procedure ASN1Error(const Msg: String);
begin
  raise Exception.Create('ASN1: ' + Msg) at ReturnAddress;
end;

procedure ASN1ErrorFmt(const Msg: String; const Values: Array of const);
begin
  raise Exception.CreateFmt('ASN1: ' + Msg, Values) at ReturnAddress;
end;

function ASN1Init(const B: TBytes): TASN1Reader;
begin
  Result.Len := Length(B);
  Result.Pos := 0;
  Result.Buf := Copy(B, 0);
end;

procedure ASN1Free(var R: TASN1Reader);
var
  len: Integer;
begin
  len := R.Len;
  if len > 0 then
    FillChar(R.Buf[0], len, 0);
  SetLength(R.Buf, 0);
  R.Len := 0;
  R.Pos := 0;
end;

function CheckBufferPos(var R: TASN1Reader; const RaiseException: Boolean = True): Boolean; inline;
begin
  Result := True;
  if R.Pos >= R.Len then
    if RaiseException then
      ASN1Error('buffer overrun')
    else
      Result := False;
end;

function ASN1PosInsideBuffer(var R: TASN1Reader): Boolean;
begin
  Result := Boolean(R.Pos <= (R.Len - 1));
end;

function ASN1ReadByte(var R: TASN1Reader): Byte;
begin
  CheckBufferPos(R);
  Result := R.Buf[R.Pos];
  Inc(R.Pos);
end;

function ASN1ReadLength(var R: TASN1Reader): Integer;
var
  b: Byte;
  i, lenBytes: Integer;
  v: Cardinal;
begin
  b := ASN1ReadByte(R);
  if (b and $80) = 0 then
    Exit(b);
  lenBytes := b and $7F;
  if lenBytes = 0 then
    ASN1Error('indefinite length not supported');
  if lenBytes > 4 then
    ASN1Error('length too large');
  //
  if not CheckBufferPos(R, False) then
    ASN1Error('ReadLength: truncated data');
  //
  v := 0;
  for i := 1 to lenBytes do begin
    if not CheckBufferPos(R, False) then
      ASN1Error('ReadLength: truncated data');
    v := (v shl 8) or ASN1ReadByte(R);
  end;
  Result := v;
end;

function ASN1PeekTag(var R: TASN1Reader): Byte;
begin
  CheckBufferPos(R);
  Result := R.Buf[R.Pos];
end;

procedure ASN1SkipNext(var R: TASN1Reader);
var
  tag: Byte;
  val: TBytes;
begin
//  ASN1SkipNext reads the next ASN.1 element (tag + length + value)
//  using ASN1ReadAny, but discards the returned value. This allows
//  callers to advance past fields (INTEGER, SEQUENCE, OID, etc.)
//  without caring about their contents.  Safe for all DER primitives
//  and constructed types because ASN1ReadAny already resolves size.

  // Read next TLV element and ignore the returned value
  val := ASN1ReadAny(R, tag);

  // Explicitly clear the buffer to avoid accidental use
  SetLength(val, 0);
end;

function ASN1ReadSeqLen(var R: TASN1Reader): Integer;
begin
  if ASN1PeekTag(R) <> $30 then
    ASN1Error('expected SEQUENCE');
  Inc(R.Pos);
  Result := ASN1ReadLength(R);
end;

function ASN1ReadSequence(var R: TASN1Reader): TBytes;
var
  tag: Byte;
  len: Integer;
  startPos: Integer;
label
  rep;
begin
  rep:
  tag := ASN1ReadByte(R);
  if tag = 0 then // 0 - NULL: skip
    goto rep;
  if tag <> $30 then
    ASN1Error('expected SEQUENCE');

  len := ASN1ReadLength(R);
  startPos := R.Pos;
  if startPos + len > R.Len then
    ASN1Error('ReadSequence: truncated data');

  SetLength(Result, len);
  if len > 0 then
    Move(R.Buf[startPos], Result[0], len);
  Inc(R.Pos, len);
end;

function ASN1ReadTagAndLength(var R: TASN1Reader; out Tag: Byte; out Len: Integer): Integer;
begin
  Tag := ASN1ReadByte(R);
  Len := ASN1ReadLength(R);
  Result := R.Pos;
end;

function ASN1ReadBytes(var R: TASN1Reader; ExpectedTag: Byte): TBytes;
var
  tag: Byte;
  len,
  startPos: Integer;
begin
  tag := ASN1ReadByte(R);
  if tag <> ExpectedTag then
    ASN1ErrorFmt('unexpected tag %02x, expected %02x', [tag, ExpectedTag]);
  len := ASN1ReadLength(R);
  startPos := R.Pos;
  if startPos + len > R.Len then
    ASN1Error('ReadBytes: truncated data');
  SetLength(Result, len);
  if len > 0 then
    Move(R.Buf[startPos], Result[0], len);
  Inc(R.Pos, len);
end;

function ASN1ReadAny(var R: TASN1Reader; out Tag: Byte): TBytes;
var
  len,
  startPos: Integer;
begin
  Tag := ASN1ReadByte(R);
  len := ASN1ReadLength(R);
  startPos := R.Pos;
  if startPos + len > R.Len then
    ASN1Error('ReadAny: truncated data');
  SetLength(Result, len);
  if len > 0 then
    Move(R.Buf[startPos], Result[0], len);
  Inc(R.Pos, len);
end;

function ASN1ReadInteger(var R: TASN1Reader): Int64;
var
  tag: Byte;
  len, i: Integer;
  v: Int64;
begin
  tag := ASN1ReadByte(R);
  if tag <> $02 then
    ASN1Error('expected INTEGER');
  len := ASN1ReadLength(R);
  if len = 0 then
    Exit(0);
  if len > 8 then
    ASN1Error('integer too large');
  v := 0;
  for i := 1 to len do begin
    if not CheckBufferPos(R, False) then
      ASN1Error('ReadInteger: truncated');
    v := (v shl 8) or ASN1ReadByte(R);
  end;
  Result := v;
end;

function ASN1ReadIntegerBytes(var R: TASN1Reader): TBytes;
var
  tag: Byte;
  val: TBytes;
begin
  val := ASN1ReadAny(R, tag);
  if tag <> $02 then
    ASN1Error('expected INTEGER');
  Result := val;
end;

function ASN1ReadOctetString(var R: TASN1Reader): TBytes;
var
  len: Integer;
  startPos: Integer;
begin
  if ASN1PeekTag(R) <> $04 then
    ASN1Error('expected OCTET STRING');
  Inc(R.Pos);
  len := ASN1ReadLength(R);
  startPos := R.Pos;
  if startPos + len > R.Len then
    ASN1Error('ReadOctet: truncated data');
  SetLength(Result, len);
  if len > 0 then
    Move(R.Buf[startPos], Result[0], len);
  Inc(R.Pos, len);
end;

function ASN1ReadOctetStringRaw(var R: TASN1Reader): TBytes;
begin
//  Many X.509 extensions wrap their actual payload inside an OCTET STRING.
//  This helper reads exactly one OCTET STRING (tag = $04) and returns
//  its inner raw bytes. It uses ASN1ReadBytes to enforce the tag.

  // Read OCTET STRING (tag $04)
  Result := ASN1ReadBytes(R, $04);
end;

function ASN1ReadOID(var R: TASN1Reader): String;
var
  tag: Byte;
  len,
  startPos,
  i: Integer;
  b,
  first,
  x: Integer;
  sb: TStringBuilder;
begin
  Result := '';
  tag := ASN1ReadByte(R);
  if tag <> $06 then
    ASN1Error('expected OID');
  len := ASN1ReadLength(R);
  if len = 0 then
    Exit;
  startPos := R.Pos;
  sb := TStringBuilder.Create;
  try
    first := R.Buf[R.Pos];
    Inc(R.Pos);
    Dec(len);
    sb.Append(IntToStr(first div 40));
    sb.Append('.');
    sb.Append(IntToStr(first mod 40));
    x := 0;
    while len > 0 do begin
      if not CheckBufferPos(R, False) then
        ASN1Error('ReadOID: truncated data');
      b := R.Buf[R.Pos];
      Inc(R.Pos);
      Dec(len);
      x := (x shl 7) or (b and $7F);
      if (b and $80) = 0 then begin
        sb.Append('.');
        sb.Append(IntToStr(x));
        x := 0;
      end;
    end;
    Result := sb.ToString;
  finally
    sb.Free;
  end;
end;

function ASN1GetSubreader(var R: TASN1Reader): TASN1Reader;
var
  tag: Byte;
  len,
  startPos: Integer;
begin
  tag := ASN1ReadByte(R);
  if (tag and $20) = 0 then
    ASN1Error('expected constructed type');
  len := ASN1ReadLength(R);
  startPos := R.Pos;
  if startPos + len > R.Len then
    ASN1Error('GetSubreader: truncated data');
  Result.Len := len;
  Result.Buf := Copy(R.Buf, startPos, len);
  Result.Pos := 0;
  Inc(R.Pos, len);
end;

function ASN1ParseName(var R: TASN1Reader): String;
var
  sb: TStringBuilder;
  seq: TBytes;
  tag: Byte;
  val: TBytes;
  inner: TASN1Reader;
  inner2: TASN1Reader;
  inner3: TASN1Reader;
  setTag: Byte;
  setVal: TBytes;
  seqTag: Byte;
  seqVal: TBytes;
  oid: String;
  sval: String;
begin
  sb := TStringBuilder.Create;
  try
    seq := ASN1ReadSequence(R);
    inner := ASN1Init(seq);
    while ASN1PosInsideBuffer(inner) do begin
      if not CheckBufferPos(inner, False) then
        ASN1Error('ParseName: truncated data');
      // RDN: SET OF SEQUENCE
      setVal := ASN1ReadAny(inner, setTag);
      if setTag <> $31 then
        ASN1Error('ParseName: expected SET in Name');
      inner2 := ASN1Init(setVal);
      while ASN1PosInsideBuffer(inner2) do begin
        if not CheckBufferPos(inner2, False) then
          ASN1Error('ParseName: truncated data');
        seqVal := ASN1ReadAny(inner2, seqTag); // SEQ
        inner3 := ASN1Init(seqVal);
        oid := ASN1ReadOID(inner3);
        sval := ASN1ReadPrintableOrUTF8(inner3);
        if sb.Length > 0 then
          sb.Append(', ');
        sb.Append(ASN1OIDToName(oid) + '=' + sval);
        ASN1Free(inner3);
      end;
      ASN1Free(inner2);
    end;
    ASN1Free(inner);
    SetLength(seq, 0);
    Result := sb.ToString;
  finally
    sb.Free;
  end;
end;

//  This updated version properly decodes both ASCII-compatible encodings
//  (PrintableString, IA5String, T61String) and UTF8String.  The previous
//  implementation incorrectly treated UTF-8 bytes as PChar, which breaks
//  on multi-byte sequences.  Here we decode ASCII-like strings using
//  TEncoding.ANSI (safe for 7-bit text) and decode UTF-8 using
//  TEncoding.UTF8.GetString.
function ASN1ReadPrintableOrUTF8(var R: TASN1Reader): String;
var
  tag: Byte;
  val: TBytes;
begin
  Result := '';
  val := ASN1ReadAny(R, tag);
  case tag of
    // PrintableString (0x13), T61String (0x14 / 0x12), IA5String (0x16):
    // These encodings are single-byte and safe to interpret via ANSI.
    $13, $12, $16: // PrintableString, T61String, IA5String
      Result := TEncoding.ANSI.GetString(val);

    // UTF8String (0x0C):
    // Must be decoded using UTF-8 decoder to handle multi-byte characters.
    $0C: // UTF8String
      Result := TEncoding.UTF8.GetString(val);
  else
    begin
      SetLength(val, 0);
      ASN1Error('expected String type');
    end;
  end;
end;

function ASN1ReadBitString(var R: TASN1Reader): TBytes;
var
  tag: Byte;
  val: TBytes;
  unused: Byte;
begin
  val := ASN1ReadAny(R, tag);
  if tag <> $03 then
    ASN1Error('Expected BIT STRING');
  if Length(val) = 0 then
    Exit(Nil);
  unused := val[0]; // 'unused' is ignored here
  if Length(val) - 1 > 0 then begin
    SetLength(Result, Length(val) - 1);
    Move(val[1], Result[0], Length(val) - 1);
  end
  else
    Result := Nil;
end;

function ASN1ReadTime(var R: TASN1Reader): TDateTime;
var
  tag: Byte;
  val: TBytes;
  len: Integer;
  S: String;
  Y, M, D, HH, MM, SS: Integer;
begin
  tag := ASN1ReadByte(R);
  len := ASN1ReadLength(R);
  SetLength(val, len);
  Move(R.Buf[R.Pos], val[0], len);
  Inc(R.Pos, len);
  SetString(S, PAnsiChar(@val[0]), len);
  if tag = $17 then begin // UTCTime
    Y := StrToInt(Copy(S, 1, 2));
    if Y >= 50 then
      Y := 1900 + Y
    else
      Y := 2000 + Y;
    M := StrToInt(Copy(S, 3, 2));
    D := StrToInt(Copy(S, 5, 2));
    HH := StrToInt(Copy(S, 7, 2));
    MM := StrToInt(Copy(S, 9, 2));
    //
    Result := EncodeDateTime(Y, M, D, HH, MM, 0, 0);
  end
  else if tag = $18 then begin // GenTime
    Y := StrToInt(Copy(S, 1, 4));
    M := StrToInt(Copy(S, 5, 2));
    D := StrToInt(Copy(S, 7, 2));
    HH := StrToInt(Copy(S, 9, 2));
    MM := StrToInt(Copy(S, 11, 2));
    SS := StrToInt(Copy(S, 13, 2));
    //
    Result := EncodeDateTime(Y, M, D, HH, MM, SS, 0);
  end
  else
    ASN1Error('unknown time tag');
end;

//  Returns a TStringList containing all extension OIDs found
//  in TBSCertificate.Extensions.  The TBSCertificate structure
//  is navigated exactly as in ASN1FindExtension, but instead of
//  returning a single extension, this function collects all extnID
//  values (OBJECT IDENTIFIER fields).  Caller must free the result.
function ASN1ListExtensions(var R: TASN1Reader): TStringList;
var
  tag: Byte;
  tbs, extSeq, extItem: TBytes;
  R_TBS, R_Ext, R_Item: TASN1Reader;
  oidStr: String;
  criticalTag: Byte;
  dummyVal: TBytes;
begin
  Result := TStringList.Create;

  // Read TBSCertificate (outer SEQUENCE)
  tbs := ASN1ReadSequence(R);
  R_TBS := ASN1Init(tbs);

  // Skip version [0] EXPLICIT if present
  if ASN1PeekTag(R_TBS) = $A0 then
    ASN1ReadAny(R_TBS, tag);

  // Skip fixed fields
  ASN1SkipNext(R_TBS); // serialNumber
  ASN1SkipNext(R_TBS); // signature
  ASN1SkipNext(R_TBS); // issuer
  ASN1SkipNext(R_TBS); // validity
  ASN1SkipNext(R_TBS); // subject
  ASN1SkipNext(R_TBS); // subjectPublicKeyInfo

  // Skip optional unique IDs ([1] and [2]) if present
  if ASN1PeekTag(R_TBS) = $81 then
    ASN1ReadAny(R_TBS, tag);
  if ASN1PeekTag(R_TBS) = $82 then
    ASN1ReadAny(R_TBS, tag);

  // Check for Extensions: [3] EXPLICIT -> tag $A3
  if ASN1PeekTag(R_TBS) <> $A3 then
    Exit; // No extensions present

  // Read [3] EXPLICIT Extensions
  extSeq := ASN1ReadAny(R_TBS, tag);    // tag should be $A3
  R_Ext := ASN1Init(extSeq);

  // Inside A3 is a SEQUENCE OF Extension
  extSeq := ASN1ReadSequence(R_Ext);    // read Extensions sequence
  R_Ext := ASN1Init(extSeq);

  // Iterate each Extension element
  while ASN1PosInsideBuffer(R_Ext) do begin
    // Each extension is a SEQUENCE
    extItem := ASN1ReadSequence(R_Ext);
    R_Item := ASN1Init(extItem);

    // extnID: OBJECT IDENTIFIER
    oidStr := ASN1ReadOID(R_Item);
    Result.Add(oidStr);

    // Optional critical flag (BOOLEAN)
    if ASN1PeekTag(R_Item) = $01 then
      dummyVal := ASN1ReadAny(R_Item, criticalTag);

    // Skip extnValue (OCTET STRING)
    dummyVal := ASN1ReadOctetStringRaw(R_Item);

    ASN1Free(R_Item);
  end;

  ASN1Free(R_Ext);
  ASN1Free(R_TBS);
end;

//  Parses QCStatements extension (1.3.6.1.5.5.7.1.3).
//  Structure:
//      QCStatements ::= SEQUENCE OF QCStatement
//      QCStatement ::= SEQUENCE {
//          statementId        OBJECT IDENTIFIER,
//          statementInfo      ANY OPTIONAL
//      }
//  This function extracts only statementId OIDs.
function ASN1ListQCStatements(const ExtValue: TBytes): TStringList;
var
  R, RSeq, RStmt: TASN1Reader;
  seqStmts, seqItem: TBytes;
  oid: String;
begin
  Result := TStringList.Create;
  if Length(ExtValue) = 0 then
    Exit;

  R := ASN1Init(ExtValue);
  seqStmts := ASN1ReadSequence(R);
  RSeq := ASN1Init(seqStmts);

  while ASN1PosInsideBuffer(RSeq) do begin
    seqItem := ASN1ReadSequence(RSeq);
    RStmt := ASN1Init(seqItem);

    // Extract statementId (OID)
    oid := ASN1ReadOID(RStmt);
    Result.Add(oid);

    ASN1Free(RStmt);
  end;

  ASN1Free(RSeq);
  ASN1Free(R);
end;

//  Parses CertificatePolicies extension (2.5.29.32).
//  Structure:
//      CertificatePolicies ::= SEQUENCE OF PolicyInformation
//      PolicyInformation ::= SEQUENCE {
//          policyIdentifier   OBJECT IDENTIFIER,
//          policyQualifiers   SEQUENCE OPTIONAL ...
//      }
//  This function extracts ONLY the policyIdentifier OID.
function ASN1ListQCPolicies(const ExtValue: TBytes): TStringList;
var
  R, RSeq, RPolicy: TASN1Reader;
  seqPolicies, seqItem: TBytes;
  tag: Byte;
  oid: String;
begin
  Result := TStringList.Create;
  if Length(ExtValue) = 0 then
    Exit;

  R := ASN1Init(ExtValue);
  // top-level: inside OCTET STRING -> SEQUENCE OF PolicyInformation
  seqPolicies := ASN1ReadSequence(R);
  RSeq := ASN1Init(seqPolicies);

  while ASN1PosInsideBuffer(RSeq) do begin
    // PolicyInformation ::= SEQUENCE
    seqItem := ASN1ReadSequence(RSeq);
    RPolicy := ASN1Init(seqItem);

    // Read policyIdentifier (OID)
    oid := ASN1ReadOID(RPolicy);
    Result.Add(oid);

    ASN1Free(RPolicy);
  end;

  ASN1Free(RSeq);
  ASN1Free(R);
end;

//  Converts QCType statement OIDs to readable short names.
//  These OIDs appear inside QCStatements extension:
//      0.4.0.1862.1.6.*   -> QcType definitions
function ASN1QCTypeOIDToName(const OID: String): String;
begin
  if OID = '0.4.0.1862.1.6.1' then Exit('Qualified Electronic Signature (ESign)');
  if OID = '0.4.0.1862.1.6.2' then Exit('Qualified Electronic Seal (ESeal)');
  if OID = '0.4.0.1862.1.6.3' then Exit('Qualified Website Authentication (QWAC)');

  Result := 'QCType (' + OID + ')';
end;

//  Reads QCStatements extension, looks specifically for
//  QCType OIDs:
//      0.4.0.1862.1.6.1 -> ESign
//      0.4.0.1862.1.6.2 -> ESeal
//      0.4.0.1862.1.6.3 -> WebAuth
//  If none match -> qcUnknown.
function ASN1ClassifyQCType(const ExtValue_QCStatements: TBytes): TQualifiedCertType;
var
  oid: string;
begin
  Result := qcUnknown;

  if Length(ExtValue_QCStatements) = 0 then
    Exit;

  oid := ASN1ExtractQCTypeOID(ExtValue_QCStatements);
  if oid = '0.4.0.1862.1.6.1' then Exit(qcESign);
  if oid = '0.4.0.1862.1.6.2' then Exit(qcESeal);
  if oid = '0.4.0.1862.1.6.3' then Exit(qcWeb);
end;

//  Converts known X.509 extension OIDs into their common human-readable
//  names.  Covers core RFC 5280 extensions, PKIX extensions, Microsoft
//  extensions, certificate transparency, QC statements, etc.  Unknown OIDs
//  are returned unchanged so the caller can still display them.
function ASN1ExtensionOIDToName(const OID: String): String;
begin
  // Basic certificate extensions (RFC 5280)
  if OID = '2.5.29.15'   then Exit('KeyUsage');
  if OID = '2.5.29.19'   then Exit('BasicConstraints');
  if OID = '2.5.29.14'   then Exit('SubjectKeyIdentifier');
  if OID = '2.5.29.35'   then Exit('AuthorityKeyIdentifier');
  if OID = '2.5.29.37'   then Exit('ExtendedKeyUsage');
  if OID = '2.5.29.17'   then Exit('SubjectAlternativeName');
  if OID = '2.5.29.18'   then Exit('IssuerAlternativeName');
  if OID = '2.5.29.31'   then Exit('CRLDistributionPoints');
  if OID = '2.5.29.32'   then Exit('CertificatePolicies');
  if OID = '2.5.29.30'   then Exit('NameConstraints');
  if OID = '2.5.29.33'   then Exit('PolicyMappings');
  if OID = '2.5.29.36'   then Exit('PolicyConstraints');
  if OID = '2.5.29.54'   then Exit('InhibitAnyPolicy');

  // Netscape / Old extensions
  if OID = '2.16.840.1.113730.1.1'    then Exit('NetscapeCertType');
  if OID = '2.16.840.1.113730.1.2'    then Exit('NetscapeBaseURL');
  if OID = '2.16.840.1.113730.1.3'    then Exit('NetscapeRevocationURL');
  if OID = '2.16.840.1.113730.1.4'    then Exit('NetscapeCARevocationURL');
  if OID = '2.16.840.1.113730.1.8'    then Exit('NetscapeCertRenewalURL');

  // PKIX / Internet extensions
  if OID = '1.3.6.1.5.5.7.1.1'        then Exit('AuthorityInfoAccess');
  if OID = '1.3.6.1.5.5.7.1.2'        then Exit('SubjectInfoAccess');
  if OID = '1.3.6.1.5.5.7.48.1'       then Exit('OCSP');
  if OID = '1.3.6.1.5.5.7.48.2'       then Exit('CAIssuers');

  // Certificate Transparency
  if OID = '1.3.6.1.4.1.11129.2.4.2'  then Exit('SignedCertificateTimestampList');

  // Microsoft extensions
  if OID = '1.3.6.1.4.1.311.21.1'     then Exit('MS-CA-Cert-Template');
  if OID = '1.3.6.1.4.1.311.21.2'     then Exit('MS-CA-CrossCertDist');
  if OID = '1.3.6.1.4.1.311.21.7'     then Exit('MS-Certificate-Template');
  if OID = '1.3.6.1.4.1.311.20.2'     then Exit('MS-SmartCard-Logon');
  if OID = '1.3.6.1.4.1.311.10.3.4'   then Exit('MS-EncryptingFileSystem');
  if OID = '1.3.6.1.4.1.311.10.3.1'   then Exit('MS-ServerGatedCrypto');

  // QC statements (Qualified Certificates)
  if OID = '0.4.0.1862.1.1'           then Exit('QC-Compliance');
  if OID = '0.4.0.1862.1.2'           then Exit('QC-SSCD');
  if OID = '0.4.0.1862.1.3'           then Exit('QC-Qualified');
  if OID = '0.4.0.1862.1.4'           then Exit('QC-RetentionPeriod');

  // Common accessDescriptions
  if OID = '1.3.6.1.5.5.7.48.5'       then Exit('TimeStamping');
  if OID = '1.3.6.1.5.5.7.48.3'       then Exit('SigningAuthority');

  // EV Policy OIDs (examples)
  if OID = '2.23.140.1.1'             then Exit('EV-Guidelines');
  if OID = '2.23.140.1.2.1'           then Exit('EV-CA-Policy');

  // If no match found -> return raw OID
  Result := OID;
end;

// Locate a certificate extension by OID within TBSCertificate.Extensions.
// Returns ExtValue (raw OCTET STRING contents) or empty TBytes if not found.
function ASN1FindExtension(var R: TASN1Reader; const TargetOID: String): TBytes;
var
  tag: Byte;
  tbs, extSeq, extItem, oidBytes, octetVal: TBytes;
  R_TBS, R_Ext, R_Item: TASN1Reader;
  oidStr: string;
  criticalTag: Byte;
  criticalVal: TBytes;
begin
//  The input reader R must point at the beginning of TBSCertificate.
//  This function walks through TBSCertificate fields until it finds
//  the [3] EXPLICIT Extensions block, then scans each Extension SEQUENCE.
//  For each extension it reads:
//      extnID (OID)
//      critical (BOOLEAN, optional)
//      extnValue (OCTET STRING)
//  and returns extnValue for the matching OID.

  Result := Nil;

  // Read TBSCertificate (outer SEQUENCE)
  tbs := ASN1ReadSequence(R);
  R_TBS := ASN1Init(tbs);

  // Skip version [0] EXPLICIT if present
  if ASN1PeekTag(R_TBS) = $A0 then
    ASN1ReadAny(R_TBS, tag);

  // Skip serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  ASN1SkipNext(R_TBS); // serialNumber
  ASN1SkipNext(R_TBS); // signature
  ASN1SkipNext(R_TBS); // issuer
  ASN1SkipNext(R_TBS); // validity
  ASN1SkipNext(R_TBS); // subject
  ASN1SkipNext(R_TBS); // subjectPublicKeyInfo

  // Skip optional unique IDs ([1] and [2]) if encountered
  if ASN1PeekTag(R_TBS) = $81 then
    ASN1ReadAny(R_TBS, tag);
  if ASN1PeekTag(R_TBS) = $82 then
    ASN1ReadAny(R_TBS, tag);

  // Check for Extensions: [3] EXPLICIT ? tag $A3
  if ASN1PeekTag(R_TBS) <> $A3 then
    Exit(Nil);

  // Read [3] EXPLICIT Extensions
  extSeq := ASN1ReadAny(R_TBS, tag);    // tag = $A3
  R_Ext := ASN1Init(extSeq);

  // Inside A3 is a SEQUENCE OF Extension
  extSeq := ASN1ReadSequence(R_Ext);
  R_Ext := ASN1Init(extSeq);

  // Iterate each Extension element
  while ASN1PosInsideBuffer(R_Ext) do begin
    // Each item is a SEQUENCE
    extItem := ASN1ReadSequence(R_Ext);
    R_Item := ASN1Init(extItem);

    // extnID: OBJECT IDENTIFIER
    oidStr := ASN1ReadOID(R_Item);

    // critical flag may or may not be present
    if ASN1PeekTag(R_Item) = $01 then begin
      criticalVal := ASN1ReadAny(R_Item, criticalTag);
      // we do not use critical flag here
    end;

    // extnValue: OCTET STRING containing encoded extension value
    octetVal := ASN1ReadOctetStringRaw(R_Item);

    // match OID
    if SameText(oidStr, TargetOID) then begin
      Result := octetVal;
      ASN1Free(R_Item);
      Exit;
    end;

    ASN1Free(R_Item);
  end;

  // nothing found
  Result := Nil;
end;

// Converts OID String (e.g. '2.5.4.6') into a readable X.509 name (e.g. 'C').
// Supports common RDN attributes: C, O, OU, CN, L, ST, SN, etc.
function ASN1OIDToName(const OID: String): String;
begin
//  This function maps known X.509 AttributeType OIDs to their
//  human-readable abbreviations. These are standard RDN identifiers
//  used inside Distinguished Names in certificates.
//  Any unknown OID is returned unchanged, allowing flexible fallback.

  if OID = '2.5.4.6'   then Exit('C');            // countryName
  if OID = '2.5.4.10'  then Exit('O');            // organizationName
  if OID = '2.5.4.11'  then Exit('OU');           // organizationalUnitName
  if OID = '2.5.4.3'   then Exit('CN');           // commonName
  if OID = '2.5.4.7'   then Exit('L');            // localityName
  if OID = '2.5.4.8'   then Exit('ST');           // stateOrProvinceName
  if OID = '2.5.4.5'   then Exit('SerialNumber'); // serialNumber
  if OID = '2.5.4.9'   then Exit('Street');       // streetAddress
  if OID = '2.5.4.4'   then Exit('SN');           // surname
  if OID = '2.5.4.42'  then Exit('GivenName');    // givenName
  if OID = '2.5.4.12'  then Exit('Title');        // title
  if OID = '2.5.4.46'  then Exit('DNQualifier');  // dnQualifier
  if OID = '2.5.4.65'  then Exit('Pseudonym');    // pseudonym

  // emailAddress (from PKCS#9, not X.509 core)
  if OID = '1.2.840.113549.1.9.1' then Exit('emailAddress');

  // domainComponent (dc)
  if OID = '0.9.2342.19200300.100.1.25' then Exit('DC');

  // if unknown, return raw OID
  Result := OID;
end;

//  Converts attribute OIDs into their standard human-readable short names.
//  These OIDs appear in Subject, Issuer, certificate requests, PKCS#9
//  attributes, directory strings, etc.  Includes the full RFC 5280 set,
//  PKCS#9 extensions, and common LDAP attribute mappings.
function ASN1AttributeOIDToName(const OID: String): String;
begin
  // X.520 / RFC 5280 Name attributes
  if OID = '2.5.4.6'    then Exit('C');              // countryName
  if OID = '2.5.4.10'   then Exit('O');              // organizationName
  if OID = '2.5.4.11'   then Exit('OU');             // organizationalUnitName
  if OID = '2.5.4.3'    then Exit('CN');             // commonName
  if OID = '2.5.4.7'    then Exit('L');              // localityName
  if OID = '2.5.4.8'    then Exit('ST');             // stateOrProvinceName
  if OID = '2.5.4.5'    then Exit('serialNumber');   // serialNumber
  if OID = '2.5.4.4'    then Exit('SN');             // surname
  if OID = '2.5.4.12'   then Exit('Title');          // title
  if OID = '2.5.4.42'   then Exit('GivenName');      // givenName
  if OID = '2.5.4.43'   then Exit('Initials');       // initials
  if OID = '2.5.4.17'   then Exit('PostalCode');     // postalCode
  if OID = '2.5.4.9'    then Exit('Street');         // streetAddress
  if OID = '2.5.4.46'   then Exit('dnQualifier');    // dnQualifier
  if OID = '2.5.4.65'   then Exit('Pseudonym');      // pseudonym
  if OID = '2.5.4.20'   then Exit('TelephoneNumber');

  // Domain Component (dc)
  if OID = '0.9.2342.19200300.100.1.25' then Exit('DC');

  // Userid (UID)
  if OID = '0.9.2342.19200300.100.1.1'  then Exit('UID');

  // Email address (PKCS#9)
  if OID = '1.2.840.113549.1.9.1'       then Exit('emailAddress');

  // PKCS#9 attributes
  if OID = '1.2.840.113549.1.9.2'       then Exit('unstructuredName');
  if OID = '1.2.840.113549.1.9.3'       then Exit('contentType');
  if OID = '1.2.840.113549.1.9.4'       then Exit('messageDigest');
  if OID = '1.2.840.113549.1.9.5'       then Exit('signingTime');
  if OID = '1.2.840.113549.1.9.7'       then Exit('challengePassword');
  if OID = '1.2.840.113549.1.9.8'       then Exit('unstructuredAddress');

  // Rare/LDAP attributes
  if OID = '2.5.4.18'                   then Exit('PostOfficeBox');
  if OID = '2.5.4.19'                   then Exit('PhysicalDeliveryOfficeName');
  if OID = '2.5.4.23'                   then Exit('FacsimileTelephoneNumber');
  if OID = '2.5.4.41'                   then Exit('Name');
  if OID = '2.5.4.45'                   then Exit('UniqueIdentifier');

  // If unknown, return raw OID
  Result := OID;
end;

function ASN1ParameterOIDToName(const OID: String): String;
begin
  // EC curve parameters
  if OID = '1.2.840.10045.3.1.7'   then Exit('prime256v1 (secp256r1)');
  if OID = '1.3.132.0.34'          then Exit('secp384r1');
  if OID = '1.3.132.0.35'          then Exit('secp521r1');
  if OID = '1.3.132.0.10'          then Exit('secp256k1');
  if OID = '1.3.132.0.33'          then Exit('secp224r1');
  if OID = '1.3.132.0.32'          then Exit('secp224k1');

  // RSA OAEP / RSA-PSS hashing and masks
  if OID = '1.2.840.113549.1.1.8'  then Exit('MGF1');
  if OID = '1.2.840.113549.1.1.9'  then Exit('PSourceAlgorithm');

  // Hash algorithms (used in PSS, OAEP, CMS)
  if OID = '1.3.14.3.2.26'         then Exit('SHA-1');
  if OID = '2.16.840.1.101.3.4.2.1' then Exit('SHA-256');
  if OID = '2.16.840.1.101.3.4.2.2' then Exit('SHA-384');
  if OID = '2.16.840.1.101.3.4.2.3' then Exit('SHA-512');
  if OID = '2.16.840.1.101.3.4.2.4' then Exit('SHA-224');

  // DH parameters
  if OID = '1.2.840.113549.1.3.1'  then Exit('DH');
  if OID = '1.3.14.3.2.22'         then Exit('DHpublicnumber');

  // EdDSA
  if OID = '1.3.101.112'           then Exit('Ed25519');
  if OID = '1.3.101.113'           then Exit('Ed448');

  // AES PBES2 / encrypted private key params
  if OID = '2.16.840.1.101.3.4.1.2'  then Exit('AES-128-CBC');
  if OID = '2.16.840.1.101.3.4.1.22' then Exit('AES-192-CBC');
  if OID = '2.16.840.1.101.3.4.1.42' then Exit('AES-256-CBC');
  if OID = '1.2.840.113549.1.5.12'   then Exit('PBKDF2');

  // Fallback -> raw OID
  Result := OID;
end;

//  Converts all commonly used *signature algorithm* OIDs into
//  human-readable names.  Signature OIDs differ from key-algorithm OIDs:
//    - RSA signing vs RSA key OIDs
//    - ECDSA variants for SHA2
//    - DSA signatures
//    - EdDSA signatures
//    - RSASSA-PSS and newer schemes
//  Unknown OIDs fall back to raw OID.
function ASN1SignatureOIDToName(const OID: String): String;
begin
  // RSA PKCS#1 v1.5 signatures
  if OID = '1.2.840.113549.1.1.4'  then Exit('md5WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.5'  then Exit('sha1WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.11' then Exit('sha256WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.12' then Exit('sha384WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.13' then Exit('sha512WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.14' then Exit('sha224WithRSAEncryption');

  // RSA-PSS signatures
  if OID = '1.2.840.113549.1.1.10' then Exit('RSASSA-PSS');

  // ECDSA signatures
  if OID = '1.2.840.10045.4.1'     then Exit('ecdsa-with-SHA1');
  if OID = '1.2.840.10045.4.3.1'   then Exit('ecdsa-with-SHA224');
  if OID = '1.2.840.10045.4.3.2'   then Exit('ecdsa-with-SHA256');
  if OID = '1.2.840.10045.4.3.3'   then Exit('ecdsa-with-SHA384');
  if OID = '1.2.840.10045.4.3.4'   then Exit('ecdsa-with-SHA512');

  // DSA signatures
  if OID = '1.2.840.10040.4.3'     then Exit('dsa-with-sha1');
  if OID = '2.16.840.1.101.3.4.3.1' then Exit('dsa-with-sha224');
  if OID = '2.16.840.1.101.3.4.3.2' then Exit('dsa-with-sha256');
  if OID = '2.16.840.1.101.3.4.3.3' then Exit('dsa-with-sha384');
  if OID = '2.16.840.1.101.3.4.3.4' then Exit('dsa-with-sha512');

  // EdDSA signatures
  if OID = '1.3.101.112'           then Exit('ed25519');
  if OID = '1.3.101.113'           then Exit('ed448');

  // GOST signatures (optional, widely used in EU / CIS)
  if OID = '1.2.643.2.2.3'         then Exit('gost3410-signature');
  if OID = '1.2.643.7.1.1.3.2'     then Exit('gost3410-2012-256-signature');
  if OID = '1.2.643.7.1.1.3.3'     then Exit('gost3410-2012-512-signature');

  // ECDSA generic (rare)
  if OID = '1.2.840.10045.4.4'     then Exit('ecdsa-with-Specified');

  // Return unknown as raw
  Result := OID;
end;

//  Maps all commonly used public-key and private-key algorithm OIDs
//  (RSA, DSA, EC, EdDSA, DH, PKCS variants, signature schemes) to
//  human-friendly names.  Unknown OIDs fall back to returning the raw
//  numeric OID string so the caller still displays something meaningful.
function ASN1AlgorithmOIDToName(const OID: String): String;
begin
  // RSA family
  if OID = '1.2.840.113549.1.1.1'  then Exit('RSA');
  if OID = '1.2.840.113549.1.1.5'  then Exit('sha1WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.11' then Exit('sha256WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.12' then Exit('sha384WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.13' then Exit('sha512WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.14' then Exit('sha224WithRSAEncryption');
  if OID = '1.2.840.113549.1.1.10' then Exit('RSASSA-PSS');
  if OID = '1.2.840.113549.1.1.7'  then Exit('RSAES-OAEP');

  // DSA
  if OID = '1.2.840.10040.4.1'     then Exit('DSA');
  if OID = '1.2.840.10040.4.3'     then Exit('sha1WithDSA');
  if OID = '2.16.840.1.101.3.4.3.2' then Exit('sha384WithDSA');
  if OID = '2.16.840.1.101.3.4.3.3' then Exit('sha512WithDSA');

  // EC (Elliptic Curve)
  if OID = '1.2.840.10045.2.1'     then Exit('EC');
  if OID = '1.2.840.10045.4.1'     then Exit('ecdsa-with-SHA1');
  if OID = '1.2.840.10045.4.3.2'   then Exit('ecdsa-with-SHA256');
  if OID = '1.2.840.10045.4.3.3'   then Exit('ecdsa-with-SHA384');
  if OID = '1.2.840.10045.4.3.4'   then Exit('ecdsa-with-SHA512');

  // EC curves (ANSI-NIST / SECG)
  if OID = '1.2.840.10045.3.1.7'   then Exit('prime256v1 (secp256r1)');
  if OID = '1.3.132.0.34'          then Exit('secp384r1');
  if OID = '1.3.132.0.35'          then Exit('secp521r1');
  if OID = '1.3.132.0.10'          then Exit('secp256k1');

  // Diffie-Hellman
  if OID = '1.2.840.113549.1.3.1'  then Exit('DH');
  if OID = '1.3.14.3.2.22'         then Exit('DHpublicnumber');

  // EdDSA (modern signature algorithms)
  if OID = '1.3.101.112'           then Exit('Ed25519');
  if OID = '1.3.101.113'           then Exit('Ed448');

  // X25519 / X448 key exchange
  if OID = '1.3.101.110'           then Exit('X25519');
  if OID = '1.3.101.111'           then Exit('X448');

  // PKCS#8 private key wrappers
  if OID = '1.2.840.113549.1.5.13' then Exit('PBES2');
  if OID = '1.2.840.113549.1.5.12' then Exit('PBKDF2');
  if OID = '1.2.840.113549.1.5.3'  then Exit('PBE-SHA1-DES-CBC');
  if OID = '1.2.840.113549.1.5.10' then Exit('PBE-SHA1-RC2-128');
  if OID = '1.2.840.113549.1.5.11' then Exit('PBE-SHA1-RC2-40');
  if OID = '1.2.840.113549.1.5.6'  then Exit('PBE-MD5-DES-CBC');
  if OID = '1.2.840.113549.1.5.9'  then Exit('PBE-MD5-RC2-64');

  // AES encryption OIDs (commonly used in PKCS#8 encrypted keys)
  if OID = '2.16.840.1.101.3.4.1.2'  then Exit('AES-128-CBC');
  if OID = '2.16.840.1.101.3.4.1.22' then Exit('AES-192-CBC');
  if OID = '2.16.840.1.101.3.4.1.42' then Exit('AES-256-CBC');

  // SHA hash OIDs
  if OID = '1.3.14.3.2.26'         then Exit('SHA-1');
  if OID = '2.16.840.1.101.3.4.2.1' then Exit('SHA-256');
  if OID = '2.16.840.1.101.3.4.2.2' then Exit('SHA-384');
  if OID = '2.16.840.1.101.3.4.2.3' then Exit('SHA-512');
  if OID = '2.16.840.1.101.3.4.2.4' then Exit('SHA-224');

  // If nothing matched, return OID unchanged
  Result := OID;
end;

//  This dispatcher attempts to classify any incoming OID.  It tries:
//    1. Attribute OIDs (C, O, CN, email, etc.)
//    2. Extension OIDs (KeyUsage, SAN, etc.)
//    3. Algorithm OIDs (RSA, EC, etc.)
//    4. Signature OIDs (ecdsa-with-SHA256, etc.)
//  First match wins.  Unknown values fall back to raw OID text.
function ASN1OIDToUniversalName(const OID: string): string;
var
  s: string;
begin
  // Attribute OIDs
  s := ASN1AttributeOIDToName(OID);
  if s <> OID then Exit(s);

  // Parameter OIDs
  s := ASN1ParameterOIDToName(OID);
  if s <> OID then Exit(s);

  // Extension OIDs
  s := ASN1ExtensionOIDToName(OID);
  if s <> OID then Exit(s);

  // Algorithm OIDs (public/private keys)
  s := ASN1AlgorithmOIDToName(OID);
  if s <> OID then Exit(s);

  // Signature algorithm OIDs
  s := ASN1SignatureOIDToName(OID);
  if s <> OID then Exit(s);

  // Nothing matched -> return raw OID
  Result := OID;
end;

//  Converts the raw KeyUsage extension value (extnValue inside the
//  Extension SEQUENCE) into human-readable flag names.  ExtValue must be
//  the raw OCTET STRING payload from ASN1FindExtension.  Inside that
//  OCTET STRING is a BIT STRING containing the usage mask.  This function
//  decodes the BIT STRING and maps each bit to its standard X.509 meaning.
function ASN1KeyUsageToText(const ExtValue: TBytes): string;
var
  R: TASN1Reader;
  bs: TBytes;
  unusedBits: Integer;
  b0, b1: Byte;
  L: TStringList;
begin
  Result := '';
  if Length(ExtValue) = 0 then
    Exit;

  // Initialize sub-reader for the OCTET STRING content
  R := ASN1Init(ExtValue);

  // Inside OCTET STRING -> BIT STRING
  bs := ASN1ReadBitString(R);          // strips unused-bits byte for you
  unusedBits := 0;                     // not used when using ASN1ReadBitString

  if Length(bs) = 0 then
    Exit('');

  // First byte holds the first 8 KeyUsage flags
  b0 := bs[0];

  // If more bytes exist, second byte holds decipherOnly
  if Length(bs) > 1 then
    b1 := bs[1]
  else
    b1 := 0;

  L := TStringList.Create;
  try
    // BIT 0 -> digitalSignature
    if (b0 and $80) <> 0 then L.Add('digitalSignature');

    // BIT 1 -> nonRepudiation / contentCommitment
    if (b0 and $40) <> 0 then L.Add('nonRepudiation');

    // BIT 2 -> keyEncipherment
    if (b0 and $20) <> 0 then L.Add('keyEncipherment');

    // BIT 3 -> dataEncipherment
    if (b0 and $10) <> 0 then L.Add('dataEncipherment');

    // BIT 4 -> keyAgreement
    if (b0 and $08) <> 0 then L.Add('keyAgreement');

    // BIT 5 -> keyCertSign
    if (b0 and $04) <> 0 then L.Add('keyCertSign');

    // BIT 6 -> cRLSign
    if (b0 and $02) <> 0 then L.Add('cRLSign');

    // BIT 7 -> encipherOnly
    if (b0 and $01) <> 0 then L.Add('encipherOnly');

    // BIT 8 -> decipherOnly (in second byte)
    if (b1 and $80) <> 0 then L.Add('decipherOnly');

    Result := StringReplace(Trim(L.Text), sLineBreak, ', ', [rfReplaceAll]);
  finally
    L.Free;
  end;
end;

//  Converts the ASN.1 BasicConstraints extension into a readable string.
//  ExtValue must be the raw OCTET STRING payload extracted from the
//  certificate extension (via ASN1FindExtension).  The structure is:
//
//      BasicConstraints ::= SEQUENCE {
//          cA            BOOLEAN DEFAULT FALSE,
//          pathLenConstraint   INTEGER OPTIONAL
//      }
//
//  This function decodes the SEQUENCE and returns strings like:
//      'CA: FALSE'
//      'CA: TRUE'
//      'CA: TRUE, pathLen: 0'
//      'CA: TRUE, pathLen: 3'
function ASN1BasicConstraintsToText(const ExtValue: TBytes): String;
var
  R, RInner: TASN1Reader;
  seq: TBytes;
  tag: Byte;
  caFlag: Boolean;
  pathLen: Int64;
  hasCAFlag, hasPathLen: Boolean;
begin
  Result := '';
  if Length(ExtValue) = 0 then
    Exit;

  // Initialize reader for the OCTET STRING content
  R := ASN1Init(ExtValue);

  // Inside OCTET STRING: a SEQUENCE containing boolean + optional integer
  seq := ASN1ReadSequence(R);
  RInner := ASN1Init(seq);

  caFlag := False;
  hasCAFlag := False;
  hasPathLen := False;
  pathLen := -1;

  // If next tag is BOOLEAN -> CA flag present
  if ASN1PosInsideBuffer(RInner) and (ASN1PeekTag(RInner) = $01) then begin
    hasCAFlag := True;
    caFlag := (ASN1ReadAny(RInner, tag)[0] <> 0);
  end;

  // If next tag is INTEGER -> pathLen present
  if ASN1PosInsideBuffer(RInner) and (ASN1PeekTag(RInner) = $02) then begin
    hasPathLen := True;
    pathLen := ASN1ReadInteger(RInner);
  end;

  // Build human-readable result
  if hasCAFlag then begin
    if caFlag then
      Result := 'CA: TRUE'
    else
      Result := 'CA: FALSE';
  end
  else
    Result := 'CA: FALSE';  // default per RFC

  if hasPathLen then
    Result := Result + ', pathLen: ' + IntToStr(pathLen);
end;

//function ASN1QCStatementsToText(const ExtValue: TBytes): String;
//var
//  QCStmt: TStringList;
//  QCPol: TStringList;
//begin
//  Result := '';
//  if Length(ExtValue) = 0 then
//    Exit;
//
//  QCStmt := ASN1ListQCStatements(ExtValue: TBytes);
//  QCPol  := ASN1ListQCPolicies(ExtValue: TBytes);
//
//  Result := ASN1AnalyzeQualification();
//end;

//  Maps known Qualified Certificate policy OIDs (ETSI EN 319 412-5)
//  to human-readable labels.  These originate from CertificatePolicies
//  extension (2.5.29.32).  Unknown OIDs are returned unchanged.
function ASN1QCPolicyOIDToName(const OID: String): String;
begin
  // ETSI QC Policies (eIDAS)
  if OID = '0.4.0.194112.1.1' then Exit('NCP (Normalised Certificate Policy)');
  if OID = '0.4.0.194112.1.2' then Exit('QWAC (Qualified Web Authentication Certificate)');
  if OID = '0.4.0.194112.1.3' then Exit('QES Signature (Qualified Electronic Signature)');
  if OID = '0.4.0.194112.1.4' then Exit('QES Seal (Qualified Electronic Seal)');
  if OID = '0.4.0.194112.1.5' then Exit('QCert for Electronic Time Stamps');
  if OID = '0.4.0.194112.1.6' then Exit('QCStmts Extension (ETSI)');

  // QCStatements statement type indicators
  if OID = '0.4.0.1862.1.1' then Exit('QcCompliance');
  if OID = '0.4.0.1862.1.4' then Exit('QcSSCD (QSCD/Qualified device)');
  if OID = '0.4.0.1862.1.6' then Exit('QcType');
  if OID = '0.4.0.1862.1.6.1' then Exit('QcType-ESign');
  if OID = '0.4.0.1862.1.6.2' then Exit('QcType-ESeal');
  if OID = '0.4.0.1862.1.6.3' then Exit('QcType-Web');

  Result := OID;
end;

//  This extracts the inner QCType OID from QCStatements extension.
//  Structure:
//      QCStatements ::= SEQUENCE OF QCStatement
//      QCStatement ::= SEQUENCE {
//          statementId   OBJECT IDENTIFIER,
//          statementInfo ANY OPTIONAL
//      }
//
//  For QcType:
//    statementId   = 0.4.0.1862.1.6
//    statementInfo = SEQUENCE OF OBJECT IDENTIFIER (the actual QcType)
//                     -> 0.4.0.1862.1.6.1 / .2 / .3
function ASN1ExtractQCTypeOID(const ExtValue_QCStatements: TBytes): String;
var
  R, RSeq, RStmt, RInfo: TASN1Reader;
  seqStmts, seqStmt, seqInfo: TBytes;
  oid: String;
begin
  Result := '';

  if Length(ExtValue_QCStatements) = 0 then
    Exit;

  // Parse QCStatements SEQUENCE
  R := ASN1Init(ExtValue_QCStatements);
  seqStmts := ASN1ReadSequence(R);
  RSeq := ASN1Init(seqStmts);

  while ASN1PosInsideBuffer(RSeq) do begin
    seqStmt := ASN1ReadSequence(RSeq);
    RStmt := ASN1Init(seqStmt);

    // Read statementId
    oid := ASN1ReadOID(RStmt);

    // Check if this is QcType container
    if oid = '0.4.0.1862.1.6' then begin
      // Must read optional statementInfo (SEQUENCE OF OIDs)
      if ASN1PosInsideBuffer(RStmt) then begin
        seqInfo := ASN1ReadSequence(RStmt);
        RInfo := ASN1Init(seqInfo);

        // First OID is actual QCType value
        if ASN1PosInsideBuffer(RInfo) then
          Result := ASN1ReadOID(RInfo);

        ASN1Free(RInfo);
      end;

      ASN1Free(RStmt);
      Break;
    end;

    ASN1Free(RStmt);
  end;

  ASN1Free(RSeq);
  ASN1Free(R);
end;

//  Converts the QcType enum to a simple human-readable name.
function ASN1QCTypeToText(const T: TQualifiedCertType): String;
begin
  case T of
    qcESign: Result := 'Qualified Electronic Signature (ESign)';
    qcESeal: Result := 'Qualified Electronic Seal (ESeal)';
    qcWeb:   Result := 'Qualified Web Authentication (QWAC)';
  else
    Result := 'Unknown or Not Qualified';
  end;
end;

//  Determines whether certificate is "qualified" under eIDAS.
//  Uses multiple indicators for reliability:
//    1) QCStatements extension exists
//    2) QCCompliance statement OID present
//    3) Policy OID inside 0.4.0.194112 subtree
//    4) QcType or QcSSCD statements present
//  Caller must provide:
//    ExtList – list of all extension OIDs from certificate
//    ExtValue_QCPolicies – raw OCTET STRING for CertificatePolicies
//    ExtValue_QCStatements – raw OCTET STRING for QCStatements
function ASN1IsQualifiedCertificate(const ExtList: TArray<String>; const ExtValue_QCStatements: TBytes; const ExtValue_QCPolicies: TBytes): Boolean;
var
  List: TStringList;
begin
  List := TStringList.Create;
  try
    List.Text := String.Join(sLineBreak, ExtList);
    Result := ASN1IsQualifiedCertificate(List, ExtValue_QCStatements, ExtValue_QCPolicies);
  finally
    List.Free;
  end;
end;

function ASN1IsQualifiedCertificate(const ExtList: TStringList; const ExtValue_QCStatements: TBytes; const ExtValue_QCPolicies: TBytes): Boolean;
var
  policies, qcstmts: TStringList;
  i: Integer;
  oid: String;
begin
  Result := False;

  // --- 1) QCStatements extension present ---
  if ExtList.IndexOf('1.3.6.1.5.5.7.1.3') >= 0 then
    Result := True;

  // --- 2) Check QCStatements content ---
  qcstmts := ASN1ListQCStatements(ExtValue_QCStatements);
  try
    for i := 0 to qcstmts.Count - 1 do begin
      oid := qcstmts[i];

      if oid = '0.4.0.1862.1.1' then Result := True;   // QcCompliance
      if oid = '0.4.0.1862.1.4' then Result := True;   // QcSSCD
      if oid.StartsWith('0.4.0.1862.1.6') then Result := True; // QcType*
    end;
  finally
    qcstmts.Free;
  end;

  // --- 3) Check CertificatePolicies for ETSI QC Policies ---
  policies := ASN1ListQCPolicies(ExtValue_QCPolicies);
  try
    for i := 0 to policies.Count - 1 do begin
      oid := policies[i];

      // All eIDAS QC policies start with 0.4.0.194112
      if oid.StartsWith('0.4.0.194112') then begin
        Result := True;
        Break;
      end;
    end;
  finally
    policies.Free;
  end;
end;

//  This function performs a complete analysis of certificate “qualification”
//  according to ETSI EN 319 412-5 and eIDAS rules.
function ASN1AnalyzeQualification(const ExtValue_QCStatements: TBytes; const ExtValue_QCPolicies: TBytes): String;
var
  Policies, QCStmts: TStringList;
  i: Integer;
  OID, Txt: string;
  IsQualified, IsQSCD: Boolean;
  QcType: TQualifiedCertType;
begin
//  It inspects:
//    1) QCStatements extension
//    2) QCCompliance, QcType, QcSSCD flags
//    3) Certificate Policies extension
//    4) QCType classification (ESign, ESeal, QWAC)
//
//  Output is a multi-line human-readable text block summarizing:
//    - Qualification status
//    - QCType class
//    - QSCD device status
//    - QCStatements list
//    - QCPolicies list

  Result := '';
  IsQualified := False;
  IsQSCD := False;

  // --- Read QCStatements ---
  QCStmts := ASN1ListQCStatements(ExtValue_QCStatements);
  try
    // QCCompliance
    if QCStmts.IndexOf('0.4.0.1862.1.1') >= 0 then
      IsQualified := True;

    // QSCD indicator
    if QCStmts.IndexOf('0.4.0.1862.1.4') >= 0 then begin
      IsQualified := True;
      IsQSCD := True;
    end;

    // QCType indicator
    QcType := qcUnknown;
    if QCStmts.IndexOf('0.4.0.1862.1.6') >= 0 then begin
      IsQualified := True;
      // QCType -> classify type (ESign / ESeal / Web)
      QcType := ASN1ClassifyQCType(ExtValue_QCStatements);
    end;

    // QCType also counts as qualifying evidence
    if QcType <> qcUnknown then
      IsQualified := True;
  finally
    QCStmts.Free;
  end;

  // --- Read QC Policies (CertificatePolicies) ---
  Policies := ASN1ListQCPolicies(ExtValue_QCPolicies);
  try
    for i := 0 to Policies.Count - 1 do begin
      OID := Policies[i];

      // All eIDAS QC policies begin with 0.4.0.194112
      if OID.StartsWith('0.4.0.194112') then begin
        IsQualified := True;
        Break;
      end;
    end;
  finally
    Policies.Free;
  end;

  // --- Now build the result text ---
  Result := Result +
    'Qualification analysis:' + sLineBreak +
    '------------------------------------' + sLineBreak;

  // Qualification status
  if IsQualified then
    Result := Result + 'Qualified Certificate: YES' + sLineBreak
  else
    Result := Result + 'Qualified Certificate: NO' + sLineBreak;

  // QCType classification
  Result := Result +
    'QCType: ' + ASN1QCTypeToText(QcType) + sLineBreak;

  // QSCD device status
  if IsQSCD then
    Result := Result + 'QSCD Device: YES (Qualified device)' + sLineBreak
  else
    Result := Result + 'QSCD Device: NO' + sLineBreak;

  // QCStatements list (human-readable)
  QCStmts := ASN1ListQCStatements(ExtValue_QCStatements);
  try
    if QCStmts.Count > 0 then  begin
      Result := Result + sLineBreak + 'QCStatements:' + sLineBreak;
      for i := 0 to QCStmts.Count - 1 do begin
        OID := QCStmts[i];
        //Txt := ASN1QCPolicyOIDToName(OID);
        if OID = '0.4.0.1862.1.6' then begin
          Txt := 'QCType';
          Result := Result + ' - ' + Txt + ' (' + OID + ')' + sLineBreak;
          OID := ASN1ExtractQCTypeOID(ExtValue_QCStatements);
          Result := Result + '    - '+ ASN1QCTypeOIDToName(OID) + ' (' + OID + ')' + sLineBreak;;
        end
        else begin
          Txt := ASN1ExtensionOIDToName(OID);
          Result := Result + ' - ' + Txt + ' (' + OID + ')' + sLineBreak;
        end;
      end;
    end;
  finally
    QCStmts.Free;
  end;

  // QCPolicies list (human-readable)
  Policies := ASN1ListQCPolicies(ExtValue_QCPolicies);
  try
    if Policies.Count > 0 then begin
      Result := Result + sLineBreak + 'QCPolicies:' + sLineBreak;
      for i := 0 to Policies.Count - 1 do begin
        OID := Policies[i];
        Txt := ASN1QCPolicyOIDToName(OID);
        Result := Result + ' - ' + Txt + ' (' + OID + ')' + sLineBreak;
      end;
    end;
  finally
    Policies.Free;
  end;
end;

// SubjectPublicKeyInfo
procedure ASN1ParseSPKI(const Raw: TBytes; var AlgOID, ParamOID: String; var PubKey: TBytes);
var
  RawR: TASN1Reader;
  Seq: TBytes;
  SeqR: TASN1Reader;
begin
  RawR := ASN1Init(Raw);
  Seq := ASN1ReadSequence(RawR);
  SeqR := ASN1Init(Seq);
  AlgOID := ASN1ReadOID(SeqR);
  if ASN1PosInsideBuffer(SeqR) then
    ParamOID := ASN1ReadOID(SeqR)
  else
    ParamOID := '';
  PubKey := ASN1ReadBitString(RawR);
  ASN1Free(SeqR);
  ASN1Free(RawR);
end;

end.

