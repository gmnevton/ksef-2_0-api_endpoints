//
// top-level signer that ties everything together
//
unit XAdESSigner;

interface

uses
  SysUtils,
  Classes,
  Windows,
  Variants,
  IOUtils,
  NetEncoding,
  MSXML,
  Crypt32_Compat,
  CNG_Compat,
  PKCS8,
  CNGSign,
  XMLCanon;

function SignXml_XAdES_BES_Enveloped(const InFile, OutFile, CertFile, PemKeyFile, PemPassword: String): Boolean; overload;
function SignXml_XAdES_BES_Enveloped(const InBytes: TBytes; out OutBytes: TBytes; CertBytes, PemKeyBytes: TBytes; PemPassword: String): Boolean; overload;

implementation

uses
  ActiveX,
  DateUtils;

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

function CreateElement(const Doc: IXMLDOMDocument; const ElementName, NamespaceURI: String): IXMLDOMElement;
begin
  Result := Doc.createElement(ElementName) as IXMLDOMElement;
  if (Length(NamespaceURI) > 0) and (Length(Result.prefix) > 0) then
    Result.setAttribute('xmlns:' + Result.prefix, NamespaceURI);
end;

function MakeElement(const Doc: IXMLDOMDocument; const Parent: IXMLDOMElement; const ElementName, NamespaceURI: String; const ElementAttrs: Array of String): IXMLDOMElement;
var
  i, len: Integer;
  name, value: String;
begin
  len := Length(ElementAttrs);
  if len mod 2 <> 0 then
    raise Exception.Create('MakeElement function expects ElementAttrs to be multiply of 2 (name / value) pairs, we got: ' + IntToStr(len) + 'elements !');
  //
  Result := CreateElement(Doc, ElementName, NamespaceURI);
  i := 0;
  while i < len do begin
    name  := ElementAttrs[i + 0];
    value := ElementAttrs[i + 1];
    //
    Result.setAttribute(name, value);
    Inc(i, 2);
  end;
  //
  if Assigned(Parent) then
    Parent.appendChild(Result);
end;

function MakeRFC2253IssuerName(const Name: CERT_NAME_BLOB): String;
var
  BufLen: DWORD;
  Blob: CERT_NAME_BLOB;
//  Encoded: TBytes;
  Flags: DWORD;
  r: AnsiString;
begin
  Result := '';
//  SetLength(Encoded, Name.cbData);
//  Move(Name.pbData^, Encoded[0], Name.cbData);

  // Prepare blob reference
  Blob.cbData := Name.cbData;
  Blob.pbData := Name.pbData;

  // Convert to RFC2253 DN
  Flags := CERT_X500_NAME_STR or CERT_NAME_STR_REVERSE_FLAG or CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG;

  BufLen := CertNameToStr(PKCS_7_ASN_ENCODING or X509_ASN_ENCODING, @Blob, Flags, Nil, 0);
  if BufLen = 0 then
    raise Exception.Create('CertNameToStr failed');

  SetLength(r, BufLen);

  CertNameToStr(PKCS_7_ASN_ENCODING or X509_ASN_ENCODING, @Blob, Flags, PWideChar(r), Length(r));

  // Trim null terminator
  Result := Trim(String(r));
end;

function AddSignedPropertiesAndReferences(Doc: IXMLDOMDocument3; const CertCtx: PCCERT_CONTEXT; SignatureEl: IXMLDOMElement; const ID, SigId, SignedPropsId: String; out SignedPropsCanonical: TBytes): IXMLDOMElement;
var
  SignedPropertiesEl,
  SignedSignaturePropertiesEl,
  signingTimeEl,
  certDigestEl,
  certEl,
  issuerSerialEl,
  certDigestNode,
  digestMethod,
  digestValue,
  X509IssuerNameEl,
  X509SerialEl: IXMLDOMElement;
  //
  issuerName: String;
  certBytes,
  digest,
  serialBytes: TBytes;
begin
  // Build QualifyingProperties and SignedProperties structure
  Result := MakeElement(Doc, SignatureEl, 'xades:QualifyingProperties', 'http://uri.etsi.org/01903/v1.3.2#', ['Id', 'QualifyingProperties-' + ID, 'Target', '#' + SigId]);

  SignedPropertiesEl := MakeElement(Doc, Nil, 'xades:SignedProperties', 'http://uri.etsi.org/01903/v1.3.2#', ['Id', SignedPropsId]); // THIS IS IMPORTANT - Parent must be Nil and Namespace set for canonicalization

  SignedSignaturePropertiesEl := MakeElement(Doc, SignedPropertiesEl, 'xades:SignedSignatureProperties', '', []);

  signingTimeEl := MakeElement(Doc, SignedSignaturePropertiesEl, 'xades:SigningTime', '', []);
  signingTimeEl.text := FormatDateTime('yyyy"-"mm"-"dd"T"hh":"nn":"ss"Z"', TTimeZone.Local.ToUniversalTime(Now));

  // SigningCertificateV2 (use SHA-256)
  //certBytes := Copy(TBytes(Pointer(CertCtx.pbCertEncoded)^), 0, CertCtx.cbCertEncoded);
  SetLength(certBytes, CertCtx.cbCertEncoded);
  Move(CertCtx.pbCertEncoded^, certBytes[0], CertCtx.cbCertEncoded);

  digest := SHA256BytesWindows(certBytes);
  SetLength(certBytes, 0);

  certDigestEl := MakeElement(Doc, SignedSignaturePropertiesEl, 'xades:SigningCertificate', '', []);
  certEl := MakeElement(Doc, certDigestEl, 'xades:Cert', '', []);

  certDigestNode := MakeElement(Doc, certEl, 'xades:CertDigest', '', []);
  digestMethod := MakeElement(Doc, certDigestNode, 'ds:DigestMethod', 'http://www.w3.org/2000/09/xmldsig#', ['Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256']);
  digestValue := MakeElement(Doc, certDigestNode, 'ds:DigestValue', 'http://www.w3.org/2000/09/xmldsig#', []);
  digestValue.text := BytesToBase64(digest, False);

  // issuerSerial
  issuerSerialEl := MakeElement(Doc, certEl, 'xades:IssuerSerial', '', []);

  //
  // ds:X509IssuerName  (RFC2253)
  // ds:X509SerialNumber
  //
  issuerName := MakeRFC2253IssuerName(CertCtx.pCertInfo.Issuer); // CertCtx.pCertInfo.Subject : ???
  X509IssuerNameEl := MakeElement(Doc, issuerSerialEl, 'ds:X509IssuerName', 'http://www.w3.org/2000/09/xmldsig#', []);
  X509IssuerNameEl.text := issuerName;

  X509SerialEl := MakeElement(Doc, issuerSerialEl, 'ds:X509SerialNumber', 'http://www.w3.org/2000/09/xmldsig#', []);
  //serialEl.text := IntToStr(CertCtx.pCertInfo.SerialNumber.dwLowDateTime); // simplistic; proper serial requires bigint handling
  serialBytes := BlobToBytes(CertCtx.pCertInfo.SerialNumber);
  ReverseBytes(serialBytes); // XAdES-BES complience
  X509SerialEl.text := BytesToDecimal(serialBytes);
  SetLength(serialBytes, 0);

  // append QualifyingProperties as an Object inside Signature later; for now return SignedProperties element for digesting
  SignedPropsCanonical := ExclusiveC14NToBytes(SignedPropertiesEl);

  Result.appendChild(SignedPropertiesEl);

  SignedPropertiesEl.removeAttribute('xmlns:xades');
  digestMethod.removeAttribute('xmlns:ds');
  digestValue.removeAttribute('xmlns:ds');
  X509IssuerNameEl.removeAttribute('xmlns:ds');
  X509SerialEl.removeAttribute('xmlns:ds');
end;

    // Build SignedInfo XML string manually (include two References: document "" and SignedProperties)
//    signedInfoXML :=
//      '<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'+ // root element if to workaround MSXML fuckery with well-formed XML and prefix parsing
//        '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'+
//          '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'+
//          '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'+
//          '<ds:Reference URI="">'+
//            '<ds:Transforms>'+
//              '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'+
//              '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'+
//            '</ds:Transforms>'+
//            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'+
//            '<ds:DigestValue>'+digestB64+'</ds:DigestValue>'+
//          '</ds:Reference>'+
//          '<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#'+SignedPropsId+'">'+
//            '<ds:Transforms>'+
//              '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'+
//            '</ds:Transforms>'+
//            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'+
//            '<ds:DigestValue>'+spDigestB64+'</ds:DigestValue>'+
//          '</ds:Reference>'+
//        '</ds:SignedInfo>';//+
//      '</root>';

    // canonicalize SignedInfo
//    tmpDoc2 := CoDOMDocument60.Create as IXMLDOMDocument3;
//    tmpDoc2.async := False;
//    tmpDoc2.preserveWhiteSpace := True;
//    tmpDoc2.setProperty('SelectionNamespaces',
//                        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
//                        'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"'
//    );
//    tmpDoc2 := Doc;

//    loaded := tmpDoc2.loadXML(signedInfoXML);
//    if not loaded then
//      raise Exception.CreateFmt('Failed to load temp XML(%.8x): %s', [tmpDoc2.parseError.errorCode, tmpDoc2.parseError.reason]);

//    ne := tmpDoc2.selectSingleNode('//ds:SignedInfo');
    //ne := ne.firstChild;

function AddSignedInfo(Doc: IXMLDOMDocument3; const CertCtx: PCCERT_CONTEXT; SignatureEl: IXMLDOMElement; const AlgOID: String; const SourceXMLDigestB64, SignedPropsId, SignedPropsDigestB64: String; out SignedInfoCanonical: TBytes): IXMLDOMElement;
var
  CanonicalizationMethodEl,
  SignatureMethodEl,
  ReferenceEl,
  TransformsEl,
  TransformEl1,
  TransformEl2,
  DigestMethodEl,
  DigestValueEl: IXMLDOMElement;
  sigMethod: String;
begin
// '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
  Result := MakeElement(Doc, SignatureEl, 'ds:SignedInfo', 'http://www.w3.org/2000/09/xmldsig#', []); // THIS IS IMPORTANT - Parent must be Nil and Namespace set for canonicalization

//   '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
//   '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
  CanonicalizationMethodEl := MakeElement(Doc, Result, 'ds:CanonicalizationMethod', '', ['Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#']);

  // ---- RSA ----
  if AlgOID = '1.2.840.113549.1.1.1' then
    sigMethod := 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
  // ---- EC ----
  else if AlgOID = '1.2.840.10045.2.1' then
    sigMethod := 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'
  else
    raise Exception.Create('Unsupported public key algorithm in certificate');

  SignatureMethodEl := MakeElement(Doc, Result, 'ds:SignatureMethod', '', ['Algorithm', sigMethod]);

//   '<ds:Reference URI="">'
//     '<ds:Transforms>'
//       '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
    //       '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">'
    //         '<ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath>'
    //       '</ds:Transform>'
//       '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
//     '</ds:Transforms>'
//     '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
//     '<ds:DigestValue>'+digestB64+'</ds:DigestValue>'
//   '</ds:Reference>'
  ReferenceEl    := MakeElement(Doc, Result,       'ds:Reference',    '', ['URI', '']);
  TransformsEl   := MakeElement(Doc, ReferenceEl,  'ds:Transforms',   '', []);
  TransformEl1   := MakeElement(Doc, TransformsEl, 'ds:Transform',    '', ['Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature']);
  TransformEl2   := MakeElement(Doc, TransformsEl, 'ds:Transform',    '', ['Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#']);
  DigestMethodEl := MakeElement(Doc, ReferenceEl,  'ds:DigestMethod', '', ['Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256']);
  DigestValueEl  := MakeElement(Doc, ReferenceEl,  'ds:DigestValue',  '', []);
  DigestValueEl.text := SourceXMLDigestB64;

//   '<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#'+SignedPropsId+'">'
//     '<ds:Transforms>'
//       '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
//     '</ds:Transforms>'
//     '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
//     '<ds:DigestValue>'+spDigestB64+'</ds:DigestValue>'
//   '</ds:Reference>'
  ReferenceEl    := MakeElement(Doc, Result,       'ds:Reference',    '', ['Type', 'http://uri.etsi.org/01903#SignedProperties', 'URI', '#' + SignedPropsId]);
  TransformsEl   := MakeElement(Doc, ReferenceEl,  'ds:Transforms',   '', []);
  TransformEl1   := MakeElement(Doc, TransformsEl, 'ds:Transform',    '', ['Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#']);
  DigestMethodEl := MakeElement(Doc, ReferenceEl,  'ds:DigestMethod', '', ['Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256']);
  DigestValueEl  := MakeElement(Doc, ReferenceEl,  'ds:DigestValue',  '', []);
  DigestValueEl.text := SignedPropsDigestB64;

  //
  SignedInfoCanonical := ExclusiveC14NToBytes(Result);

  Result.removeAttribute('xmlns:ds');
end;

function SignXml(CertCtx: PCCERT_CONTEXT; keyHandle: BCRYPT_KEY_HANDLE; const AlgOID: String; XMLBytes: TBytes; out OutBytes: TBytes): Boolean;
var
  Doc: IXMLDOMDocument3;

//  // helper
//  function MakeElement(const Name: String): IXMLDOMElement;
//  begin
//    Result := (Doc as IXMLDOMDocument).createElement(Name) as IXMLDOMElement;
//  end;

var
  XML: UTF8String;
  loaded: WordBool;
//  signedInfoXML: String;
  digestBytes,
  signedInfoCanonical,
  sigValue,
  docCanonical: TBytes;
  digestB64, sigB64: String;
  SignatureEl,
  SignedInfoEl,
  SigValueEl,
  KeyInfoEl,
  ObjectEl,
  QualPropsEl: IXMLDOMElement;
  ID,
  SignedPropsId,
  SigId: String;
//  qId,
//  SignatureID: String;
  SignedPropsCanonical: TBytes;
//  refNode: IXMLDOMNode;
  KeyContext: CERT_KEY_CONTEXT;
  nl: IXMLDOMNodeList;
//  ne: IXMLDOMNode;
  i: Integer;
  spDigest: TBytes;
  spDigestB64: String;
  //tmpDoc1, tmpDoc2: IXMLDOMDocument3;
  sigHash: TBytes;
//  tmpSignedInfo: IXMLDOMElement;
//  importedSI: IXMLDOMNode;
  X509Data: IXMLDOMElement;
  X509Cert: IXMLDOMElement;
//  importedQP: IXMLDOMNode;
  X509CertBytes: TBytes;
//  temp: String;
//  child: IXMLDOMNode;
//  importedChild: IXMLDOMNode;
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

//    temp := SerialToHex(SHA256BytesWindows(BytesOf('abc')));
//    if temp <> 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD' then
//      raise Exception.Create('SHA256 sanity check is fucked !');

    // load XML
    Doc := CoDOMDocument60.Create as IXMLDOMDocument3;
    Doc.async := False;
    Doc.preserveWhiteSpace := True;
    Doc.setProperty('SelectionNamespaces',
                    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
                    'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"'
    );

    XML := UTF8String(TEncoding.UTF8.GetString(XMLBytes));
    loaded := Doc.loadXML(XML);
    if not loaded then
      raise Exception.CreateFmt('Failed to load input XML(%.8x): %s', [Doc.parseError.errorCode, Doc.parseError.reason]);

    // remove existing Signature nodes if any (typically none existent in a xml file before signing, but someone might sign a signed xml again)
    nl := Doc.selectNodes('//ds:Signature');
    if (nl <> Nil) and (nl.length > 0) then begin
      for i := 0 to nl.length - 1 do
        if nl.item[i].parentNode <> Nil then
          nl.item[i].parentNode.removeChild(nl.item[i]);
    end;

    // compute digest of the whole source document (enveloped transform already removed signature nodes)
    docCanonical := ExclusiveC14NToBytes(Doc.documentElement);
    digestBytes := SHA256BytesWindows(docCanonical);
    digestB64 := BytesToBase64(digestBytes, False);
    //TFile.WriteAllBytes('xml_to_be_signed.xml', docCanonical);

    // build SignedProperties and QualifyingProperties
    Randomize;
    ID := IntToStr(Random(MaxInt));
    SigId := 'Signature-' + ID;
    SignedPropsId := 'SignedProps-' + ID; //IntToStr(Random(MaxInt));

    // assemble Signature element
    SignatureEl := MakeElement(Doc, Doc.documentElement, 'ds:Signature', 'http://www.w3.org/2000/09/xmldsig#', ['Id', SigId]);

    // canonicalize SignedProps
//    tmpDoc1 := CoDOMDocument60.Create as IXMLDOMDocument3;
//    tmpDoc1.async := False;
//    tmpDoc1.preserveWhiteSpace := True;
//    tmpDoc1.setProperty('SelectionNamespaces',
//                        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
//                        'xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"'
//    );
    //tmpDoc1 := Doc;
    QualPropsEl := AddSignedPropertiesAndReferences(Doc, CertCtx, Nil{SignatureEl}, ID, SigId, SignedPropsId, SignedPropsCanonical);
    //TFile.WriteAllBytes('signed_props_canonical.xml', SignedPropsCanonical);
    // compute digest of SignedProperties (already canonicalized in AddSignedPropertiesAndReferences)
    spDigest := SHA256BytesWindows(SignedPropsCanonical);
    spDigestB64 := BytesToBase64(spDigest, False);

    SignedInfoEl := AddSignedInfo(Doc, CertCtx, Nil{SignatureEl}, AlgOID, digestB64, SignedPropsId, spDigestB64, signedInfoCanonical);
    SignatureEl.appendChild(SignedInfoEl);
    //TFile.WriteAllBytes('signed_info_canonical.xml', signedInfoCanonical);
    // hash SignedInfo canonicalized
//    ReverseBytes(signedInfoCanonical);
    sigHash := SHA256BytesWindows(signedInfoCanonical);
    //TFile.WriteAllText('signed_info_canonical_hash.xml', BytesToBase64(sigHash, False));
    //MoveBytes(signedInfoCanonical, sigHash);

    // sign
    // ---- RSA ----
    if AlgOID = '1.2.840.113549.1.1.1' then begin
      sigValue := SignHashWithRSA_PKCS1(keyHandle, sigHash)
    end
    else // ---- EC ----
      if AlgOID = '1.2.840.10045.2.1' then begin
        sigValue := SignHashWithECDSA(keyHandle, sigHash);
      end
      else
        raise Exception.Create('Unsupported public key algorithm in certificate');


    sigB64 := BytesToBase64(sigValue, False);
    //TFile.WriteAllText('signed_info_canonical_signed_hash.xml', sigB64);

//    tmpSignedInfo := tmpDoc2.documentElement;
//    importedSI := Doc.importNode(tmpSignedInfo, True);
//    //SignatureEl.appendChild(importedSI);
//    //SignedInfoEl.appendChild(importedSI.firstChild);
//    child := importedSI.firstChild;
//    while child <> nil do begin
//      importedChild := Doc.importNode(child, True);
//      SignedInfoEl.appendChild(importedChild);
//      child := child.nextSibling;
//    end;

    SigValueEl := MakeElement(Doc, SignatureEl, 'ds:SignatureValue', '', ['Id', 'value-' + ID]);
    SigValueEl.text := sigB64;

    // KeyInfo with certificate
    KeyInfoEl := MakeElement(Doc, SignatureEl, 'ds:KeyInfo', '', []);
    X509Data := MakeElement(Doc, KeyInfoEl, 'ds:X509Data', '', []);
    X509Cert := MakeElement(Doc, X509Data, 'ds:X509Certificate', '', []);

    SetLength(X509CertBytes, CertCtx.cbCertEncoded);
    if CertCtx.cbCertEncoded > 0 then
      Move(CertCtx.pbCertEncoded^, X509CertBytes[0], CertCtx.cbCertEncoded);

    X509Cert.text := BytesToBase64(X509CertBytes, False);

//    X509Data.appendChild(X509Cert);
//    KeyInfoEl.appendChild(X509Data);
//    SignatureEl.appendChild(KeyInfoEl);

    // Object element containing QualifyingProperties
    ObjectEl := MakeElement(Doc, SignatureEl, 'ds:Object', '', ['Id', 'QualifyingInfos-' + ID]);

//    importedQP := Doc.importNode(QualPropsEl, True);
//    ObjectEl.appendChild(importedQP);
    ObjectEl.appendChild(QualPropsEl);
//    SignatureEl.appendChild(ObjectEl);

    // append Signature to document element
    Doc.documentElement.appendChild(SignatureEl);

    // save
    OutBytes := TEncoding.UTF8.GetBytes(Doc.xml);

    Result := True;
  finally
    SetLength(docCanonical, 0);
    SetLength(SignedPropsCanonical, 0);
    SetLength(spDigest, 0);
    SetLength(signedInfoCanonical, 0);
    SetLength(sigValue, 0);
    SetLength(X509CertBytes, 0);
  end;
end;

function SignXml_XAdES_BES_Enveloped(const InFile, OutFile, CertFile, PemKeyFile, PemPassword: String): Boolean;
var
  CertCtx: PCCERT_CONTEXT;
  keyBytes: TBytes;
  keyHandle: BCRYPT_KEY_HANDLE;
  AlgOID: String;
  InBytes: TBytes;
  OutBytes: TBytes;
begin
  CoInitialize(Nil);
  try
    // load cert
    CertCtx := LoadCertificateContext(CertFile);
    if CertCtx = Nil then
      raise Exception.Create('Failed to load certificate: ' + CertFile);

    // load & decrypt key
    keyBytes := LoadPEMBytes(PemKeyFile, PemPassword);
    if not ImportPrivateKey_CNG(keyBytes, keyHandle, AlgOID) then
      raise Exception.Create('Failed to import private key into CNG: ' + PemKeyFile);

    // load input xml
    InBytes := TFile.ReadAllBytes(InFile);
    if Length(InBytes) = 0 then
      raise Exception.Create('Failed to load XML file: ' + InFile);

    // sign
    Result := SignXml(CertCtx, keyHandle, AlgOID, InBytes, OutBytes);
    if Result then
      TFile.WriteAllBytes(OutFile, OutBytes);
  finally
    AlgOID := '';
    SetLength(inBytes, 0);
    SetLength(OutBytes, 0);
    if CertCtx <> Nil then
      CertFreeCertificateContext(CertCtx);
    if keyHandle <> 0 then
      BCryptDestroyKey(keyHandle);
    CoUninitialize;
  end;
end;

function SignXml_XAdES_BES_Enveloped(const InBytes: TBytes; out OutBytes: TBytes; CertBytes, PemKeyBytes: TBytes; PemPassword: String): Boolean;
var
  CertCtx: PCCERT_CONTEXT;
  keyBytes: TBytes;
  keyHandle: BCRYPT_KEY_HANDLE;
  AlgOID: String;
begin
  CoInitialize(Nil);
  try
    // load cert
    CertCtx := LoadCertificateContext(CertBytes);
    if CertCtx = Nil then
      raise Exception.Create('Failed to load certificate');

    // load & decrypt key
    keyBytes := LoadPEMBytes(PemKeyBytes, PemPassword);
    if not ImportPrivateKey_CNG(keyBytes, keyHandle, AlgOID) then
      raise Exception.Create('Failed to import private key into CNG');

    // sign
    Result := SignXml(CertCtx, keyHandle, AlgOID, InBytes, OutBytes);
  finally
    AlgOID := '';
    if CertCtx <> Nil then try
      CertFreeCertificateContext(CertCtx);
    except
    end;
    if keyHandle <> 0 then try
      BCryptDestroyKey(keyHandle);
    except
    end;
    CoUninitialize;
  end;
end;

end.

