unit uMain;

interface

uses
  System.SysUtils,
  System.Classes,
  Vcl.Controls,
  Vcl.StdCtrls,
  Vcl.ExtCtrls,
  Vcl.Forms,
  Vcl.Dialogs,
  CryptoAPI_XAdESSign;

type
  TForm1 = class(TForm)
    edCertFile: TLabeledEdit;
    edKeyFile: TLabeledEdit;
    edKeyPass: TLabeledEdit;
    edXMLFile: TLabeledEdit;
    edXMLFileOut: TLabeledEdit;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    Button5: TButton;
    OpenDialog1: TOpenDialog;
    OpenDialog2: TOpenDialog;
    OpenDialog3: TOpenDialog;
    SaveDialog1: TSaveDialog;
    Label1: TLabel;
    Label2: TLabel;
    edCertInfo: TMemo;
    edKeyInfo: TMemo;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure edKeyPassChange(Sender: TObject);
  private
    xades: TXAdESSign;
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

uses
  IOUtils,
  NetEncoding,
  StrUtils,
  ASN1,
  ASN1CertParser,
  ASN1KeyParser,
  PKCS8,
  CNGSign,
  Crypt32_Compat,
  Crypt32_Info;

function IfThen(const Cond: Boolean; IfTrue: String; IfFalse: String = ''): String;
begin
  if Cond then
    Result := IfTrue
  else
    Result := IfFalse;
end;

procedure PrintCertInfo(const SL: TStrings; const C: TCertInfo);
var
  i: Integer;
  qc: Boolean;
begin
  SL.Add('Cert DER len: ' + IntToStr(Length(C.RawDER)));
  SL.Add('Serial:               ' + C.SerialNumberHex);
  SL.Add('Issuer:               ' + C.Issuer);
  SL.Add('Subject:              ' + C.Subject);
  SL.Add('NotBefore:            ' + DateTimeToStr(C.NotBefore));
  SL.Add('NotAfter:             ' + DateTimeToStr(C.NotAfter));
  SL.Add('KeyUsage:             ' + C.KeyUsage);
  SL.Add('BasicConstraints:     ' + C.BasicConstraints);
  qc := ASN1IsQualifiedCertificate(C.Extensions, C.QCStatements, C.QCPolicies);
  SL.Add('QualifiedCertificate: ' + IfThen(qc, 'YES', 'NO'));
  if qc then begin
    SL.Add('');
    SL.Add(ASN1AnalyzeQualification(C.QCStatements, C.QCPolicies));
  end;
  SL.Add('');
  SL.Add('SignatureAlgorithm:   ' + C.SigAlgOID + IfThen(not SameText(C.SigAlgOID, ASN1SignatureOIDToName(C.SigAlgOID)), ' : ' + ASN1SignatureOIDToName(C.SigAlgOID)));
  SL.Add('PubKeyAlgorithm:      ' + C.PubKeyAlgOID + IfThen(not SameText(C.PubKeyAlgOID, ASN1AlgorithmOIDToName(C.PubKeyAlgOID)), ' : ' + ASN1AlgorithmOIDToName(C.PubKeyAlgOID)));
  SL.Add('PubKeyParam:          ' + C.PubKeyParamsOID + IfThen(not SameText(C.PubKeyParamsOID, ASN1OIDToUniversalName(C.PubKeyParamsOID)), ' : ' + ASN1OIDToUniversalName(C.PubKeyParamsOID)));
  SL.Add('PubKeyBytes(len): ' + IntToStr(Length(C.PublicKeyBytes)));
  if Length(C.ECPub_X) > 0 then begin
    SL.Add('EC X (hex):           ' + BytesToHex(C.ECPub_X));
    if Length(C.ECPub_Y) > 0 then
      SL.Add('EC Y (hex):           ' + BytesToHex(C.ECPub_Y))
    else
      SL.Add('EC Y: (probably compressed or not decompressed)');
  end
  else
    SL.Add('No EC public point extracted.');
  SL.Add('');
  SL.Add('Extensions:           ' + IntToStr(Length(C.Extensions)));
  for i := 0 to High(C.Extensions) do
    SL.Add('  ' + C.Extensions[i] + IfThen(not SameText(C.Extensions[i], ASN1ExtensionOIDToName(C.Extensions[i])), ' : ' + ASN1ExtensionOIDToName(C.Extensions[i])));
end;

procedure ExtractInfoFromCert(const SL: TStrings; const B: TBytes);
var
  DER: TBytes;
  Temp: String;
  Decoded: TBytes;
  CertInfo: TCertInfo;
begin
  Temp := ReplaceStr(ReplaceStr(Temp, #13, ''), #10, ''); // remove line ends
  DER := StripPEMEnvelope(B);
  Temp := TEncoding.ASCII.GetString(DER);
  SetLength(DER, 0);
  Decoded := TNetEncoding.Base64.DecodeStringToBytes(Temp);
  Temp := '';
  CertInfo := ParseCertificateFromDER(Decoded);
  SetLength(Decoded, 0);
  PrintCertInfo(SL, CertInfo);
end;

procedure ExtractInfoFromKey(const SL: TStrings; const B: TBytes; DataType: TCryptInfoDataType; const KeyPass: String);
var
  Password: String; // change this
  Encrypted, Decrypted: TBytes;

  R: TASN1Reader;
  tag: Byte;
  seqLen: Integer;
  Version: Int64;
  KeySize: Integer;
  FPrivateKeyEncrypted: Boolean;

  Temp: String;
  DER: TBytes;
  i: Integer;

  key_info: TPrivateKeyInfo;
begin
  FPrivateKeyEncrypted := False;
  Temp := TEncoding.ASCII.GetString(B);
  i := Pos('-----BEGIN ENCRYPTED PRIVATE KEY-----', Temp);
  if i = 1 then begin
    FPrivateKeyEncrypted := True;
    Password := KeyPass;
    Password := Trim(Password);
    if Length(Password) = 0 then begin
      SL.Add('Empty password not allowed !!!');
      Exit;
    end;
  end;
  Temp := '';
  DER := StripPEMEnvelope(B);
  Temp := TEncoding.ASCII.GetString(DER);
  SetLength(DER, 0);
  Encrypted := TNetEncoding.Base64.DecodeStringToBytes(Temp);

  if FPrivateKeyEncrypted then begin
    SL.Add('Decrypting PKCS#8...');
    try
      Decrypted := DecryptEncryptedPKCS8(Encrypted, Password);
    except
      on E: Exception do begin
        SL.Add(E.ClassName + ': ' + E.Message);
        Exit;
      end;
    end;
  end
  else
    Decrypted := Encrypted;
  SetLength(Encrypted, 0);

  case DataType of
    kdtRSAPrivate,
    kdtRSAPublic,
    kdtECPrivate,
    kdtECPublic: begin
      key_info := ParsePrivateKeyFromPKCS8DER(Decrypted);
      SL.Add('');
      SL.Add('Public/Private KeyInfo');
      SL.Add('Key DER len: ' + IntToStr(Length(key_info.RawDER)));
      SL.Add('AlgOID:         ' + ASN1AlgorithmOIDToName(key_info.AlgOID) + ' (' + key_info.AlgOID + ')');
      SL.Add('CurveOID:       ' + ASN1AlgorithmOIDToName(key_info.CurveOID) + ' (' + key_info.CurveOID + ')');
      SL.Add('Scalar D (hex): ' + BytesToHex(key_info.D));
      SL.Add('Public X (hex): ' + BytesToHex(key_info.Pub_X));
      SL.Add('Public Y (hex): ' + BytesToHex(key_info.Pub_Y));
    end;
    kdtPKCS8Private,
    kdtPKCS8EncryptedPrivate: begin
      key_info := ParsePrivateKeyFromPKCS8DER(Decrypted);
      SL.Add('');
      SL.Add('PKCS#8 Public/Private KeyInfo');
      SL.Add('Key DER len: ' + IntToStr(Length(key_info.RawDER)));
      SL.Add('AlgOID:         ' + ASN1AlgorithmOIDToName(key_info.AlgOID) + ' (' + key_info.AlgOID + ')');
      SL.Add('CurveOID:       ' + ASN1AlgorithmOIDToName(key_info.CurveOID) + ' (' + key_info.CurveOID + ')');
      SL.Add('Scalar D (hex): ' + BytesToHex(key_info.D));
      SL.Add('Public X (hex): ' + BytesToHex(key_info.Pub_X));
      SL.Add('Public Y (hex): ' + BytesToHex(key_info.Pub_Y));
    end;
  end;
end;

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
begin
  xades := TXAdESSign.Create;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  xades.Free;
end;

procedure TForm1.FormShow(Sender: TObject);
begin
//
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  xml: UTF8String;
begin
  xades.LoadPublicKeyCertificate(edCertFile.Text);
  xades.LoadPrivateKey(edKeyFile.Text);
  xades.PrivateKeyEncryptionPassword := edKeyPass.Text;
  xml := TFile.ReadAllText(edXMLFile.Text);
  xades.XMLToSign := xml;
  if xades.Sign then begin
    TFile.WriteAllText(edXMLFileOut.Text, xades.SignedXML, TEncoding.UTF8);
    ShowMessage('Plik "' + ExtractFileName(edXMLFile.Text) + '" podpisano.');
  end
  else
    MessageDlg('B³¹d w trakcie podpisywania pliku "' + ExtractFileName(edXMLFile.Text) + '" !.', mtError, [mbOK], 0);
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
  if OpenDialog1.Execute then begin
    edCertFile.Text := OpenDialog1.FileName;
  end;
end;

procedure TForm1.Button3Click(Sender: TObject);
begin
  if OpenDialog2.Execute then begin
    edKeyFile.Text := OpenDialog2.FileName;
  end;
end;

procedure TForm1.Button4Click(Sender: TObject);
begin
  if OpenDialog3.Execute then begin
    edXMLFile.Text := OpenDialog3.FileName;
    edXMLFileOut.Text := edXMLFile.Text + '.xades';
  end;
end;

procedure TForm1.Button5Click(Sender: TObject);
begin
  if SaveDialog1.Execute then begin
    edXMLFileOut.Text := SaveDialog1.FileName;
  end;
end;

procedure TForm1.edKeyPassChange(Sender: TObject);
var
  Encrypted: TBytes;
  DataType: TCryptInfoDataType;
begin
  edCertInfo.Clear;
  edKeyInfo.Clear;

  if FileExists(edCertFile.Text) then begin
    Encrypted := TFile.ReadAllBytes(edCertFile.Text);

    DataType := CryptDetectDataTypePEM(Encrypted);
    if DataType = kdtUnknown then begin
      edCertInfo.Lines.Add('Zawartoœæ pliku nie zosta³a rozpoznana !');
      Exit;
    end;

    edCertInfo.Lines.Add('Plik zawiera: ' + CryptDataTypeToString(DataType));

    case DataType of
      kdtX509Certificate: begin
        ExtractInfoFromCert(edCertInfo.Lines, Encrypted);
      end;
      kdtRSAPrivate,
      kdtRSAPublic,
      kdtECPrivate,
      kdtECPublic,
      kdtPKCS8Private,
      kdtPKCS8EncryptedPrivate: begin
        ExtractInfoFromKey(edCertInfo.Lines, Encrypted, DataType, edKeyPass.Text);
      end;
      kdtPKCS12: begin
        edCertInfo.Lines.Add('PKCS#12 - nie jest jeszcze wspierany !');
      end;
      kdtCSR: begin
        edCertInfo.Lines.Add('CSR - nie jest jeszcze wspierany !');
      end;
    end;
  end;

  if FileExists(edKeyFile.Text) then begin
    Encrypted := TFile.ReadAllBytes(edKeyFile.Text);

    DataType := CryptDetectDataTypePEM(Encrypted);
    if DataType = kdtUnknown then begin
      edKeyInfo.Lines.Add('Zawartoœæ pliku nie zosta³a rozpoznana !');
      Exit;
    end;

    edKeyInfo.Lines.Add('Plik zawiera: ' + CryptDataTypeToString(DataType));

    case DataType of
      kdtX509Certificate: begin
        ExtractInfoFromCert(edKeyInfo.Lines, Encrypted);
      end;
      kdtRSAPrivate,
      kdtRSAPublic,
      kdtECPrivate,
      kdtECPublic,
      kdtPKCS8Private,
      kdtPKCS8EncryptedPrivate: begin
        ExtractInfoFromKey(edKeyInfo.Lines, Encrypted, DataType, edKeyPass.Text);
      end;
      kdtPKCS12: begin
        edKeyInfo.Lines.Add('PKCS#12 - nie jest jeszcze wspierany !');
      end;
      kdtCSR: begin
        edKeyInfo.Lines.Add('CSR - nie jest jeszcze wspierany !');
      end;
    end;
  end;
end;

end.

