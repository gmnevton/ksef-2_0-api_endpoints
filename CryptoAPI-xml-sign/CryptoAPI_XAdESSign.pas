unit CryptoAPI_XAdESSign;

interface

uses
  SysUtils,
  Classes;

type
  TXAdESSign = class
  private
    FPublicKeyCertificate: TBytes;
    FPrivateKey: TBytes;
    FPrivateKeyEncrypted: Boolean;
    FPrivateKeyEncryptionPassword: String;
    FXMLToSign: TBytes;
    FSignedXML: TBytes;
  private
    function GetPublicKeyCertificate: String;
    function GetPrivateKey: String;
    function GetXMLToSign: UTF8String;
    function GetSignedXML: UTF8String;
    //
    procedure SetPublicKeyCertificate(const Value: String);
    procedure SetPrivateKey(const Value: String);
    procedure SetXMLToSign(const Value: UTF8String);
  protected
    function DoSign: Boolean; virtual;
  public
    constructor Create;
    destructor Destroy; override;
    //
    procedure LoadPublicKeyCertificate(const FileName: String; Encoding: TEncoding = Nil); overload;
    procedure LoadPublicKeyCertificate(const Stream: TStringStream); overload;
    procedure LoadPrivateKey(const FileName: String; Encoding: TEncoding = Nil); overload;
    procedure LoadPrivateKey(const Stream: TStringStream); overload;
    //
    function Sign: Boolean;
    //
    property PublicKeyCertificate: String read GetPublicKeyCertificate write SetPublicKeyCertificate;
    property PrivateKey: String read GetPrivateKey write SetPrivateKey;
    property PrivateKeyEncryptionPassword: String read FPrivateKeyEncryptionPassword write FPrivateKeyEncryptionPassword;
    property XMLToSign: UTF8String read GetXMLToSign write SetXMLToSign;
    property SignedXML: UTF8String read GetSignedXML;
  end;

implementation

uses
  StrUtils,
  NetEncoding,
  IOUtils,
  XAdESSigner,
  Crypt32_Compat;

function IfThen(const Cond: Boolean; IfTrue: String; IfFalse: String = ''): String;
begin
  if Cond then
    Result := IfTrue
  else
    Result := IfFalse;
end;

{ TXAdESSign }

constructor TXAdESSign.Create;
begin
  SetLength(FPublicKeyCertificate, 0);
  SetLength(FPrivateKey, 0);
  FPrivateKeyEncrypted := False;
  FPrivateKeyEncryptionPassword := '';
  SetLength(FXMLToSign, 0);
  SetLength(FSignedXML, 0);
end;

destructor TXAdESSign.Destroy;
begin
  SetLength(FPublicKeyCertificate, 0);
  SetLength(FPrivateKey, 0);
  FPrivateKeyEncrypted := False;
  FPrivateKeyEncryptionPassword := '';
  SetLength(FXMLToSign, 0);
  SetLength(FSignedXML, 0);
  inherited;
end;

function TXAdESSign.GetPublicKeyCertificate: String;
begin
  Result := '-----BEGIN CERTIFICATE-----'#13#10;
  Result := Result + BytesToBase64(FPublicKeyCertificate) + #13#10;
  Result := '-----END CERTIFICATE-----';
end;

function TXAdESSign.GetPrivateKey: String;
begin
  Result := '-----BEGIN ' + IfThen(FPrivateKeyEncrypted, 'ENCRYPTED ') + 'PRIVATE KEY-----'#13#10;
  Result := Result + BytesToBase64(FPrivateKey) + #13#10;
  Result := '-----END ' + IfThen(FPrivateKeyEncrypted, 'ENCRYPTED ') + 'PRIVATE KEY-----';
end;

function TXAdESSign.GetXMLToSign: UTF8String;
begin
  Result := UTF8String(TEncoding.UTF8.GetString(FXMLToSign));
end;

function TXAdESSign.GetSignedXML: UTF8String;
begin
  Result := UTF8String(TEncoding.UTF8.GetString(FSignedXML));
end;

procedure TXAdESSign.SetPublicKeyCertificate(const Value: String);
var
  Temp: String;
  i: Integer;
  base64: String;
begin
  SetLength(FPublicKeyCertificate, 0);
  Temp := Value;
  i := Pos('-----BEGIN CERTIFICATE-----', Temp);
  if i <> 1 then
    raise Exception.Create('Valid PEM encoded certificate is required.');
  Delete(Temp, 1, 27); // remove '-----BEGIN CERTIFICATE-----'
  i := Pos('-----END CERTIFICATE-----', Temp);
  if i <= 1 then
    raise Exception.Create('Valid PEM encoded certificate is required.');
  Delete(Temp, i, 25); // remove '-----END CERTIFICATE-----'
  //
  Temp := Trim(Temp);
  base64 := ReplaceStr(ReplaceStr(Temp, #13, ''), #10, ''); // remove line ends
  FPublicKeyCertificate := TNetEncoding.Base64.DecodeStringToBytes(base64);
  Temp := '';
  base64 := '';
end;

procedure TXAdESSign.SetPrivateKey(const Value: String);
var
  Temp: String;
  i: Integer;
  base64: String;
begin
  SetLength(FPrivateKey, 0);
  FPrivateKeyEncrypted := False;
  Temp := Value;
  i := Pos('-----BEGIN ENCRYPTED PRIVATE KEY-----', Temp);
  if i = 1 then
    FPrivateKeyEncrypted := True;
  if i < 1 then
    i := Pos('-----BEGIN PRIVATE KEY-----', Temp);
  if i <> 1 then
    raise Exception.Create('Valid PEM encoded private key is required.');
  if FPrivateKeyEncrypted then
    Delete(Temp, 1, 37) // remove '-----BEGIN ENCRYPTED PRIVATE KEY-----'
  else
    Delete(Temp, 1, 27); // remove '-----BEGIN PRIVATE KEY-----'
  if FPrivateKeyEncrypted then
    i := Pos('-----END ENCRYPTED PRIVATE KEY-----', Temp)
  else
    i := Pos('-----END PRIVATE KEY-----', Temp);
  if i <= 1 then
    raise Exception.Create('Valid PEM encoded private key is required.');
  if FPrivateKeyEncrypted then
    Delete(Temp, i, 35) // remove '-----END ENCRYPTED PRIVATE KEY-----'
  else
    Delete(Temp, i, 25); // remove '-----END PRIVATE KEY-----'
  //
  Temp := Trim(Temp);
  base64 := ReplaceStr(ReplaceStr(Temp, #13, ''), #10, ''); // remove line ends
  FPrivateKey := TNetEncoding.Base64.DecodeStringToBytes(base64);
  Temp := '';
  base64 := '';
end;

procedure TXAdESSign.SetXMLToSign(const Value: UTF8String);
begin
  SetLength(FXMLToSign, 0);
  FXMLToSign := TEncoding.UTF8.GetBytes(Value);
end;

function TXAdESSign.DoSign: Boolean;
begin
  Result := SignXml_XAdES_BES_Enveloped(FXMLToSign, FSignedXML, FPublicKeyCertificate, FPrivateKey, FPrivateKeyEncryptionPassword);
  if Result then
    TFile.WriteAllBytes('signed_xml.xml', FSignedXML);
end;

procedure TXAdESSign.LoadPublicKeyCertificate(const FileName: String; Encoding: TEncoding = Nil);
var
  stream: TStringStream;
  path: String;
begin
  if Encoding = Nil then
    Encoding := TEncoding.ASCII;
  //
  path := ExtractFilePath(FileName);
  if Length(path) = 0 then
    path := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0)));
  //
  stream := TStringStream.Create('', Encoding);
  try
    stream.LoadFromFile(path + ExtractFileName(FileName));
    LoadPublicKeyCertificate(stream);
  finally
    stream.Free;
  end;
end;

procedure TXAdESSign.LoadPublicKeyCertificate(const Stream: TStringStream);
begin
  stream.Position:=0;
  SetPublicKeyCertificate(stream.DataString);
end;

procedure TXAdESSign.LoadPrivateKey(const FileName: String; Encoding: TEncoding = Nil);
var
  stream: TStringStream;
  path: String;
begin
  if Encoding = Nil then
    Encoding := TEncoding.ASCII;
  //
  path := ExtractFilePath(FileName);
  if Length(path) = 0 then
    path := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0)));
  //
  stream := TStringStream.Create('', Encoding);
  try
    stream.LoadFromFile(path + ExtractFileName(FileName));
    LoadPrivateKey(stream);
  finally
    stream.Free;
  end;
end;

procedure TXAdESSign.LoadPrivateKey(const Stream: TStringStream);
begin
  stream.Position:=0;
  SetPrivateKey(stream.DataString);
end;

function TXAdESSign.Sign: Boolean;
begin
  Result := DoSign;
end;

end.

