object Form1: TForm1
  Left = 8
  Top = 8
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsSingle
  Caption = 'KSeF XML Signer'
  ClientHeight = 721
  ClientWidth = 1000
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 8
    Top = 272
    Width = 146
    Height = 13
    Caption = 'Info o certyfikacie publicznym:'
  end
  object Label2: TLabel
    Left = 512
    Top = 272
    Width = 122
    Height = 13
    Caption = 'Info o kluczu prywatnym:'
  end
  object edCertFile: TLabeledEdit
    Left = 8
    Top = 24
    Width = 785
    Height = 21
    EditLabel.Width = 133
    EditLabel.Height = 13
    EditLabel.Caption = 'Plik certyfikatu publicznego:'
    TabOrder = 0
    OnChange = edKeyPassChange
  end
  object edKeyFile: TLabeledEdit
    Left = 8
    Top = 121
    Width = 785
    Height = 21
    EditLabel.Width = 112
    EditLabel.Height = 13
    EditLabel.Caption = 'Plik klucza prywatnego:'
    TabOrder = 3
    OnChange = edKeyPassChange
  end
  object edKeyPass: TLabeledEdit
    Left = 8
    Top = 72
    Width = 505
    Height = 21
    EditLabel.Width = 221
    EditLabel.Height = 13
    EditLabel.Caption = 'Has'#322'o do zaszyfrowanego klucza prywatnego:'
    TabOrder = 2
    OnChange = edKeyPassChange
  end
  object edXMLFile: TLabeledEdit
    Left = 8
    Top = 184
    Width = 785
    Height = 21
    EditLabel.Width = 110
    EditLabel.Height = 13
    EditLabel.Caption = 'Plik XML do podpisania:'
    TabOrder = 5
  end
  object edXMLFileOut: TLabeledEdit
    Left = 8
    Top = 232
    Width = 785
    Height = 21
    EditLabel.Width = 261
    EditLabel.Height = 13
    EditLabel.Caption = #346'cie'#380'ka w kt'#243'rej zostanie zapisany podpisany plik XML:'
    TabOrder = 7
  end
  object Button1: TButton
    Left = 850
    Top = 24
    Width = 142
    Height = 119
    Caption = 'Podpisz'#13#10'XML'#13#10#13#10'(format XAdES-BES)'
    TabOrder = 9
    WordWrap = True
    OnClick = Button1Click
  end
  object Button2: TButton
    Left = 799
    Top = 22
    Width = 27
    Height = 25
    Caption = '...'
    TabOrder = 1
    OnClick = Button2Click
  end
  object Button3: TButton
    Left = 799
    Top = 119
    Width = 27
    Height = 25
    Caption = '...'
    TabOrder = 4
    OnClick = Button3Click
  end
  object Button4: TButton
    Left = 799
    Top = 182
    Width = 27
    Height = 25
    Caption = '...'
    TabOrder = 6
    OnClick = Button4Click
  end
  object Button5: TButton
    Left = 799
    Top = 230
    Width = 27
    Height = 25
    Caption = '...'
    TabOrder = 8
    OnClick = Button5Click
  end
  object edCertInfo: TMemo
    Left = 8
    Top = 288
    Width = 480
    Height = 425
    Font.Charset = EASTEUROPE_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Consolas'
    Font.Pitch = fpFixed
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 10
    WordWrap = False
  end
  object edKeyInfo: TMemo
    Left = 512
    Top = 288
    Width = 480
    Height = 425
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Consolas'
    Font.Pitch = fpFixed
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 11
    WordWrap = False
  end
  object OpenDialog1: TOpenDialog
    Filter = 
      'Certyfikaty (*.crt)|*.crt|Certyfikaty zakodowane PEM (*.pem)|*.p' +
      'em|Certyfikaty zakodowane DER (*.der)|*.der'
    Left = 856
    Top = 152
  end
  object OpenDialog2: TOpenDialog
    Filter = 'Klucze (*.key)|*.key'
    Left = 936
    Top = 152
  end
  object OpenDialog3: TOpenDialog
    Filter = 'Pliki XML (*.xml)|*.xml'
    Left = 856
    Top = 200
  end
  object SaveDialog1: TSaveDialog
    Filter = 'Pliki XML podpisane XAdES|*.xades'
    Left = 936
    Top = 200
  end
end
