unit BigInt;

interface

uses
  SysUtils,
  Classes;

type
  TBigInt = class
  private
    F: TBytes; // big-endian
    procedure Trim;
  public
    constructor Create; overload;
    constructor Create(const Value: Int64); overload;
    constructor Create(const Bytes: TBytes); overload;
    constructor Create(const Hex: String; Base: Integer); overload;
    //
    function ToString: String;
    function Clone: TBigInt;
    function BitLength: Integer;
    function ShiftLeft(Bits: Integer): TBigInt;
    function ShiftRight(Bits: Integer): TBigInt;
    function AsBytes: TBytes;
    function AsBytesPadded(Count: Integer): TBytes;
    function Compare(const B: TBigInt): Integer;
    function Add(const B: TBigInt): TBigInt;
    function AddInt(const I: Integer): TBigInt;
    function Subtract(const B: TBigInt): TBigInt;
    function Multiply(const B: TBigInt): TBigInt;
    function DivInt(const N: Integer): TBigInt;
    function Modulo(const Modulus: TBigInt): TBigInt;
    function ModPow(const Exponent, Modulus: TBigInt): TBigInt;
  end;

implementation

//
// Helpers
//
function Max(A,B: Integer): Integer; inline;
begin
  if A > B then 
    Result := A
  else
    Result := B;
end;

function HexToBytes(const Hex: string): TBytes;
var
  i,j: Integer;
begin
  SetLength(Result, Length(Hex) div 2);
  j := 0;
  for i := 1 to Length(Hex) div 2 do begin
    Result[j] := StrToInt('$' + Copy(Hex, 2*i-1, 2));
    Inc(j);
  end;
end;

//
// TBigInt implementation
//
constructor TBigInt.Create;
begin
  SetLength(F, 1);
  F[0] := 0;
end;

constructor TBigInt.Create(const Value: Int64);
var
  v: UInt64;
  tmp: TBytes;
  i, start: Integer;
begin
  // handle zero
  if Value = 0 then begin
    SetLength(F, 1);
    F[0] := 0;
    Exit;
  end;

  // work with unsigned to cover positive Int64
  if Value < 0 then
    raise Exception.Create('TBigInt.Create: negative values not supported');

  v := UInt64(Value);

  // build big-endian bytes
  SetLength(tmp, 8);
  for i := 0 to 7 do
    tmp[7 - i] := Byte((v shr (8*i)) and $FF);

  // strip leading zeros
  start := 0;
  while (start < 7) and (tmp[start] = 0) do Inc(start);

  F := Copy(tmp, start, Length(tmp) - start);
end;

constructor TBigInt.Create(const Bytes: TBytes);
begin
  if Length(Bytes) = 0 then begin
    SetLength(F,1);
    F[0] := 0;
  end
  else
    F := Copy(Bytes);
  Trim;
end;

constructor TBigInt.Create(const Hex: String; Base: Integer);
begin
  if Base <> 16 then
    raise Exception.Create('Only hex supported');
  F := HexToBytes(Hex);
  Trim;
end;

function TBigInt.ToString: string;
var
  temp: TBytes;
  quotient: TBytes;
  remainder: Integer;
  digit: Integer;
  i, carry, value: Integer;
  s: string;
begin
  // Zero?
  if (Length(F) = 0) or ((Length(F) = 1) and (F[0] = 0)) then begin
    Result := '0';
    Exit;
  end;

  // Work on a temp copy so we don't destroy original number
  temp := Copy(F);

  s := '';

  while True do begin
    // Divide temp by 10 -> quotient + remainder
    SetLength(quotient, Length(temp));
    carry := 0;

    for i := 0 to High(temp) do begin
      value := carry * 256 + temp[i];
      digit := value div 10;
      carry := value mod 10;
      quotient[i] := digit;
    end;

    // remainder = carry
    remainder := carry;

    // prepend the decimal digit
    s := Chr(Ord('0') + remainder) + s;

    // Strip leading zeros from quotient
    i := 0;
    while (i < Length(quotient)) and (quotient[i] = 0) do
      Inc(i);
    if i > 0 then
      Delete(quotient, 0, i);

    // Done?
    if Length(quotient) = 0 then
      Break;

    // Next iteration
    temp := quotient;
  end;

  // Apply sign if negative
//  if FSign < 0 then
//    s := '-' + s;

  Result := s;
end;

procedure TBigInt.Trim;
var
  i: Integer;
begin
  i := 0;
  while (i < High(F)) and (F[i] = 0) do
    Inc(i);
  if i > 0 then
    F := Copy(F, i, Length(F)-i);
end;

function TBigInt.Clone: TBigInt;
begin
  Result := TBigInt.Create(F);
end;

function TBigInt.BitLength: Integer;
var
  i, b: Integer;
  v: Byte;
begin
  // Skip leading zeros
  i := 0;
  while (i < Length(F)) and (F[i] = 0) do
    Inc(i);

  if i = Length(F) then
    Exit(0);

  v := F[i];

  // Count MSB position
  b := 0;
  while (v and (1 shl (7 - b))) = 0 do
    Inc(b);

  Result := (Length(F) - i) * 8 - b;
end;

function TBigInt.ShiftLeft(Bits: Integer): TBigInt;
var
  ByteShift, BitShift, i, carry, newByte: Integer;
begin
  Result := TBigInt.Create(0);

  ByteShift := Bits div 8;
  BitShift  := Bits mod 8;

  SetLength(Result.F, Length(Self.F) + ByteShift + 1); // +1 for overflow
  FillChar(Result.F[0], Length(Result.F), 0);

  // shift-all-by-byte first
  Move(Self.F[0], Result.F[ByteShift], Length(Self.F));

  if BitShift = 0 then
    Exit;

  // now shift-intra-byte
  carry := 0;
  for i := Length(Result.F)-1 downto 0 do begin
    newByte := (Result.F[i] shl BitShift) or carry;
    carry := (Result.F[i] shr (8 - BitShift)) and ((1 shl BitShift) - 1);
    Result.F[i] := Byte(newByte and $FF);
  end;

  // remove leading zero if no overflow
  if Result.F[0] = 0 then
    Delete(Result.F, 0, 1);
end;

function TBigInt.ShiftRight(Bits: Integer): TBigInt;
var
  ByteShift, BitShift, i, carry, newByte: Integer;
begin
  ByteShift := Bits div 8;
  BitShift  := Bits mod 8;

  if ByteShift >= Length(Self.F) then begin
    Result := TBigInt.Create(0);
    Exit;
  end;

  Result := TBigInt.Create(0);

  SetLength(Result.F, Length(Self.F) - ByteShift);
  Move(Self.F[ByteShift], Result.F[0], Length(Result.F));

  if BitShift = 0 then
    Exit;

  carry := 0;
  for i := 0 to Length(Result.F) - 1 do begin
    newByte := (Result.F[i] shr BitShift) or (carry shl (8 - BitShift));
    carry := Result.F[i] and ((1 shl BitShift) - 1);
    Result.F[i] := Byte(newByte and $FF);
  end;

  // trim leading zeros
  while (Length(Result.F) > 1) and (Result.F[0] = 0) do
    Delete(Result.F, 0, 1);
end;

function TBigInt.AsBytes: TBytes;
begin
  Result := Copy(F);
end;

function TBigInt.AsBytesPadded(Count: Integer): TBytes;
var
  Offset, Pad: Integer;
begin
  Pad := Count - Length(F);
  if Pad < 0 then
    raise Exception.Create('BigInt is larger than requested size');
  SetLength(Result, Count);
  FillChar(Result[0], Pad, 0);
  Move(F[0], Result[Pad], Length(F));
end;

function TBigInt.Compare(const B: TBigInt): Integer;
var
  i: Integer;
begin
  if Length(F) <> Length(B.F) then
    Exit(Ord(Length(F) > Length(B.F)) - Ord(Length(F) < Length(B.F)));

  for i := 0 to High(F) do begin
    if F[i] <> B.F[i] then
      Exit(Ord(F[i] > B.F[i]) - Ord(F[i] < B.F[i]));
  end;
  Result := 0;
end;

//
// A + B
//
function TBigInt.Add(const B: TBigInt): TBigInt;
var
  iA, iB, iR: Integer;
  Carry: Integer;
  AArr, BArr, R: TBytes;
  av, bv: Byte;
  sum: Integer;
begin
  AArr := F;
  BArr := B.F;
  SetLength(R, Max(Length(AArr), Length(BArr)) + 1);

  iA := Length(AArr)-1;
  iB := Length(BArr)-1;
  iR := Length(R)-1;

  Carry := 0;
  while (iA >= 0) or (iB >= 0) or (Carry > 0) do begin
    av := 0;
    bv := 0;
    if iA >= 0 then
      av := AArr[iA];
    if iB >= 0 then
      bv := BArr[iB];

    sum := av + bv + Carry;

    Carry := sum shr 8;

    R[iR] := Byte(sum);

    Dec(iA);
    Dec(iB);
    Dec(iR);
  end;

  Result := TBigInt.Create(R);
end;

function TBigInt.AddInt(const I: Integer): TBigInt;
var
  B: TBigInt;
begin
  B := TBigInt.Create;
  B.F := TBytes.Create(Byte(I));
  Result := Add(B);
end;

//
// A - B  (assumes A >= B)
//
function TBigInt.Subtract(const B: TBigInt): TBigInt;
var
  iA, iB, iR: Integer;
  Borrow: Integer;
  AArr, BArr, R: TBytes;
  av, bv: Byte;
  diff: Integer;
begin
  AArr := F;
  BArr := B.F;
  SetLength(R, Max(Length(AArr), Length(BArr)));

  iA := Length(AArr)-1;
  iB := Length(BArr)-1;
  iR := Length(R)-1;

  Borrow := 0;
  while (iA >= 0) do begin
    av := AArr[iA];
    bv := 0;
    if iB >= 0 then
      bv := BArr[iB];

    diff := av - bv - Borrow;
    if diff < 0 then begin
      diff := diff + 256;
      Borrow := 1;
    end
    else
      Borrow := 0;

    R[iR] := Byte(diff);

    Dec(iA);
    Dec(iB);
    Dec(iR);
  end;

  Result := TBigInt.Create(R);
  Result.Trim;
end;

//
// A * B
//
function TBigInt.Multiply(const B: TBigInt): TBigInt;
var
  AArr, BArr, R: TBytes;
  i, j: Integer;
  Carry: Integer;
  v: Integer;
begin
  AArr := F;
  BArr := B.F;
  SetLength(R, Length(AArr) + Length(BArr));
  FillChar(R[0], Length(R), 0);

  for i := High(AArr) downto 0 do begin
    Carry := 0;
    for j := High(BArr) downto 0 do begin
      v := R[i + j + 1] + (AArr[i] * BArr[j]) + Carry;
      R[i + j + 1] := Byte(v);
      Carry := v shr 8;
    end;
    R[i] := Byte(R[i] + Carry);
  end;

  Result := TBigInt.Create(R);
  Result.Trim;
end;

//
// integer division by small int
//
function TBigInt.DivInt(const N: Integer): TBigInt;
var
  R: TBytes;
  i: Integer;
  Carry: Integer;
  v: Integer;
begin
  SetLength(R, Length(F));
  Carry := 0;
  for i := 0 to High(F) do begin
    v := Carry * 256 + F[i];
    R[i] := Byte(v div N);
    Carry := v mod N;
  end;
  Result := TBigInt.Create(R);
  Result.Trim;
end;

//
// modulo
//
//function TBigInt.Modulo(const Modulus: TBigInt): TBigInt;
//begin
//  // simple subtractive mod (sufficient for EC sizes)
//  Result := Self.Clone;
//  while Result.Compare(Modulus) >= 0 do
//    Result := Result.Subtract(Modulus);
//end;

function TBigInt.Modulo(const Modulus: TBigInt): TBigInt;
var
  Shift: Integer;
  Tmp: TBigInt;
begin
  Result := Self.Clone;

  // If smaller -> already reduced
  if Result.Compare(Modulus) < 0 then
    Exit;

  // How much we must left-shift Modulus so its MSB aligns with Result
  Shift := (Result.BitLength - Modulus.BitLength);

  Tmp := Modulus.ShiftLeft(Shift);

  while Shift >= 0 do begin
    if Result.Compare(Tmp) >= 0 then
      Result := Result.Subtract(Tmp);

    Dec(Shift);
    Tmp := Tmp.ShiftRight(1);
  end;
end;

//
// modular exponentiation (square & multiply)
//
function TBigInt.ModPow(const Exponent, Modulus: TBigInt): TBigInt;
var
  Base, Exp, Res: TBigInt;
  Bit: Integer;
  i: Integer;
begin
  Base := Self.Modulo(Modulus);
  Exp := Exponent.Clone;

  Res := TBigInt.Create;
  Res.F := TBytes.Create(1); // =1

  for i := 0 to High(Exp.F) do begin
    for Bit := 7 downto 0 do begin
      // square
      Res := Res.Multiply(Res).Modulo(Modulus);

      // multiply if bit = 1
      if ((Exp.F[i] shr Bit) and 1) = 1 then
        Res := Res.Multiply(Base).Modulo(Modulus);
    end;
  end;

  Result := Res;
end;

end.

