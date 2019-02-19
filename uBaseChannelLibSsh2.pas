unit uBaseChannelLibSsh2;

interface

uses
  SysUtils, Classes, AnsiStrings,
  //
  uBaseLibSsh2,
  //
  libssh2;

type
  TBaseChannelLibSsh2 = class(TBaseLibSsh2)
  protected
    FChannel: PLIBSSH2_CHANNEL;
    FReadBuffer: AnsiString;
  public
    constructor Create;
    destructor Destroy; override;

    function CloseChannel: Boolean;
    function Write(const A: AnsiString): Boolean;
    function WriteLine(const A: AnsiString): Boolean;
    function Read(var A: AnsiString): Boolean;
    function ReadLine: AnsiString;
    function ReadAll: AnsiString;
    function ReadAvaible: Boolean;
    function IsEOF: Boolean;
  end;
implementation

{ TBaseChannelLibSsh2 }

function TBaseChannelLibSsh2.CloseChannel: Boolean;
begin
  if FChannel <> nil then
  begin
    libssh2_channel_free(FChannel);
    FChannel := nil;
  end;
  Result := True;
end;

constructor TBaseChannelLibSsh2.Create;
begin
  inherited;
end;

destructor TBaseChannelLibSsh2.Destroy;
begin
  CloseChannel();
  inherited;
end;

function TBaseChannelLibSsh2.IsEOF: Boolean;
var r: Integer;
begin
  r := libssh2_channel_eof(FChannel);
  if r < 0 then
  begin
    RaiseSshError('libssh2_channel_eof, ');
    Result := False;
    Exit
  end;
  Result := r <> 0
end;

function TBaseChannelLibSsh2.Read(var A: AnsiString): Boolean;
const
  BUF_SIZE = 1000;
var
  len: Integer;
  buf: PAnsiChar;
begin
  A := '';
  if not ReadAvaible() then
  begin
    Result := False;
    Exit;
  end;
  buf := AnsiStrings.AnsiStrAlloc(BUF_SIZE);
  try
    len := libssh2_channel_read(FChannel, buf, BUF_SIZE);
    if LIBSSH2_ERROR_EAGAIN = len then
    begin
      Result := True;
      Exit
    end
    else
    if len < 0 then
    begin
      Result := False;
      Exit;
    end;
    SetString(A, buf, len);
    A := FReadBuffer + A;
    FReadBuffer := ''
  finally
    AnsiStrings.StrDispose(buf)
  end;
  Result := True;
end;

function TBaseChannelLibSsh2.ReadAll: AnsiString;
begin
  Read(Result);
  Result := FReadBuffer + Result;
  FReadBuffer := ''
end;

function TBaseChannelLibSsh2.ReadAvaible: Boolean;
begin
  Result := True//libssh2_poll_channel_read(FChannel, 0) = 1
end;

function TBaseChannelLibSsh2.ReadLine: AnsiString;
var
  buf: AnsiString;
  p: Integer;
begin
  Read(buf);
  p := AnsiStrings.PosEx(#13#10, buf);
  if p > 0 then
  begin
    Result := Copy(buf, 1, p - 1);
    Delete(buf, 1, p + 1);
    FReadBuffer := buf;
  end
  else
  begin
    Result := FReadBuffer + buf;
    FReadBuffer := ''
  end;
end;

function TBaseChannelLibSsh2.Write(const A: AnsiString): Boolean;
var
  wr, len, i: Integer;
  p: PAnsiChar;
begin
  wr := 0;
  len := Length(A);
  p := PAnsiChar(A);
  while wr < len do
  begin
    i := libssh2_channel_write(FChannel, p + wr, len - wr);
    if LIBSSH2_ERROR_EAGAIN = i then
    begin
      Continue;
    end;
    if i < 0 then
    begin
      RaiseSshError('libssh2_channel_write, ');
      Result := False;
      Exit;
    end;
    Inc(wr, i)
  end;
  Result := True
end;

function TBaseChannelLibSsh2.WriteLine(const A: AnsiString): Boolean;
begin
  Result := Write(A + #13#10)
end;

end.
