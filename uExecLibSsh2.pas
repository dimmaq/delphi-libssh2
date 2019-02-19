unit uExecLibSsh2;

interface

uses
  SysUtils, Classes, AnsiStrings,
  //
  uBaseLibSsh2, uBaseChannelLibSsh2,
  //
  libssh2;

type
  TExecLibSsh2 = class(TBaseChannelLibSsh2)
  private
  public
    function OpenChannel: Boolean;
    function Exec(const ACommand: AnsiString): AnsiString; {$IFDEF UNICODE}overload;{$ENDIF}
    {$IFDEF UNICODE}
    function Exec(const ACommand: string): string; overload;
    {$ENDIF}
  end;

implementation

{ TExecLibSsh2 }


function TExecLibSsh2.Exec(const ACommand: AnsiString): AnsiString;
var rc: Integer;
begin
  while True do
  begin
    rc := libssh2_channel_exec(FChannel, PAnsiChar(ACommand));
    if rc = LIBSSH2_ERROR_EAGAIN then
    begin
      WaitSocket();
      Continue;
    end;
    Break;
  end;
  if (rc <> 0) then
  begin
      RaiseSshError('libssh2_channel_exec, ');
      exit('');
  end;
  Result := ReadAll();
end;

function TExecLibSsh2.Exec(const ACommand: string): string;
begin
  //libssh2_session_set_blocking(FSession, 0);
  Result := string(Exec(AnsiString(ACommand)))
end;

function TExecLibSsh2.OpenChannel: Boolean;
var err: Integer;
begin
  //libssh2_session_set_blocking(FSession, 0);
  // /* Exec non-blocking on the remove host */
  while True do
  begin
    FChannel := libssh2_channel_open_session(Fsession);
    if FChannel = nil then
    begin
      err := GetLastErrorNum();
      if err = LIBSSH2_ERROR_EAGAIN then
      begin
        WaitSocket();
        Continue;
      end;
    end;
    Break;
  end;

  if FChannel = nil then
  begin
      RaiseSshError('libssh2_channel_open_session, ');
      exit(False);
  end;

  Exit(True);
end;

end.
