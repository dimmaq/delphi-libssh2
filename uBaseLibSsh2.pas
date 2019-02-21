unit uBaseLibSsh2;

interface

uses
  SysUtils, Classes, AnsiStrings, SyncObjs,
  //
  Winapi.Winsock2,
  //
  libssh2;

type
  TBaseLibSsh2 = class;

  ELibSsh2Error = class(Exception);

  TFingerprintState = (fsNew, fsChanged);
  TConnectHashAction = (chaCancel, chaIgnore, chaSave);
  TFingerprintEvent = procedure(ASender: TBaseLibSsh2; AHexHash: AnsiString;
    const AState: TFingerprintState; var AAction: TConnectHashAction) of object;

  TSshAuthType = (SSH_AUTH_NONE, SSH_AUTH_PASSWORD, SSH_AUTH_PUBLICKEY,
    SSH_AUTH_KEYBOARD_INTERACTIVE);
  TSshAuthTypeSet = set of TSshAuthType;


  TBaseLibSsh2 = class
  private
    function GetTimeout: Integer;
    procedure SetTimeout(const Value: Integer);
  protected
    FRaiseError: Boolean;
    FSocket: TSocket;
    FSession: PLIBSSH2_SESSION;
    FHostKey: AnsiString;
    FHostKeyType: Integer;
    FHostKeyTypeStr: string;
    FFingerprint: AnsiString;
    FRemoteBanner: AnsiString;
    FAuthTypeSet: TSshAuthTypeSet;
    FAuthTypeStr: AnsiString;
    FOnFingerprint: TFingerprintEvent;
    function GetLibVer: AnsiString;
    function DoHandshake: Boolean;
    function GetHostkeyHash: AnsiString;
    function GetSessionHostkey: Integer;
    function GetRemoteBanner: AnsiString;
    function GetUserAuthList(const AUsername: AnsiString): TSshAuthTypeSet;
    procedure RaiseSshError_(const A: string);
    procedure RaiseSshError(const A: AnsiString);
    procedure DoOnFingerprint;
    //---
    function ConnectAndAuth(const ASocket: TSocket;
      const AUsername, APassword: AnsiString): Boolean;{$IFDEF UNICODE}overload;{$ENDIF}
    {$IFDEF UNICODE}
    function ConnectAndAuth(const ASocket: TSocket;
      const AUsername, APassword: string): Boolean; overload;
    {$ENDIF}
  public
    constructor Create;
    destructor Destroy; override;

    function GetLastErrorNum: Integer;
    function GetLastErrorStr: string;
    function GetFormatErrorStr: string;
//    function GetSessionLastError: AnsiString;
    function AuthPasswordSupport(const AUser: AnsiString): Boolean; overload;
    function AuthPasswordSupport(const AUser: string): Boolean; overload;
    function Auth(const AUsername, APassword: AnsiString; ATerminatedEvent: TEvent): Boolean; overload;
    function Auth(const AUsername, APassword: string; ATerminatedEvent: TEvent): Boolean; overload;
    function AuthKeyboardIntecactive(const AUsername, APassword: AnsiString; ATerminatedEvent: TEvent): Boolean;
    function Connect(const ASocket: TSocket): Boolean;
    function WaitSocket: Boolean;

    property Socket: TSocket read FSocket write FSocket;
    property LibVersion: AnsiString read GetLibVer;
    property Fingerprint: AnsiString read FFingerprint;
    property HostKey: AnsiString read FHostKey;
    property HostKeyType: Integer read FHostKeyType;
    property HostKeyTypeStr: string read FHostKeyTypeStr;
    property RemoteBanner: AnsiString read FRemoteBanner;
    property AuthTypeSet: TSshAuthTypeSet read FAuthTypeSet;
    property AuthTypeStr: AnsiString read FAuthTypeStr;
    property RaiseError: Boolean read FRaiseError write FRaiseError;
    property Timeout: Integer read GetTimeout write SetTimeout;
  end;


function GetLibSsh2Ver: AnsiString;

implementation

uses windows;


function HostKeyTypeToStr(const AType: Integer): string;
begin
  case AType of
    LIBSSH2_HOSTKEY_TYPE_UNKNOWN   : Result := 'Unknow';
    LIBSSH2_HOSTKEY_TYPE_RSA       : Result := 'RSA';
    LIBSSH2_HOSTKEY_TYPE_DSS       : Result := 'DSS';
    LIBSSH2_HOSTKEY_TYPE_ECDSA_256 : Result := 'ECDSA_256';
    LIBSSH2_HOSTKEY_TYPE_ECDSA_384 : Result := 'ECDSA_384';
    LIBSSH2_HOSTKEY_TYPE_ECDSA_521 : Result := 'ECDSA_521';
    LIBSSH2_HOSTKEY_TYPE_ED25519   : Result := 'ED25519';
  else
      Result := '';
  end;
end;

var
  gLibVer: AnsiString;

function GetLibSsh2Ver: AnsiString;
begin
  Result := gLibVer
end;

function sshAllocMem(count: UINT; _abstract: PPointer): Pointer; cdecl;
begin
  Result := GetMemory(count);
end;

procedure sshFreeMem(ptr: Pointer; _abstract: PPointer); cdecl;
begin
  FreeMemory(ptr);
end;

function sshReallocMem(ptr: Pointer; count: UINT; _abstract: PPointer): Pointer; cdecl;
begin
  Result := ReallocMemory(ptr, count);
end;


{ TBaseLibSsh2 }

constructor TBaseLibSsh2.Create;
begin
  inherited;
  //FSession := libssh2_session_init();
  FSession := libssh2_session_init_ex(sshAllocMem, sshFreeMem, sshReallocMem, nil);
  if Fsession = nil then
    RaiseSshError('libssh2_session_init ');
end;

destructor TBaseLibSsh2.Destroy;
begin
  if FSession <> nil then
  begin
    libssh2_session_disconnect(FSession, '');
    libssh2_session_free(FSession);
  end;
  inherited;
end;

procedure TBaseLibSsh2.RaiseSshError_(const A: string);
begin
  if FRaiseError then
    raise ELibSsh2Error.Create(A + string(GetLastErrorStr()))
end;


function TBaseLibSsh2.DoHandshake: Boolean;
var r: Integer;
begin
  // ... start it up. This will trade welcome banners, exchange keys,
  // and setup crypto, compression, and MAC layers
  r := libssh2_session_handshake(FSession, FSocket);
  if r <> 0 then
  begin
    RaiseSshError('libssh2_session_handshake ');
    Result := False;
    Exit;
  end;
  Result := True;
end;

procedure TBaseLibSsh2.DoOnFingerprint;
var AAction: TConnectHashAction;
begin
  if Assigned(FOnFingerprint) then
    FOnFingerprint(Self, FFingerprint, fsNew, AAction)
end;

function TBaseLibSsh2.GetUserAuthList(const AUsername: AnsiString): TSshAuthTypeSet;
var
  p: PAnsiChar;
begin
  FAuthTypeStr := '';
  FAuthTypeSet := [];
  //* check what authentication methods are available */
  p := libssh2_userauth_list(FSession, PAnsiChar(AUsername), Length(AUsername));
  if p = nil then
    RaiseSshError('libssh2_userauth_list ');

  FAuthTypeStr := p;
  FAuthTypeSet := [];
  if AnsiStrings.StrPos(p, 'password') <> nil then
    FAuthTypeSet := FAuthTypeSet + [SSH_AUTH_PASSWORD];
  if AnsiStrings.StrPos(p, 'publickey') <> nil then
    FAuthTypeSet := FAuthTypeSet + [SSH_AUTH_PUBLICKEY];
  if AnsiStrings.StrPos(p, 'keyboard-interactive') <> nil then
    FAuthTypeSet := FAuthTypeSet + [SSH_AUTH_KEYBOARD_INTERACTIVE];

  Result := FAuthTypeSet;
end;

function TBaseLibSsh2.GetLastErrorNum: Integer;
begin
  Result := libssh2_session_last_errno(FSession)
end;

function TBaseLibSsh2.GetLastErrorStr: string;
var
  I: Integer;
  P: PAnsiChar;
  z: AnsiString;
begin
  I := 0;
  P := nil;

  if FSession <> nil then
  begin

    libssh2_session_last_error(FSession, P, I, 0);
  end;
  z := AnsiString(P);
  Result := string(z)
end;

procedure TBaseLibSsh2.RaiseSshError(const A: AnsiString);
begin
  RaiseSshError_(string(A))
end;

function TBaseLibSsh2.GetFormatErrorStr: string;
begin
  Result := Format('%d %s', [GetLastErrorNum(), GetLastErrorStr()])
end;

function TBaseLibSsh2.GetHostkeyHash: AnsiString;
const
  HASH_ID = LIBSSH2_HOSTKEY_HASH_SHA1;
  HASH_LEN = 20;
var
  p: PAnsiChar;
  l: Integer;
begin
  FFingerprint := '';

  { At this point we havn't yet authenticated.  The first thing to do
  * is check the hostkey's fingerprint against our known hosts Your app
  * may have it hard coded, may go to a file, may present it to the
  * user, that's your call }
  p := libssh2_hostkey_hash(FSession, HASH_ID);
  if p = nil then
  begin
    RaiseSshError('libssh2_hostkey_hash ');
    Exit;
  end;

  l := HASH_LEN;
  SetLength(FFingerprint, l * 2);
  BinToHex(p, PAnsiChar(FFingerprint), l);

  DoOnFingerprint();
  Result := FFingerprint;
end;

function TBaseLibSsh2.GetSessionHostkey: Integer;
var
  p: PAnsiChar;
  l: Cardinal;
  t: Integer;
begin
  FHostKey := '';
  FHostKeyType := LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
  FHostKeyTypeStr := '';
  //---
  p := libssh2_session_hostkey(FSession, l, t);
  if p <> nil then
  begin
    SetString(FHostKey, p, l);
    FHostKeyType := t;
    FHostKeyTypeStr := HostKeyTypeToStr(t);
  end;

  Result := FHostKeyType;
end;

function TBaseLibSsh2.GetLibVer: AnsiString;
begin
  Result := gLibVer
end;

function TBaseLibSsh2.GetRemoteBanner: AnsiString;
var p: PAnsiChar;
begin
  p := libssh2_session_banner_get(FSession);
  FRemoteBanner := AnsiString(p);
//  FRemoteBanner := 'test' ;
  Result := FRemoteBanner;
end;


function TBaseLibSsh2.GetTimeout: Integer;
begin
  Result := libssh2_session_get_timeout(FSession)
end;

procedure TBaseLibSsh2.SetTimeout(const Value: Integer);
begin
  libssh2_session_set_timeout(FSession, Value)

end;

function TBaseLibSsh2.WaitSocket: Boolean;
var
  timeout: timeval;
  rc: Integer;
  fd: fd_set;
  writefd: PFD_SET;
  readfd: PFD_SET;
  dir: Integer;
begin
  writefd := nil;
  readfd := nil;

  timeout.tv_sec := 10;
  timeout.tv_usec := 0;

  FD_ZERO(fd);

  _FD_SET(FSocket, fd);

  ///* now make sure we wait in the correct direction */
  dir := libssh2_session_block_directions(FSession);

  if (dir and LIBSSH2_SESSION_BLOCK_INBOUND) <> 0 then
      readfd := @fd;

  if (dir and LIBSSH2_SESSION_BLOCK_OUTBOUND) <> 0 then
      writefd := @fd;

  rc := select(FSocket + 1, readfd, writefd, nil, @timeout);


  Result := (rc <> SOCKET_ERROR) and (rc <> 0); // !Error and !Timeout
end;


function sshStrDup(var A: AnsiString): PAnsiChar;
begin
  Result := sshAllocMem(Length(A) + 1, nil);
  AnsiStrings.StrCopy(Result, PAnsiChar(A));
end;

threadvar
  ssh_password: AnsiString;

procedure kbd_callback(const name: PAnsiChar;
                name_len: Integer;
                const instruction: PAnsiChar;
                instruction_len: Integer;
                num_prompts: Integer;
                const prompts: PLIBSSH2_USERAUTH_KBDINT_PROMPT;
                var responses: LIBSSH2_USERAUTH_KBDINT_RESPONSE;
                abstract: Pointer); cdecl;
begin
  if (num_prompts > 0) then
  begin
    responses.text := sshStrDup(ssh_password);
    responses.length := Length(ssh_password);
  end;
end;

function TBaseLibSsh2.AuthKeyboardIntecactive(const AUsername, APassword: AnsiString; ATerminatedEvent: TEvent): Boolean;
var r: Integer;
begin
  while True do
  begin
    ssh_password := APassword;
    r := libssh2_userauth_keyboard_interactive(FSession, PAnsiChar(AUsername), kbd_callback);
    ssh_password := '';
    if r <> 0 then
    begin
      if r = LIBSSH2_ERROR_EAGAIN then
      begin
        if Assigned(ATerminatedEvent) and (ATerminatedEvent.WaitFor(0) = wrSignaled) then
        begin
          Result := False;
          Exit;
        end;
        Sleep(0);
        Continue;
      end;
      //---
      RaiseSshError('auth kb-interactive fail, ');
      Result := False;
      Exit;
    end;
    Break;
  end;
  Result := True;
end;

function TBaseLibSsh2.Auth(const AUsername, APassword: AnsiString; ATerminatedEvent: TEvent): Boolean;
var r: Integer;
begin
  while True do
  begin
    r := libssh2_userauth_password(FSession, PAnsiChar(AUsername), PAnsiChar(APassword));
    if r <> 0 then
    begin
      if r = LIBSSH2_ERROR_EAGAIN then
      begin
        if Assigned(ATerminatedEvent) and (ATerminatedEvent.WaitFor(0) = wrSignaled) then
        begin
          Result := False;
          Exit;
        end;
        Sleep(0);
        Continue;
      end;
      //---
      RaiseSshError('auth fail, ');
      Result := False;
      Exit;
    end;
    Break;
  end;
  Result := True;
end;

function TBaseLibSsh2.Auth(const AUsername, APassword: string; ATerminatedEvent: TEvent): Boolean;
begin
  Result := Auth(AnsiString(AUsername), AnsiString(APassword), ATerminatedEvent)
end;

function TBaseLibSsh2.AuthPasswordSupport(const AUser: string): Boolean;
begin
  Result := AuthPasswordSupport(AnsiString(AUser))
end;

function TBaseLibSsh2.AuthPasswordSupport(const AUser: AnsiString): Boolean;
begin
  if FAuthTypeStr = '' then
    GetUserAuthList(AUser);

  Result := (SSH_AUTH_PASSWORD in FAuthTypeSet) or (SSH_AUTH_KEYBOARD_INTERACTIVE in FAuthTypeSet)
end;

function TBaseLibSsh2.Connect(const ASocket: TSocket): Boolean;
begin
  Socket := ASocket;
  if DoHandshake() then
  begin
    GetRemoteBanner();
    GetHostkeyHash();
    GetSessionHostkey();
    Result := True;
    Exit
  end;
  Result := False
end;

function TBaseLibSsh2.ConnectAndAuth(const ASocket: TSocket; const AUsername,
  APassword: AnsiString): Boolean;
begin
  if Connect(ASocket) then
  begin
    Result := Auth(AUsername, APassword, nil);
    Exit
  end;
  Result := False
end;

function TBaseLibSsh2.ConnectAndAuth(const ASocket: TSocket; const AUsername,
  APassword: string): Boolean;
begin
  Result := ConnectAndAuth(ASocket, AnsiString(AUsername), AnsiString(APassword))
end;

procedure LibSshInit_;
var
  r: Integer;
  p: PAnsiChar;
begin
  r := libssh2_init(0);
  if r <> 0 then
    raise ELibSsh2Error.CreateFmt('libssh2 initialization failed (%d)', [r]);

  p := libssh2_version(LIBSSH2_VERSION_NUM);
  if nil = p then
    raise ELibSsh2Error.Create('libssh2.dll to old');

  gLibVer := p;
end;

initialization
  LibSshInit_();

finalization
  libssh2_exit();

end.
