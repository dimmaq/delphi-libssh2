unit uBaseLibSsh2;

interface

uses
  SysUtils, Classes, AnsiStrings,
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
    FFingerprint: AnsiString;
    FRemoteBanner: AnsiString;
    FAuthTypeSet: TSshAuthTypeSet;
    FAuthTypeStr: AnsiString;
    FOnFingerprint: TFingerprintEvent;
    function GetLibVer: AnsiString;
    function DoHandshake: Boolean;
    function GetHostkeyHash: AnsiString;
    function GetRemoteBanner: AnsiString;
    function GetUserAuthList(const AUsername: AnsiString): TSshAuthTypeSet;
    procedure RaiseSshError_(const A: string);
    procedure RaiseSshError(const A: AnsiString);
    procedure DoOnFingerprint;
  public
    constructor Create;
    destructor Destroy; override;

    function GetLastErrorNum: Integer;
    function GetLastErrorStr: string;
    function GetFormatErrorStr: string;
//    function GetSessionLastError: AnsiString;
    function AuthPasswordSupport(const AUser: AnsiString): Boolean; overload;
    function AuthPasswordSupport(const AUser: string): Boolean; overload;
    function Auth(const AUsername, APassword: AnsiString): Boolean; overload;
    function Auth(const AUsername, APassword: string): Boolean; overload;
    function Connect(const ASocket: TSocket): Boolean;
    function ConnectAndAuth(const ASocket: TSocket;
      const AUsername, APassword: AnsiString): Boolean;{$IFDEF UNICODE}overload;{$ENDIF}
    {$IFDEF UNICODE}
    function ConnectAndAuth(const ASocket: TSocket;
      const AUsername, APassword: string): Boolean; overload;
    {$ENDIF}
    function WaitSocket: Boolean;

    property Socket: TSocket read FSocket write FSocket;
    property LibVersion: AnsiString read GetLibVer;
    property Fingerprint: AnsiString read FFingerprint;
    property RemoteBanner: AnsiString read FRemoteBanner;
    property AuthTypeSet: TSshAuthTypeSet read FAuthTypeSet;
    property AuthTypeStr: AnsiString read FAuthTypeStr;
    property RaiseError: Boolean read FRaiseError write FRaiseError;
    property Timeout: Integer read GetTimeout write SetTimeout;
  end;


function GetLibSsh2Ver: AnsiString;

implementation

uses windows;

var
  gLibVer: AnsiString;

function GetLibSsh2Ver: AnsiString;
begin
  Result := gLibVer
end;

{ TBaseLibSsh2 }

constructor TBaseLibSsh2.Create;
begin
  inherited;

  // Create a session instance
  FSession := libssh2_session_init();
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
    libssh2_session_last_error(FSession, P, I, 0);
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

function TBaseLibSsh2.Auth(const AUsername, APassword: AnsiString): Boolean;
var r: Integer;
begin
  r := libssh2_userauth_password(FSession, PAnsiChar(AUsername), PAnsiChar(APassword));
  if r <> 0 then
  begin
    RaiseSshError('auth fail, ');
    Result := False;
    Exit;
  end;

  Result := True;
end;

function TBaseLibSsh2.Auth(const AUsername, APassword: string): Boolean;
begin
  Result := Auth(AnsiString(AUsername), AnsiString(APassword))
end;

function TBaseLibSsh2.AuthPasswordSupport(const AUser: string): Boolean;
begin
  Result := AuthPasswordSupport(AnsiString(AUser))
end;

function TBaseLibSsh2.AuthPasswordSupport(const AUser: AnsiString): Boolean;
begin
  if FAuthTypeStr = '' then
    GetUserAuthList(AUser);

  Result := SSH_AUTH_PASSWORD in FAuthTypeSet
end;

function TBaseLibSsh2.Connect(const ASocket: TSocket): Boolean;
begin
  Socket := ASocket;
  if DoHandshake() then
  begin
    GetRemoteBanner();
    GetHostkeyHash();
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
    Result := Auth(AUsername, APassword);
    Exit
  end;
  Result := False
end;

function TBaseLibSsh2.ConnectAndAuth(const ASocket: TSocket; const AUsername,
  APassword: string): Boolean;
begin
  Result := ConnectAndAuth(ASocket, AnsiString(AUsername), AnsiString(APassword))
end;

const
  LIBEAY_DLL = 'libeay32.dll';
  OPENSSL_CRYPTO_LOCK = 1;

var
  glock_cs: array of THandle;

function CRYPTO_num_locks: Integer; cdecl; external LIBEAY_DLL;
procedure CRYPTO_set_locking_callback(cb: Pointer); cdecl; external LIBEAY_DLL;

procedure win32_locking_callback(mode: Integer; atype: integer; afile: PAnsiChar; line: Integer); cdecl;
begin
  if ((mode and OPENSSL_CRYPTO_LOCK) <> 0) then
  begin
    WaitForSingleObject(glock_cs[atype], INFINITE);
  end
  else
  begin
    ReleaseMutex(glock_cs[atype]);
  end
end;


procedure InitOpenSslThreads_;
var l,j: Integer;
begin
  l := CRYPTO_num_locks();
  SetLength(glock_cs, l);

  for j := 0 to l - 1 do
  begin
    glock_cs[j] := CreateMutex(nil, False, nil);
  end;

  CRYPTO_set_locking_callback(@win32_locking_callback);
end;

procedure FinalOpenSslThreads_;
var j: Integer;

  for j := 0 to Length(glock_cs) - 1 do
  begin
    CloseHandle(glock_cs[j]);
    glock_cs[j] := 0;
  end;
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
  InitOpenSslThreads_();
  LibSshInit_();

finalization
  libssh2_exit();
  FinalOpenSslThreads_();

end.