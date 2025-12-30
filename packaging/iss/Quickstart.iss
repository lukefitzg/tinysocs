; ------------------------------------------------------------
; Quickstart.iss — TinySocs
; IMPORTANT:
;   ISPP (preprocessor) is strict:
;     - directives (#define/#if/#else/#endif/#error) MUST start at column 1
;     - uses C-style operators: ||  &&  !
;   PascalScript (in [Code]) uses: or  and  not
;
;   ALSO IMPORTANT:
;     ISPP will treat any line whose first non-space character is "#"
;     as a preprocessor directive. Therefore DO NOT start PascalScript
;     lines with #13#10 etc. Use a CRLF constant instead.
; ------------------------------------------------------------

#define HasTinyBoxSeedConfig (FileExists('..\opensearch\programdata\config\opensearch.yml'))
#define HasTinyBoxSeedCerts  (DirExists('..\opensearch\programdata\certs'))

; Support both seed layouts:
;  - preferred: packaging/opensearch/programdata/opensearch-security
;  - legacy:    packaging/opensearch/programdata/security
#define HasTinyBoxSeedSecA   (DirExists('..\opensearch\programdata\opensearch-security'))
#define HasTinyBoxSeedSecB   (DirExists('..\opensearch\programdata\security'))
#define HasTinyBoxSeedSec    (HasTinyBoxSeedSecA || HasTinyBoxSeedSecB)

#define HasTinyBoxSeed       (HasTinyBoxSeedConfig || HasTinyBoxSeedCerts || HasTinyBoxSeedSec)

[Setup]
AppName=TinySocs
AppVersion=0.7.1
AppPublisher=TinySocs
AppId={{F2DCCF8F-6F5F-4D8B-9EAF-6E2C2C6B1234}}
DefaultDirName={commonpf}\TinySocs
DefaultGroupName=TinySocs
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
OutputDir={#SourcePath}
OutputBaseFilename=TinySocs-Setup
PrivilegesRequired=admin
WizardStyle=modern
; Debugging=yes

[Files]
; Binaries (paths relative to this .iss → back out two levels)
Source: "..\..\dist\TinySocsNode.exe";      DestDir: "{app}\bin"; Flags: ignoreversion
Source: "..\..\dist\TinySocsMaster.exe";   DestDir: "{app}\bin"; Flags: ignoreversion
Source: "..\..\dist\TinySocsAnchors.exe";  DestDir: "{app}\bin"; Flags: ignoreversion

; TinySocs collector agent binary (self-contained win-x64 publish)
Source: "..\..\src\TinySocs.Agent\bin\Release\net8.0\win-x64\publish\TinySocs.Agent.exe"; \
    DestDir: "{app}\bin"; \
    Flags: ignoreversion

; TinySocs collector agent config template → ProgramData
; (Do not overwrite on upgrade; operator may have edited it)
Source: "..\..\config\agent-config.yml"; \
    DestDir: "{commonappdata}\TinySocs\Collector\agent"; \
    DestName: "config.yml"; \
    Flags: ignoreversion onlyifdoesntexist

; NSSM is optional — include only if present at build time
#if FileExists('..\..\thirdparty\nssm.exe')
Source: "..\..\thirdparty\nssm.exe";       DestDir: "{app}\bin"; Flags: ignoreversion
#endif

; Modules / helpers
Source: "..\..\modules\TinySocs.Installer.psm1";  DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\TinySocs.RotateQueue.ps1"; DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Master.ps1";        DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Anchors.ps1";       DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\OPERATOR-README.txt";      DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\PostInstall.ps1";          DestDir: "{app}\modules"; Flags: ignoreversion

; OpenSearch persistence script (deterministic TLS + ports)
Source: ".\scripts\OpenSearch.Persistence.ps1";   DestDir: "{app}\modules"; Flags: ignoreversion

; --- Build-time sanity checks for vendor payloads + payload copy ---

#if FileExists('..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\bin\opensearch.bat')
; OpenSearch vendor payload present
#else
#error "OpenSearch vendor payload missing. Extract opensearch-3.3.2-windows-x64.zip into vendor\opensearch-3.3.2-windows-x64"
#endif

Source: "..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\*"; \
    DestDir: "{app}\OpenSearch"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; OpenSearch index templates for TinySocs
Source: "..\opensearch\templates\*.json"; \
    DestDir: "{app}\OpenSearch\templates"; \
    Flags: ignoreversion

; --- TinyBox runtime seed payload (OPTIONAL at build time) ---
#if HasTinyBoxSeed
; TinyBox ProgramData seed payload present — installer can embed + optionally seed ProgramData.
#else
; TinyBox ProgramData seed payload NOT present — build will still succeed.
; In this case, TinySocs.Installer.psm1 MUST generate/repair ProgramData config at runtime.
#endif

; --- Seed: config ---
#if HasTinyBoxSeedConfig
Source: "..\opensearch\programdata\config\*"; \
    DestDir: "{app}\OpenSearch\seed\config"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
#endif

#if HasTinyBoxSeedConfig
Source: "..\opensearch\programdata\config\*"; \
    DestDir: "{commonappdata}\TinySocs\OpenSearch\config"; \
    Flags: ignoreversion recursesubdirs createallsubdirs onlyifdoesntexist
#endif

; --- Seed: certs (TLS material) ---
#if HasTinyBoxSeedCerts
Source: "..\opensearch\programdata\certs\*"; \
    DestDir: "{app}\OpenSearch\seed\config\certs"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
#endif

#if HasTinyBoxSeedCerts
Source: "..\opensearch\programdata\certs\*"; \
    DestDir: "{commonappdata}\TinySocs\OpenSearch\config\certs"; \
    Flags: ignoreversion recursesubdirs createallsubdirs onlyifdoesntexist
#endif

; NOTE: canonical certs location is {commonappdata}\TinySocs\OpenSearch\config\certs
; (do NOT also copy to {commonappdata}\TinySocs\OpenSearch\certs; avoid divergence/regressions)

; --- Seed: security config (OpenSearch Security plugin YAMLs) ---
; IMPORTANT: these must land under ProgramData\OpenSearch\config\opensearch-security
; (NOT under ProgramData\OpenSearch\security), otherwise the plugin will miss them.

#if HasTinyBoxSeedSecA
Source: "..\opensearch\programdata\opensearch-security\*"; \
    DestDir: "{app}\OpenSearch\seed\config\opensearch-security"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
#endif

#if HasTinyBoxSeedSecA
Source: "..\opensearch\programdata\opensearch-security\*"; \
    DestDir: "{commonappdata}\TinySocs\OpenSearch\config\opensearch-security"; \
    Flags: ignoreversion recursesubdirs createallsubdirs onlyifdoesntexist
#endif

#if HasTinyBoxSeedSecB
Source: "..\opensearch\programdata\security\*"; \
    DestDir: "{app}\OpenSearch\seed\config\opensearch-security"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
#endif

#if HasTinyBoxSeedSecB
Source: "..\opensearch\programdata\security\*"; \
    DestDir: "{commonappdata}\TinySocs\OpenSearch\config\opensearch-security"; \
    Flags: ignoreversion recursesubdirs createallsubdirs onlyifdoesntexist
#endif

; Ship the canonical runner script (PowerShell) for ProgramData and for repair.
#if HasTinyBoxSeedConfig
#if FileExists('..\opensearch\programdata\run-opensearch.ps1')
Source: "..\opensearch\programdata\run-opensearch.ps1"; \
    DestDir: "{app}\OpenSearch\seed"; \
    Flags: ignoreversion
Source: "..\opensearch\programdata\run-opensearch.ps1"; \
    DestDir: "{commonappdata}\TinySocs\OpenSearch"; \
    Flags: ignoreversion onlyifdoesntexist
#else
; If you do not ship run-opensearch.ps1 in packaging/opensearch/programdata, the module MUST generate it.
#endif
#endif

[Dirs]
Name: "{commonappdata}\TinySocs"
Name: "{commonappdata}\TinySocs\logs"; Permissions: users-modify
Name: "{commonappdata}\TinySocs\queue"
Name: "{commonappdata}\TinySocs\config"
Name: "{commonappdata}\TinySocs\rules"
Name: "{commonappdata}\TinySocs\anchors\state"
Name: "{commonappdata}\TinySocs\ledger"

; TinySocs collector agent directories under ProgramData
Name: "{commonappdata}\TinySocs\Collector"
Name: "{commonappdata}\TinySocs\Collector\agent"
Name: "{commonappdata}\TinySocs\Collector\agent\queue"
Name: "{commonappdata}\TinySocs\Collector\agent\bookmarks"
Name: "{commonappdata}\TinySocs\Collector\logs"; Permissions: users-modify

; TinyBox (OpenSearch) runtime directories under ProgramData
Name: "{commonappdata}\TinySocs\OpenSearch"
Name: "{commonappdata}\TinySocs\OpenSearch\config"
Name: "{commonappdata}\TinySocs\OpenSearch\config\certs"
Name: "{commonappdata}\TinySocs\OpenSearch\config\opensearch-security"
Name: "{commonappdata}\TinySocs\OpenSearch\data"
Name: "{commonappdata}\TinySocs\OpenSearch\logs"; Permissions: users-modify
Name: "{commonappdata}\TinySocs\OpenSearch\scripts"

[Run]
; Post-install configuration is handled in the [Code] ssPostInstall step.

[UninstallRun]
Filename: "cmd.exe"; \
  Parameters: "/c sc stop TinySocsOpenSearch >nul 2>&1 & sc stop TinySocsAgent >nul 2>&1 & sc stop TinySocsNode >nul 2>&1"; \
  Flags: runhidden

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""try {{ Get-CimInstance Win32_Process -Filter 'Name=''java.exe''' | Where-Object {{ $_.CommandLine -match 'TinySocs\\OpenSearch|opensearch' }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }} }} catch {{ }}"""; \
  Flags: runhidden

Filename: "cmd.exe"; \
  Parameters: "/c sc delete TinySocsOpenSearch >nul 2>&1 & sc delete TinySocsAgent >nul 2>&1 & sc delete TinySocsNode >nul 2>&1"; \
  Flags: runhidden

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""try {{ $ppid = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $PID)).ParentProcessId; $cmd = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $ppid)).CommandLine; $isUp = ($cmd -match '(?i)/UPGRADE|/UPDATE'); $flag = Join-Path $env:ProgramData 'TinySocs\remove_on_uninstall.flag'; Import-Module '{app}\modules\TinySocs.Installer.psm1' -Force; if ($isUp) {{ Uninstall-TinySocs -KeepData }} elseif (Test-Path $flag) {{ Uninstall-TinySocs }} else {{ Uninstall-TinySocs -KeepData }} }} catch {{ exit 0 }}"""; \
  Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Icons]
Name: "{group}\Operator README"; Filename: "{app}\modules\OPERATOR-README.txt"; WorkingDir: "{app}\modules"

[Code]

const
  ROLE_NODE    = 0;
  ROLE_MASTER  = 1;
  ROLE_TINYBOX = 2;

  { IMPORTANT: do NOT start lines with #13#10; ISPP can misread them as directives }
  CRLF = #13#10;

var
  RolePage: TWizardPage;
  ConfigPage: TWizardPage;
  SchedulePage: TWizardPage;

  RoleNodeRadio: TRadioButton;
  RoleMasterRadio: TRadioButton;
  RoleTinyBoxRadio: TRadioButton;

  RemoveDataCheck: TNewCheckBox;

  SharedSecretEdit: TNewEdit;
  NodePortEdit: TNewEdit;
  NodesEdit: TNewEdit;
  SiemUrlEdit: TNewEdit;
  SiemUserEdit: TNewEdit;
  SiemPassEdit: TNewEdit;
  TinyBoxCheck: TNewCheckBox;
  ResetTinyBoxConfigCheck: TNewCheckBox;

  HeartbeatEdit: TNewEdit;
  RetentionEdit: TNewEdit;

  SelectedRole: Integer;
  InstallTinyBox: Boolean;
  ForceTinyBoxConfig: Boolean;
  RemoveDataOnUninstall: Boolean;

  SharedSecret: String;
  NodePort: String;
  Nodes: String;
  SiemUrl: String;
  SiemUser: String;
  SiemPass: String;
  HeartbeatMinutes: Integer;
  AnchorsRetentionDays: Integer;

  PsRunCounter: Integer;

function PsEscape(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '''', '''''', True);
end;

function StartsWithHttps(const Url: String): Boolean;
var
  L: String;
begin
  L := Lowercase(Trim(Url));
  Result := Pos('https://', L) = 1;
end;

function IsLocalhostUrl(const Url: String): Boolean;
var
  L: String;
begin
  L := Lowercase(Trim(Url));
  Result :=
    (Pos('https://127.0.0.1', L) = 1) or
    (Pos('http://127.0.0.1', L) = 1) or
    (Pos('https://localhost', L) = 1) or
    (Pos('http://localhost', L) = 1);
end;

function BoolToPs(const B: Boolean): String;
begin
  if B then
    Result := '$true'
  else
    Result := '$false';
end;

function CmdLineParamExists(const Value: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Value) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

function SetEnvironmentVariable(lpName, lpValue: string): Integer;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';
function GetLastError: Integer;
  external 'GetLastError@kernel32.dll stdcall';

procedure SetProcessEnv(const Name: String; const Value: String);
var
  E: Integer;
begin
  try
    if SetEnvironmentVariable(Name, Value) = 0 then
    begin
      E := GetLastError;
      Log('SetProcessEnv: failed to set ' + Name + ' (GetLastError=' + IntToStr(E) + ' ' + SysErrorMessage(E) + ')');
    end
    else
      Log('SetProcessEnv: set ' + Name + ' (length=' + IntToStr(Length(Value)) + ')');
  except
    Log('SetProcessEnv: exception while setting ' + Name);
  end;
end;

function BoolToLogStr(const B: Boolean): String;
begin
  if B then
    Result := 'True'
  else
    Result := 'False';
end;

function RunPowerShellScript(const PsScript: String): Boolean;
var
  ResultCode: Integer;
  TmpFile: String;
  CmdLine: String;
  LogDir: String;
  LogFile: String;
  Started: Boolean;
  Header: String;
  Stage: Integer;
begin
  Result := False;
  Stage := 0;

  try
    Stage := 1;
    Log('RunPowerShellScript: enter (len=' + IntToStr(Length(PsScript)) + ')');

    Stage := 2;
    PsRunCounter := PsRunCounter + 1;
    Log('RunPowerShellScript: counter=' + IntToStr(PsRunCounter));

    Stage := 3;
    TmpFile := ExpandConstant('{tmp}\tinysocs-postinstall-' + IntToStr(PsRunCounter) + '.ps1');
    Log('RunPowerShellScript: tmp=' + TmpFile);

    Stage := 4;
    LogDir := ExpandConstant('{commonappdata}\TinySocs\logs');
    LogFile := LogDir + '\postinstall-powershell.log';
    Log('RunPowerShellScript: logfile=' + LogFile);

    Stage := 5;
    if (not DirExists(LogDir)) then
    begin
      if not ForceDirectories(LogDir) then
        Log('RunPowerShellScript: warning: could not create log dir: ' + LogDir);
    end;

    Stage := 6;
    try
      if FileExists(TmpFile) then
        DeleteFile(TmpFile);
    except
      Log('RunPowerShellScript: warning: could not delete existing tmp file');
    end;

    Stage := 7;
    if not SaveStringToFile(TmpFile, PsScript, False) then
    begin
      Log('RunPowerShellScript: SaveStringToFile failed for ' + TmpFile);
      Exit;
    end;

    Stage := 8;
    Header :=
      CRLF +
      '==== TinySocs PostInstall PowerShell run #' + IntToStr(PsRunCounter) + ' ====' + CRLF +
      'Script: ' + TmpFile + CRLF;

    Stage := 9;
    try
      SaveStringToFile(LogFile, Header, True);
    except
      Log('RunPowerShellScript: warning: could not append header to ' + LogFile);
    end;

    Stage := 10;
    CmdLine :=
      '/c ""powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + TmpFile + '"' +
      ' 1>>"' + LogFile + '" 2>>&1"';

    Stage := 11;
    ResultCode := -1;
    Started := Exec('cmd.exe', CmdLine, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    Stage := 12;
    Log('RunPowerShellScript: Exec started=' + BoolToLogStr(Started) + ' exitCode=' + IntToStr(ResultCode));

    Result := Started and (ResultCode = 0);

    Stage := 13;
    if Result then
    begin
      try
        DeleteFile(TmpFile);
      except
        Log('RunPowerShellScript: warning: could not delete tmp file');
      end;
    end
    else
      Log('RunPowerShellScript: keeping temp script for debugging: ' + TmpFile);

  except
    Log('RunPowerShellScript: UNHANDLED EXCEPTION at stage ' + IntToStr(Stage) + ': ' + GetExceptionMessage);
    Result := False;
  end;
end;

function GeneratePassword(Len: Integer): String;
var
  Alphabet: String;
  Seed: String;
  SeedVal: Integer;
  I: Integer;
  Idx: Integer;
  Ch: Char;
begin
  Alphabet :=
    'ABCDEFGHJKLMNPQRSTUVWXYZ' +
    'abcdefghijkmnopqrstuvwxyz' +
    '23456789' +
    '!@#$%^&*_-+=';

  Seed :=
    GetDateTimeString('yyyymmddhhnnsszzz', '', '') + '|' +
    GetEnv('COMPUTERNAME') + '|' +
    GetEnv('USERNAME') + '|' +
    IntToStr(Len);

  SeedVal := 0;
  for I := 1 to Length(Seed) do
  begin
    Ch := Seed[I];
    SeedVal := (SeedVal * 131 + Ord(Ch)) and $7FFFFFFF;
  end;

  if SeedVal = 0 then
    SeedVal := 1;

  Result := '';
  for I := 1 to Len do
  begin
    SeedVal := (SeedVal * 1103515245 + 12345) and $7FFFFFFF;
    Idx := (SeedVal mod Length(Alphabet)) + 1;
    Result := Result + Copy(Alphabet, Idx, 1);
  end;
end;

procedure InitializeWizard;
var
  L: TNewStaticText;
  FlagPath: String;
begin
  RolePage := CreateCustomPage(wpSelectDir, 'TinySocs Role', '');

  L := TNewStaticText.Create(RolePage.Surface);
  L.Parent := RolePage.Surface;
  L.Left := 0;
  L.Top := 0;
  L.Width := RolePage.SurfaceWidth;
  L.Caption := 'Select this machine''s TinySocs role.';

  RoleNodeRadio := TRadioButton.Create(RolePage.Surface);
  RoleNodeRadio.Parent := RolePage.Surface;
  RoleNodeRadio.Left := 0;
  RoleNodeRadio.Top := L.Top + 158;
  RoleNodeRadio.Width := RolePage.SurfaceWidth + 100;
  RoleNodeRadio.Height := ScaleY(24);
  RoleNodeRadio.Caption := '&Node';

  RoleMasterRadio := TRadioButton.Create(RolePage.Surface);
  RoleMasterRadio.Parent := RolePage.Surface;
  RoleMasterRadio.Left := 0;
  RoleMasterRadio.Top := RoleNodeRadio.Top + 130;
  RoleMasterRadio.Width := RolePage.SurfaceWidth + 100;
  RoleMasterRadio.Height := ScaleY(24);
  RoleMasterRadio.Caption := '&Master';

  RoleTinyBoxRadio := TRadioButton.Create(RolePage.Surface);
  RoleTinyBoxRadio.Parent := RolePage.Surface;
  RoleTinyBoxRadio.Left := 0;
  RoleTinyBoxRadio.Top := RoleMasterRadio.Top + 130;
  RoleTinyBoxRadio.Width := RolePage.SurfaceWidth + 100;
  RoleTinyBoxRadio.Height := ScaleY(24);
  RoleTinyBoxRadio.Caption := '&TinyBox (all-in-one)';

  ConfigPage := CreateCustomPage(RolePage.ID, 'Secrets and Endpoints', 'Configure shared secret, node endpoints, and SIEM settings.');

  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := 8;
  L.Caption := '&Shared secret (used between Master and Nodes):';

  SharedSecretEdit := TNewEdit.Create(ConfigPage.Surface);
  SharedSecretEdit.Parent := ConfigPage.Surface;
  SharedSecretEdit.Left := 0;
  SharedSecretEdit.Top := L.Top + 32;
  SharedSecretEdit.Width := ConfigPage.SurfaceWidth;
  SharedSecretEdit.PasswordChar := '*';

  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := SharedSecretEdit.Top + 60;
  L.Caption := '&Node port:';

  NodePortEdit := TNewEdit.Create(ConfigPage.Surface);
  NodePortEdit.Parent := ConfigPage.Surface;
  NodePortEdit.Left := 0;
  NodePortEdit.Top := L.Top + 32;
  NodePortEdit.Width := 80;
  NodePortEdit.Text := '8081';

  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := NodePortEdit.Top + 60;
  L.Caption := 'Node URL(s) for Master (comma-separated):';

  NodesEdit := TNewEdit.Create(ConfigPage.Surface);
  NodesEdit.Parent := ConfigPage.Surface;
  NodesEdit.Left := 0;
  NodesEdit.Top := L.Top + 32;
  NodesEdit.Width := ConfigPage.SurfaceWidth;
  NodesEdit.Text := 'http://127.0.0.1:8081';

  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := NodesEdit.Top + 60;
  L.Caption := 'SIEM URL (TinyBox local is https://127.0.0.1:9201):';

  SiemUrlEdit := TNewEdit.Create(ConfigPage.Surface);
  SiemUrlEdit.Parent := ConfigPage.Surface;
  SiemUrlEdit.Left := 0;
  SiemUrlEdit.Top := L.Top + 32;
  SiemUrlEdit.Width := ConfigPage.SurfaceWidth;
  SiemUrlEdit.Text := 'https://127.0.0.1:9201';

  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := SiemUrlEdit.Top + 60;
  L.Caption := 'SIEM user (TinyBox local admin user):';

  SiemUserEdit := TNewEdit.Create(ConfigPage.Surface);
  SiemUserEdit.Parent := ConfigPage.Surface;
  SiemUserEdit.Left := 0;
  SiemUserEdit.Top := L.Top + 32;
  SiemUserEdit.Width := ConfigPage.SurfaceWidth;
  SiemUserEdit.Text := 'admin';

  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := SiemUserEdit.Top + 60;
  L.Caption := 'SIEM password (TinyBox local admin password):';

  SiemPassEdit := TNewEdit.Create(ConfigPage.Surface);
  SiemPassEdit.Parent := ConfigPage.Surface;
  SiemPassEdit.Left := 0;
  SiemPassEdit.Top := L.Top + 32;
  SiemPassEdit.Width := ConfigPage.SurfaceWidth;
  SiemPassEdit.PasswordChar := '*';

  TinyBoxCheck := TNewCheckBox.Create(ConfigPage.Surface);
  TinyBoxCheck.Parent := ConfigPage.Surface;
  TinyBoxCheck.Left := 0;
  TinyBoxCheck.Top := SiemPassEdit.Top + 36;
  TinyBoxCheck.Width := ConfigPage.SurfaceWidth + 150;
  TinyBoxCheck.Height := ScaleY(24);
  TinyBoxCheck.Caption := 'Install &TinySocs local datastore (TinyBox SIEM) on this machine';
  TinyBoxCheck.Checked := False;

  ResetTinyBoxConfigCheck := TNewCheckBox.Create(ConfigPage.Surface);
  ResetTinyBoxConfigCheck.Parent := ConfigPage.Surface;
  ResetTinyBoxConfigCheck.Left := 0;
  ResetTinyBoxConfigCheck.Top := TinyBoxCheck.Top + 34;
  ResetTinyBoxConfigCheck.Width := ConfigPage.SurfaceWidth + 150;
  ResetTinyBoxConfigCheck.Height := ScaleY(24);
  ResetTinyBoxConfigCheck.Caption := 'Reset TinyBox ProgramData config (re-seed from installer payload)';
  ResetTinyBoxConfigCheck.Checked := False;

  SchedulePage := CreateCustomPage(ConfigPage.ID, 'Schedules and Retention', 'Configure TinySocs heartbeat and anchor retention.');

  L := TNewStaticText.Create(SchedulePage.Surface);
  L.Parent := SchedulePage.Surface;
  L.Left := 0;
  L.Top := 8;
  L.Caption := 'Heartbeat interval (minutes):';

  HeartbeatEdit := TNewEdit.Create(SchedulePage.Surface);
  HeartbeatEdit.Parent := SchedulePage.Surface;
  HeartbeatEdit.Left := 0;
  HeartbeatEdit.Top := L.Top + 32;
  HeartbeatEdit.Width := 80;
  HeartbeatEdit.Text := '15';

  L := TNewStaticText.Create(SchedulePage.Surface);
  L.Parent := SchedulePage.Surface;
  L.Left := 0;
  L.Top := HeartbeatEdit.Top + 60;
  L.Caption := 'Anchor retention (days):';

  RetentionEdit := TNewEdit.Create(SchedulePage.Surface);
  RetentionEdit.Parent := SchedulePage.Surface;
  RetentionEdit.Left := 0;
  RetentionEdit.Top := L.Top + 32;
  RetentionEdit.Width := 80;
  RetentionEdit.Text := '45';

  RemoveDataCheck := TNewCheckBox.Create(SchedulePage.Surface);
  RemoveDataCheck.Parent := SchedulePage.Surface;
  RemoveDataCheck.Left := 0;
  RemoveDataCheck.Top := RetentionEdit.Top + 60;
  RemoveDataCheck.Width := SchedulePage.SurfaceWidth + 150;
  RemoveDataCheck.Height := ScaleY(24);
  RemoveDataCheck.Caption := 'Remove all TinySocs data (logs, ledger, config) when uninstalling';
  RemoveDataCheck.Checked := False;

  FlagPath := ExpandConstant('{commonappdata}\TinySocs\remove_on_uninstall.flag');
  if FileExists(FlagPath) then
    RemoveDataCheck.Checked := True;

  SelectedRole := ROLE_NODE;
  InstallTinyBox := False;
  ForceTinyBoxConfig := False;
  AnchorsRetentionDays := 45;
  HeartbeatMinutes := 15;

  PsRunCounter := 0;
end;

function GetSelectedRole: Integer;
begin
  if RoleMasterRadio.Checked then
    Result := ROLE_MASTER
  else if RoleTinyBoxRadio.Checked then
    Result := ROLE_TINYBOX
  else
    Result := ROLE_NODE;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  TmpInt: Integer;
begin
  Result := True;

  if CurPageID = RolePage.ID then
  begin
    SelectedRole := GetSelectedRole;
    if (SelectedRole < ROLE_NODE) or (SelectedRole > ROLE_TINYBOX) then
    begin
      MsgBox('Please select a TinySocs role for this machine.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end
  else if CurPageID = ConfigPage.ID then
  begin
    SharedSecret := Trim(SharedSecretEdit.Text);
    if SharedSecret = '' then
    begin
      MsgBox('Shared secret is required.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    NodePort := Trim(NodePortEdit.Text);
    if NodePort = '' then
      NodePort := '8081';

    Nodes := Trim(NodesEdit.Text);
    if (Nodes = '') and ((SelectedRole = ROLE_MASTER) or (SelectedRole = ROLE_TINYBOX)) then
      Nodes := 'http://127.0.0.1:' + NodePort;

    SiemUrl := Trim(SiemUrlEdit.Text);
    SiemUser := Trim(SiemUserEdit.Text);
    SiemPass := SiemPassEdit.Text;

    InstallTinyBox := TinyBoxCheck.Checked or (SelectedRole = ROLE_TINYBOX);
    ForceTinyBoxConfig := ResetTinyBoxConfigCheck.Checked and InstallTinyBox;

    if InstallTinyBox then
      SiemUrl := 'https://127.0.0.1:9201'
    else if SiemUrl = '' then
      SiemUrl := 'https://127.0.0.1:9201';

    if InstallTinyBox then
    begin
      if SiemUser = '' then
        SiemUser := 'admin';

      if SiemPass = '' then
      begin
        SiemPass := GeneratePassword(24);
        MsgBox(
          'TinyBox password was blank, so one was generated.'#13#10#13#10 +
          'User: ' + SiemUser + #13#10 +
          'Password: ' + SiemPass + #13#10#13#10 +
          'It will also be stored in Windows Credential Manager as TinySocs/SIEM/Creds.',
          mbInformation,
          MB_OK
        );
      end;
    end;
  end
  else if CurPageID = SchedulePage.ID then
  begin
    TmpInt := StrToIntDef(Trim(HeartbeatEdit.Text), 15);
    if TmpInt <= 0 then
      TmpInt := 15;
    HeartbeatMinutes := TmpInt;

    TmpInt := StrToIntDef(Trim(RetentionEdit.Text), 45);
    if TmpInt <= 0 then
      TmpInt := 45;
    AnchorsRetentionDays := TmpInt;

    RemoveDataOnUninstall := RemoveDataCheck.Checked;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  InstallerModule: String;
  AppDir: String;
  MasterSiemUrl: String;
  Script: String;
  DataFlagFile: String;
  VerifyPs: String;
  ForceArg: String;
  PersistScriptPath: String;
begin
  if CurStep <> ssPostInstall then
    Exit;

  try
    Log('CurStepChanged(ssPostInstall): begin');

    AppDir := ExpandConstant('{app}');
    InstallerModule := AppDir + '\modules\TinySocs.Installer.psm1';
    PersistScriptPath := AppDir + '\modules\OpenSearch.Persistence.ps1';

    Log('CurStepChanged: AppDir=' + AppDir);
    Log('CurStepChanged: InstallerModule=' + InstallerModule);
    Log('CurStepChanged: PersistScript=' + PersistScriptPath);

    if InstallTinyBox then
    begin
      Log('CurStepChanged: InstallTinyBox=True');
      Log('STEP TB-1: defaults');

      if (SiemUser = '') then
        SiemUser := 'admin';

      if (SiemPass = '') then
        SiemPass := GeneratePassword(24);

      ForceArg := '';
      if ForceTinyBoxConfig then
        ForceArg := ' -ForceConfig';

      Log('STEP TB-2: SetProcessEnv TS_SIEM_USER');
      SetProcessEnv('TS_SIEM_USER', SiemUser);

      Log('STEP TB-3: SetProcessEnv TS_SIEM_PASS');
      SetProcessEnv('TS_SIEM_PASS', SiemPass);

      Log('STEP TB-4: build Install-TinySocsLocalSiem script');
      Script :=
        '$ErrorActionPreference = ''Stop''' + #13#10 +
        '$u = [Environment]::GetEnvironmentVariable(''TS_SIEM_USER'',''Process'')' + #13#10 +
        '$p = [Environment]::GetEnvironmentVariable(''TS_SIEM_PASS'',''Process'')' + #13#10 +
        'Import-Module ''' + InstallerModule + ''' -Force' + #13#10 +
        'Install-TinySocsLocalSiem -SiemUser $u -SiemPass $p -ApiPort 9201' + ForceArg + #13#10;

      Log('STEP TB-5: calling RunPowerShellScript(Install-TinySocsLocalSiem)');
      Log('CurStepChanged: running Install-TinySocsLocalSiem');
      if not RunPowerShellScript(Script) then
      begin
        Log('CurStepChanged: Install-TinySocsLocalSiem FAILED (see postinstall-powershell.log + temp script path above).');
        MsgBox('TinyBox install failed during Install-TinySocsLocalSiem. See ProgramData\TinySocs\logs\postinstall-powershell.log.', mbError, MB_OK);
        Abort;
      end;
      Log('STEP TB-6: returned from RunPowerShellScript(Install-TinySocsLocalSiem)');

      Log('STEP TB-7: build optional ProgramData repair script');
      Script :=
        'Import-Module ''' + InstallerModule + ''' -Force' + #13#10 +
        'if (Get-Command Repair-TinySocsTinyBoxProgramData -ErrorAction SilentlyContinue) {' + #13#10 +
        '  Repair-TinySocsTinyBoxProgramData -Force:' + BoolToPs(ForceTinyBoxConfig) + #13#10 +
        '}' + #13#10;

      Log('CurStepChanged: optional ProgramData repair (if implemented)');
      Log('STEP TB-8: calling RunPowerShellScript(Repair-TinySocsTinyBoxProgramData optional)');
      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Repair-TinySocsTinyBoxProgramData call failed (optional).');
      Log('STEP TB-9: returned from RunPowerShellScript(Repair-TinySocsTinyBoxProgramData optional)');

      Log('STEP TB-10: enforce deterministic OpenSearch TLS+port persistence (OpenSearch.Persistence.ps1)');
      Script :=
        '$ErrorActionPreference = ''Stop''' + #13#10 +
        '& ''' + PsEscape(PersistScriptPath) + ''' -ConfDir ''C:\ProgramData\TinySocs\OpenSearch\config'' -ServiceName ''TinySocsOpenSearch'' -HttpPort 9201 -NetworkHost ''127.0.0.1''' + #13#10;
      if not RunPowerShellScript(Script) then
      begin
        Log('CurStepChanged: OpenSearch.Persistence.ps1 FAILED (this is NOT optional).');
        MsgBox('TinyBox install failed during OpenSearch.Persistence.ps1. See ProgramData\TinySocs\logs\postinstall-powershell.log.', mbError, MB_OK);
        Abort;
      end;

      Log('STEP TB-11: build SIEM_CA_CERT env set script');
      Script :=
        '$certDir = Join-Path $env:ProgramData ''TinySocs\OpenSearch\config\certs''' + #13#10 +
        '$candidates = @(' +
        '  (Join-Path $certDir ''ca.crt''),' +
        '  (Join-Path $certDir ''ca.pem''),' +
        '  (Join-Path $certDir ''root-ca.pem''),' +
        '  (Join-Path $certDir ''root-ca.crt''),' +
        '  (Join-Path $certDir ''root-ca.cer'')' +
        ')' + #13#10 +
        '$ca = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1' + #13#10 +
        'if (-not $ca) {' + #13#10 +
        '  try { $ca = Get-ChildItem -Path $certDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match ''(?i)^ca\.(crt|pem|cer)$'' } | Select-Object -First 1 | ForEach-Object { $_.FullName } } catch { }' + #13#10 +
        '}' + #13#10 +
        'if ($ca) {' + #13#10 +
        '  [Environment]::SetEnvironmentVariable(''SIEM_CA_CERT'', [string]$ca, ''Machine'')' + #13#10 +
        '  [Environment]::SetEnvironmentVariable(''SIEM_CA_CERT'', [string]$ca, ''Process'')' + #13#10 +
        '}' + #13#10;

      Log('CurStepChanged: best-effort SIEM_CA_CERT env set for TinyBox');
      Log('STEP TB-12: calling RunPowerShellScript(SIEM_CA_CERT optional)');
      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: SIEM_CA_CERT env set script failed (optional).');
      Log('STEP TB-13: returned from RunPowerShellScript(SIEM_CA_CERT optional)');

      Log('STEP TB-14: build OpenSearch security bootstrap optional');
      Script :=
        'Import-Module ''' + InstallerModule + ''' -Force' + #13#10 +
        'if (Get-Command Initialize-TinySocsOpenSearchSecurity -ErrorAction SilentlyContinue) {' + #13#10 +
        '  Initialize-TinySocsOpenSearchSecurity ' +
        '    -SiemUrl ''https://127.0.0.1:9201'' ' +
        '    -AdminUser ''' + PsEscape(SiemUser) + ''' ' +
        '    -AdminPass ''' + PsEscape(SiemPass) + ''' ' +
        '    -ServiceUser ''tinysocs'' ' +
        '    -SkipTlsVerify' + #13#10 +
        '}' + #13#10;

      Log('CurStepChanged: optional OpenSearch security bootstrap / CredMan (if implemented)');
      Log('STEP TB-15: calling RunPowerShellScript(Initialize-TinySocsOpenSearchSecurity optional)');
      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Initialize-TinySocsOpenSearchSecurity call failed (optional).');
      Log('STEP TB-16: returned from RunPowerShellScript(Initialize-TinySocsOpenSearchSecurity optional)');
    end
    else
      Log('CurStepChanged: InstallTinyBox=False');

    if (SelectedRole = ROLE_NODE) or (SelectedRole = ROLE_TINYBOX) then
    begin
      Log('CurStepChanged: doing node pairing');

      if InstallTinyBox then
        SiemUrl := 'https://127.0.0.1:9201'
      else if SiemUrl = '' then
        SiemUrl := 'https://127.0.0.1:9201';

      VerifyPs := BoolToPs(StartsWithHttps(SiemUrl) and (InstallTinyBox or (not IsLocalhostUrl(SiemUrl))));

      Script :=
        'Import-Module ''' + InstallerModule + ''' -Force' + #13#10 +
        'Pair-TinySocs -Role Node ' +
        '-SharedSecret ''' + PsEscape(SharedSecret) + ''' ' +
        '-NodePort ''' + PsEscape(NodePort) + ''' ' +
        '-SiemUrl ''' + PsEscape(SiemUrl) + ''' ' +
        '-SiemSslVerify:' + VerifyPs + #13#10;

      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Pair-TinySocs (Node) FAILED.');

      Script :=
        '$port = ''' + PsEscape(NodePort) + '''' + #13#10 +
        'if ([string]::IsNullOrWhiteSpace($port)) { $port = ''8081'' }' + #13#10 +
        '$name = ''TinySocsNode-'' + $port' + #13#10 +
        'try { & netsh advfirewall firewall show rule name="$name" >$null 2>&1 } catch { }' + #13#10 +
        'if ($LASTEXITCODE -ne 0) {' + #13#10 +
        '  try { & netsh advfirewall firewall add rule name="$name" dir=in action=allow protocol=TCP localport=$port profile=domain,private | Out-Null } catch { }' + #13#10 +
        '}' + #13#10;

      Log('CurStepChanged: ensuring inbound firewall rule for Node port');
      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: firewall rule script FAILED (optional).');
    end
    else
      Log('CurStepChanged: skipping node pairing');

    if (SelectedRole = ROLE_MASTER) or (SelectedRole = ROLE_TINYBOX) then
    begin
      Log('CurStepChanged: doing master pairing');

      if InstallTinyBox then
        MasterSiemUrl := 'https://127.0.0.1:9201'
      else if SiemUrl <> '' then
        MasterSiemUrl := SiemUrl
      else
        MasterSiemUrl := 'https://127.0.0.1:9201';

      VerifyPs := BoolToPs(StartsWithHttps(MasterSiemUrl) and (InstallTinyBox or (not IsLocalhostUrl(MasterSiemUrl))));

      Script :=
        'Import-Module ''' + InstallerModule + ''' -Force' + #13#10 +
        'Pair-TinySocs -Role Master ' +
        '-SharedSecret ''' + PsEscape(SharedSecret) + ''' ' +
        '-Nodes ''' + PsEscape(Nodes) + ''' ' +
        '-SiemUrl ''' + PsEscape(MasterSiemUrl) + ''' ' +
        '-SiemUser ''' + PsEscape(SiemUser) + ''' ' +
        '-SiemPass ''' + PsEscape(SiemPass) + ''' ' +
        '-SiemSslVerify:' + VerifyPs + ' ' +
        '-AnchorsRetentionDays ' + IntToStr(AnchorsRetentionDays) + ' ' +
        '-HeartbeatMinutes ' + IntToStr(HeartbeatMinutes) + #13#10;

      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Pair-TinySocs (Master) FAILED.');
    end
    else
      Log('CurStepChanged: skipping master pairing');

    Log('CurStepChanged: installing agent service');
    Script :=
      'Import-Module ''' + InstallerModule + ''' -Force' + #13#10 +
      'Install-TinySocsAgentService' + #13#10;

    if not RunPowerShellScript(Script) then
      Log('CurStepChanged: Install-TinySocsAgentService FAILED.');

    if InstallTinyBox then
    begin
      Log('CurStepChanged: configuring service dependencies');
      Script :=
        'sc.exe config TinySocsAgent depend= TinySocsOpenSearch' + #13#10 +
        'sc.exe config TinySocsNode depend= TinySocsOpenSearch' + #13#10 +
        'sc.exe failure TinySocsOpenSearch reset= 86400 actions= restart/5000/restart/5000/restart/5000' + #13#10;

      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: service dependency script FAILED (optional).');
    end;

    if InstallTinyBox then
    begin
      Script :=
        'Import-Module ''' + InstallerModule + ''' -Force' + #13#10 +
        'if (Get-Command Test-TinySocsOpenSearch -ErrorAction SilentlyContinue) {' + #13#10 +
        '  Test-TinySocsOpenSearch -SiemUrl ''https://127.0.0.1:9201'' -User ''' + PsEscape(SiemUser) + ''' -Pass ''' + PsEscape(SiemPass) + ''' -Cleanup' + #13#10 +
        '}' + #13#10;

      Log('CurStepChanged: optional TinyBox smoketest (if implemented)');
      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Test-TinySocsOpenSearch call failed (optional).');
    end;

    DataFlagFile := ExpandConstant('{commonappdata}\\TinySocs\\remove_on_uninstall.flag');
    if RemoveDataOnUninstall then
      SaveStringToFile(DataFlagFile, '1', False)
    else if FileExists(DataFlagFile) then
      DeleteFile(DataFlagFile);

    Log('CurStepChanged(ssPostInstall): end');
  except
    Log('CurStepChanged: exception: ' + GetExceptionMessage);
    Log('CurStepChanged: continuing install.');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataRoot: String;
  FlagPath: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;

  if CmdLineParamExists('/UPGRADE') or CmdLineParamExists('/UPDATE') then
  begin
    Log('CurUninstallStepChanged: upgrade detected; skipping ProgramData removal.');
    Exit;
  end;

  DataRoot := ExpandConstant('{commonappdata}\TinySocs');
  FlagPath := DataRoot + '\remove_on_uninstall.flag';

  if FileExists(FlagPath) then
  begin
    DelTree(DataRoot, True, True, True);
  end;
end;