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

; ------------------------------------------------------------
; OpenSearch config-template source selection
; ------------------------------------------------------------
; Preferred: repo-provided golden template under packaging\opensearch\config-template
#define HasRepoConfigTemplate (DirExists('..\opensearch\config-template'))

; Fallback: use vendor OpenSearch config as the golden template
#define HasVendorConfigTemplate (DirExists('..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\config'))

; PATCH(2026-01-15): Vendor cert fallback (if repo seed cert payload is absent)
#define HasVendorCerts (DirExists('..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\config\certs'))

[Setup]
AppName=TinySocs
AppVersion=0.7.1
AppPublisher=TinySocs
AppId={{F2DCCF8F-6F5F-4D8B-9EAF-6E2C2C6B1234}}
DefaultDirName={commonpf}\TinySocs
DefaultGroupName=TinySocs

; PATCH: hard-require 64-bit OS (OpenSearch + win-x64 agent payloads)
ArchitecturesAllowed=x64compatible
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
Source: "..\..\modules\TinySocs.Installer.psm1";   DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\TinySocs.Uninstall.ps1";    DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\TinySocs.RotateQueue.ps1";  DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Master.ps1";         DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Anchors.ps1";        DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\OPERATOR-README.txt";       DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\PostInstall.ps1";           DestDir: "{app}\modules"; Flags: ignoreversion

; OpenSearch persistence script (deterministic TLS + ports)
Source: ".\scripts\OpenSearch.Persistence.ps1";   DestDir: "{app}\modules"; Flags: ignoreversion

; --- TinySocs OpenSearch runner (PowerShell) ---
; Put a copy under {app}\scripts (seed) AND {commonappdata}\TinySocs\OpenSearch (runtime)
Source: "..\..\installer\Run-OpenSearch.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion overwritereadonly
Source: "..\..\installer\Run-OpenSearch.ps1"; DestDir: "{commonappdata}\TinySocs\OpenSearch"; Flags: ignoreversion overwritereadonly

; --- Build-time sanity checks for vendor payloads + payload copy ---

#if FileExists('..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\bin\opensearch.bat')
; OpenSearch vendor payload present
#else
#error "OpenSearch vendor payload missing. Extract opensearch-3.3.2-windows-x64.zip into vendor\opensearch-3.3.2-windows-x64"
#endif

Source: "..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\*"; \
    DestDir: "{app}\OpenSearch"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; --- OpenSearch config template (golden copy shipped with installer) ---
; Mirror a full config tree into {app}\OpenSearch\config-template (so PS can copy it to ProgramData deterministically)
; Prefer repo-provided template; otherwise fall back to vendor OpenSearch config.
#if HasRepoConfigTemplate
Source: "..\opensearch\config-template\*"; \
    DestDir: "{app}\OpenSearch\config-template"; \
    Flags: recursesubdirs createallsubdirs ignoreversion overwritereadonly uninsneveruninstall
#else
#if HasVendorConfigTemplate
Source: "..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\config\*"; \
    DestDir: "{app}\OpenSearch\config-template"; \
    Flags: recursesubdirs createallsubdirs ignoreversion overwritereadonly uninsneveruninstall
#else
; Last resort: do not fail the build. TinySocs.Installer.psm1 MUST generate/repair ProgramData config at runtime.
; (Leaving this as a comment because [Files] lines cannot be conditional at runtime.)
#endif
#endif

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

; PATCH(2026-01-15): Vendor certs fallback when repo seed certs are absent.
; This helps avoid "admin-keystore.p12 must be exported" paths by ensuring there are .p12 candidates to alias.
#if !HasTinyBoxSeedCerts && HasVendorCerts
Source: "..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\config\certs\*"; \
    DestDir: "{app}\OpenSearch\seed\config\certs"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
#endif

#if !HasTinyBoxSeedCerts && HasVendorCerts
Source: "..\..\vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\config\certs\*"; \
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

; --- OpenSearch config template (golden copy shipped with installer) ---
Name: "{app}\OpenSearch\config-template"; Flags: uninsneveruninstall

[Run]
; Post-install configuration is handled in the [Code] ssPostInstall step.

[UninstallRun]
; IMPORTANT:
; Do NOT embed PowerShell scriptblocks ({ ... }) here — Inno treats {X} as constants and the compiler will explode.
; Use a dedicated uninstall script instead. It will:
;   - detect upgrade (/UPGRADE|/UPDATE) and keep ProgramData
;   - respect remove_on_uninstall.flag for full removal
;   - stop + delete services
;   - kill leftover opensearch/java processes
;
; PATCH: add -FromInnoUninstall so the script can refuse accidental execution during install/repair/etc.
; PATCH: DO NOT use {sysnative} here — sysnative only exists from a 32-bit process; uninstall may run 64-bit.
;        {sys} resolves correctly in both 64-bit and 32-bit contexts (System32 vs SysWOW64) and avoids "path not found".
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\modules\TinySocs.Uninstall.ps1"" -FromInnoUninstall"; \
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

function GetPowerShellExePath: String;
var
  P: String;
  WinDir: String;
  Pf: String;
  PfW6432: String;
begin
  { PATCH v12 (2026-01-14): Prefer PowerShell 7 (pwsh.exe) if present.
    Rationale: TinySocs modules may use newer syntax (e.g., ??) not supported by Windows PowerShell 5.1. }

  Pf := GetEnv('ProgramFiles');
  PfW6432 := GetEnv('ProgramW6432');

  if PfW6432 <> '' then
  begin
    P := PfW6432 + '\PowerShell\7\pwsh.exe';
    if FileExists(P) then
    begin
      Result := P;
      Exit;
    end;
  end;

  if Pf <> '' then
  begin
    P := Pf + '\PowerShell\7\pwsh.exe';
    if FileExists(P) then
    begin
      Result := P;
      Exit;
    end;
  end;

  { Prefer sysnative ONLY if it actually exists (it only exists from 32-bit on 64-bit OS) }
  if IsWin64 then
  begin
    P := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
    if FileExists(P) then
    begin
      Result := P;
      Exit;
    end;
  end;

  (* The {sys} constant resolves correctly in both contexts (System32 in 64-bit, SysWOW64 in 32-bit). *)
  P := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if FileExists(P) then
  begin
    Result := P;
    Exit;
  end;

  { Absolute fallbacks }
  WinDir := GetEnv('WINDIR');
  if WinDir = '' then
    WinDir := GetEnv('SystemRoot');

  if WinDir <> '' then
  begin
    P := WinDir + '\System32\WindowsPowerShell\v1.0\powershell.exe';
    if FileExists(P) then
    begin
      Result := P;
      Exit;
    end;

    P := WinDir + '\SysWOW64\WindowsPowerShell\v1.0\powershell.exe';
    if FileExists(P) then
    begin
      Result := P;
      Exit;
    end;
  end;

  { Last-ditch: rely on PATH }
  Result := 'powershell.exe';
end;

function RunPowerShellScript(const PsScript: String): Boolean;
var
  ResultCode: Integer;
  TmpFile: String;
  LogDir: String;
  LogFile: String;
  Started: Boolean;
  Header: String;
  Stage: Integer;
  PsExe: String;
  AppDir: String;
  FinalScript: String;
  Params: String;
  PsCmd: String;
  Err: Integer;
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
    Log('RunPowerShellScript: logdir=' + LogDir);
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
    AppDir := ExpandConstant('{app}');
    Log('RunPowerShellScript: appdir=' + AppDir);

    Stage := 8;
    FinalScript :=
      '$ErrorActionPreference = ''Continue''' + CRLF +
      'try {' + CRLF +
      '  $tsApp = ''' + PsEscape(AppDir) + '''' + CRLF +
      '  if ($tsApp -and (Test-Path -LiteralPath $tsApp)) { Set-Location -LiteralPath $tsApp }' + CRLF +
      '} catch { }' + CRLF +
      'Write-Host (''[TinySocs] PWD='' + (Get-Location).Path)' + CRLF +
      'Write-Host (''[TinySocs] User='' + [Environment]::UserName)' + CRLF +
      'Write-Host (''[TinySocs] PS='' + $PSVersionTable.PSVersion.ToString())' + CRLF +
      CRLF +
      PsScript;

    if not SaveStringToFile(TmpFile, FinalScript, False) then
    begin
      Log('RunPowerShellScript: SaveStringToFile failed for ' + TmpFile);
      Exit;
    end;

    Stage := 9;
    PsExe := GetPowerShellExePath;
    Log('RunPowerShellScript: psExe=' + PsExe);

    (* If we resolved to a concrete path, it must exist *)
    if (Pos('\', PsExe) > 0) and (not FileExists(PsExe)) then
    begin
      Log('RunPowerShellScript: ERROR powershell not found at: ' + PsExe);
      try
        SaveStringToFile(LogFile, 'ERROR: powershell not found at: ' + PsExe + CRLF, True);
      except
      end;
      Exit;
    end;

    Stage := 10;
    Header :=
      CRLF +
      '==== TinySocs PostInstall PowerShell run #' + IntToStr(PsRunCounter) + ' ====' + CRLF +
      'Script: ' + TmpFile + CRLF +
      'AppDir: ' + AppDir + CRLF +
      'PsExe: ' + PsExe + CRLF +
      'LogFile: ' + LogFile + CRLF;

    try
      SaveStringToFile(LogFile, Header, True);
    except
      Log('RunPowerShellScript: warning: could not append header to ' + LogFile);
    end;

    Stage := 11;
    (* Run PowerShell directly; do NOT involve cmd.exe.
       Log capture is done inside PowerShell via Start-Transcript. *)

    PsCmd :=
      '$log = ''' + PsEscape(LogFile) + '''; ' +
      'try { $ld = Split-Path -Parent $log; if ($ld) { New-Item -ItemType Directory -Force -Path $ld | Out-Null } } catch { }; ' +
      'Start-Transcript -Path $log -Append | Out-Null; ' +
      'try { & ''' + PsEscape(TmpFile) + ''' } finally { try { Stop-Transcript | Out-Null } catch { } }; ' +
      'exit $LASTEXITCODE';

    Params :=
      '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + PsCmd + '"';

    Log('RunPowerShellScript: params(len)=' + IntToStr(Length(Params)));

    ResultCode := -1;
    Started := Exec(PsExe, Params, AppDir, SW_HIDE, ewWaitUntilTerminated, ResultCode);

    Stage := 12;
    Log('RunPowerShellScript: Exec started=' + BoolToLogStr(Started) + ' exitCode=' + IntToStr(ResultCode));

    if not Started then
    begin
      Err := GetLastError;
      Log('RunPowerShellScript: Exec failed GetLastError=' + IntToStr(Err) + ' ' + SysErrorMessage(Err));
      try
        SaveStringToFile(LogFile, 'ERROR: Exec failed GetLastError=' + IntToStr(Err) + ' ' + SysErrorMessage(Err) + CRLF, True);
      except
      end;
      Exit;
    end;

    Result := (ResultCode = 0);

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

  { PATCH: make the default selection explicit (removes “blank role” ambiguity) }
  RoleNodeRadio.Checked := True;

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

  { PATCH: ensure a deterministic default even if wizard pages are skipped (e.g., /SILENT) }
  RemoveDataOnUninstall := False;

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
  Script: String;
  PersistScriptPath: String;
  DidRunLocalSiem: Boolean;
begin
  if CurStep <> ssPostInstall then
    Exit;

  DidRunLocalSiem := False;

  try
    Log('CurStepChanged(ssPostInstall): begin');

    { *** BUILD STAMP (change this every rebuild) *** }
    Log('TinySocs installer build stamp: 2026-01-16-POSTINSTALL-ORDER-v15-KEYSTORE-ACL');

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

      { PATCH(2026-01-16): DO NOT default blank password to "admin".
        If we're here and it's blank (e.g. silent installs), generate one deterministically. }
      if (SiemPass = '') then
      begin
        SiemPass := GeneratePassword(24);
        Log('CurStepChanged: SiemPass was blank at ssPostInstall; generated a password (stored later in CredMan).');
      end;

      { PATCH(2026-01-16): keep TB-12 before cred probe, but ALSO repair keystore ACLs
        (pre and post) anywhere the keystore can be created/touched. }
      Log('ORDER CHECK: running ONE deterministic PS chain: TB-7 -> TB-10 -> TB-11 -> TB-12 -> CRED PRESET -> TB-3 (conditional)');

      Script :=
        '$ErrorActionPreference = ''Stop''' + #13#10 +
        '$ProgressPreference = ''SilentlyContinue''' + #13#10 +
        'Write-Host ''[TinySocs][Inno] build stamp: 2026-01-16-POSTINSTALL-ORDER-v15-KEYSTORE-ACL''' + #13#10 +
        '' + #13#10 +

        '# Force TEMP/TMP to ProgramData AND harden ACL so stashes never land in user-profile temp (avoids ACL/AV weirdness)' + #13#10 +
        '$tsTmp = Join-Path $env:ProgramData ''TinySocs\tmp''' + #13#10 +
        'try { New-Item -ItemType Directory -Force -Path $tsTmp | Out-Null } catch { }' + #13#10 +
        '$who = $null; try { $who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who = $env:USERNAME }' + #13#10 +
        'try {' + #13#10 +
        '  & icacls.exe $tsTmp /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who + ":(OI)(CI)F") /T /C | Out-Null' + #13#10 +
        '} catch { }' + #13#10 +
        '$env:TEMP = $tsTmp' + #13#10 +
        '$env:TMP  = $tsTmp' + #13#10 +
        'Write-Host (''[TinySocs][Inno] TEMP='' + $env:TEMP)' + #13#10 +
        '' + #13#10 +

        '# Transcript (best-effort) so we always have a decisive log on the installed machine' + #13#10 +
        '$tsLogDir = Join-Path $env:ProgramData ''TinySocs\logs''' + #13#10 +
        'try { New-Item -ItemType Directory -Force -Path $tsLogDir | Out-Null } catch { }' + #13#10 +
        '$tsTranscript = Join-Path $tsLogDir (''postinstall-powershell-'' + (Get-Date -Format ''yyyyMMdd-HHmmss'') + ''.log'')' + #13#10 +
        'try { Start-Transcript -Path $tsTranscript -Append | Out-Null } catch { }' + #13#10 +
        '' + #13#10 +

        '$u_in = ''' + PsEscape(SiemUser) + '''' + #13#10 +
        '$p_in = ''' + PsEscape(SiemPass) + '''' + #13#10 +
        '$siemUrl = ''https://127.0.0.1:9201''  # do not use localhost; keep cert/SAN behaviour consistent' + #13#10 +
        'Import-Module ''' + PsEscape(InstallerModule) + ''' -Force' + #13#10 +
        '' + #13#10 +

        '# PATCH(2026-01-15): Always overwrite CredMan from wizard inputs for local TinyBox determinism' + #13#10 +
        'try {' + #13#10 +
        '  if (Get-Command Set-TinySocsSiemCredential -ErrorAction SilentlyContinue) {' + #13#10 +
        '    $sc = Get-Command Set-TinySocsSiemCredential -ErrorAction Stop' + #13#10 +
        '    $sp = @{}' + #13#10 +
        '    if ($sc.Parameters.ContainsKey(''SiemUrl''))       { $sp.SiemUrl = $siemUrl }' + #13#10 +
        '    if ($sc.Parameters.ContainsKey(''SiemUser''))      { $sp.SiemUser = $u_in }' + #13#10 +
        '    if ($sc.Parameters.ContainsKey(''SiemPass''))      { $sp.SiemPass = $p_in }' + #13#10 +
        '    if ($sc.Parameters.ContainsKey(''SiemSslVerify'')) { $sp.SiemSslVerify = $false }' + #13#10 +
        '    & $sc @sp | Out-Null' + #13#10 +
        '    Write-Host (''[TinySocs][Inno] Forced CredMan TinySocs/SIEM/Creds from wizard inputs (sslVerify=false, url='' + $siemUrl + '')'')' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] Failed to force SIEM creds from wizard (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +

        'function _http($user,$pass,$path) {' + #13#10 +
        '  try {' + #13#10 +
        '    $pair = ($user + '':'' + $pass)' + #13#10 +
        '    $code = & curl.exe -k -s -o NUL -w ''%{http_code}'' -u $pair ($siemUrl + $path) 2>$null' + #13#10 +
        '    if (-not $code) { $code = ''000'' }' + #13#10 +
        '    return [string]$code' + #13#10 +
        '  } catch { return ''000'' }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        'function _curl_i($path) {' + #13#10 +
        '  try {' + #13#10 +
        '    return (& curl.exe -k -sS -i ($siemUrl + $path) 2>&1 | Out-String)' + #13#10 +
        '  } catch { return (''EXC: '' + $_.Exception.Message) }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        'function _code_from_i($out) {' + #13#10 +
        '  try {' + #13#10 +
        '    $m = [regex]::Match($out, ''HTTP/(1\.1|2)\s+(\d{3})'')' + #13#10 +
        '    if ($m.Success) { return $m.Groups[2].Value }' + #13#10 +
        '    return ''000''' + #13#10 +
        '  } catch { return ''000'' }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        '# PATCH: Avoid Export-PfxCertificate non-exportable failures by ensuring an admin-keystore.p12 exists via alias/copy' + #13#10 +
        'function _ensure_admin_p12($certsDir) {' + #13#10 +
        '  $target = Join-Path $certsDir ''admin-keystore.p12''' + #13#10 +
        '  if (Test-Path -LiteralPath $target) {' + #13#10 +
        '    Write-Host (''[TinySocs][Inno] admin-keystore.p12 already present: '' + $target)' + #13#10 +
        '    return $true' + #13#10 +
        '  }' + #13#10 +
        '  try {' + #13#10 +
        '    $cands = @()' + #13#10 +
        '    $all = @(Get-ChildItem -LiteralPath $certsDir -Filter ''*.p12'' -ErrorAction SilentlyContinue)' + #13#10 +
        '    if (-not $all -or $all.Count -eq 0) {' + #13#10 +
        '      Write-Warning (''[TinySocs][Inno] No .p12 files found in certs dir to alias as admin-keystore.p12: '' + $certsDir)' + #13#10 +
        '      return $false' + #13#10 +
        '    }' + #13#10 +
        '    $rank = @(''admin-keystore.p12'',''admin.p12'',''kirk-keystore.p12'',''kirk.p12'')' + #13#10 +
        '    foreach ($name in $rank) {' + #13#10 +
        '      $m = $all | Where-Object { $_.Name -ieq $name } | Select-Object -First 1' + #13#10 +
        '      if ($m) { $cands += $m }' + #13#10 +
        '    }' + #13#10 +
        '    if ($cands.Count -eq 0) {' + #13#10 +
        '      $m = $all | Where-Object { $_.Name -match ''admin'' } | Select-Object -First 1' + #13#10 +
        '      if ($m) { $cands += $m }' + #13#10 +
        '    }' + #13#10 +
        '    if ($cands.Count -eq 0) {' + #13#10 +
        '      $m = $all | Where-Object { $_.Name -match ''kirk'' } | Select-Object -First 1' + #13#10 +
        '      if ($m) { $cands += $m }' + #13#10 +
        '    }' + #13#10 +
        '    if ($cands.Count -eq 0) { $cands += ($all | Select-Object -First 1) }' + #13#10 +
        '    $src = $cands[0].FullName' + #13#10 +
        '    Copy-Item -LiteralPath $src -Destination $target -Force' + #13#10 +
        '    Write-Host (''[TinySocs][Inno] Aliased admin-keystore.p12 from '' + $src + '' -> '' + $target)' + #13#10 +
        '    return (Test-Path -LiteralPath $target)' + #13#10 +
        '  } catch {' + #13#10 +
        '    Write-Warning (''[TinySocs][Inno] Failed to alias admin-keystore.p12: '' + $_.Exception.Message)' + #13#10 +
        '    return $false' + #13#10 +
        '  }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        'Write-Host ''[TinySocs][Inno] TB-7 (optional): Repair-TinySocsTinyBoxProgramData''' + #13#10 +
        'try {' + #13#10 +
        '  if (Get-Command Repair-TinySocsTinyBoxProgramData -ErrorAction SilentlyContinue) {' + #13#10 +
        '    Repair-TinySocsTinyBoxProgramData -Force:' + BoolToPs(ForceTinyBoxConfig) + #13#10 +
        '  }' + #13#10 +
        '} catch {' + #13#10 +
        '  Write-Warning (''[TinySocs][Inno] TB-7 optional repair failed (continuing): '' + $_.Exception.Message)' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        'Write-Host ''[TinySocs][Inno] TB-10 (HARD): Ensure service exists + ProgramData OPENSEARCH_PATH_CONF + TLS keystore repair''' + #13#10 +
        '$svcName  = ''TinySocsOpenSearch''' + #13#10 +
        '$pdConf   = Join-Path $env:ProgramData ''TinySocs\OpenSearch\config''' + #13#10 +
        '$certsDir = Join-Path $pdConf ''certs''' + #13#10 +
        '$pdYml    = Join-Path $pdConf ''opensearch.yml''' + #13#10 +
        'if (-not (Test-Path -LiteralPath $pdConf))   { throw (''ProgramData OpenSearch config dir missing: '' + $pdConf) }' + #13#10 +
        'if (-not (Test-Path -LiteralPath $certsDir)) { throw (''ProgramData OpenSearch certs dir missing: '' + $certsDir) }' + #13#10 +
        '' + #13#10 +

        '# PATCH(2026-01-15): Fix ProgramData OpenSearch ACLs so keystore CLI can read opensearch.yml (prevents AccessDeniedException)' + #13#10 +
        'try {' + #13#10 +
        '  # Clear read-only flags that can be inherited from payload extracts' + #13#10 +
        '  try { attrib.exe -R $pdConf /S /D | Out-Null } catch { }' + #13#10 +
        '  $who2 = $null; try { $who2 = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $who2 = $env:USERNAME }' + #13#10 +
        '  & icacls.exe $pdConf /inheritance:e /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" ($who2 + ":(OI)(CI)F") /T /C | Out-Null' + #13#10 +
        '  if (Test-Path -LiteralPath $pdYml) {' + #13#10 +
        '    & icacls.exe $pdYml /inheritance:e /grant:r "SYSTEM:F" "Administrators:F" ($who2 + ":F") /C | Out-Null' + #13#10 +
        '  }' + #13#10 +
        '  Write-Host ''[TinySocs][Inno] TB-10: ensured ACLs/attrs on ProgramData OpenSearch config''' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-10: ACL fix failed (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +

        'try {' + #13#10 +
        '  $osSvcs = Get-Service -Name ''*OpenSearch*'' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name' + #13#10 +
        '  if ($osSvcs) { Write-Host (''[TinySocs][Inno] Services matching *OpenSearch*: '' + ($osSvcs -join '', '')) } else { Write-Host ''[TinySocs][Inno] Services matching *OpenSearch*: (none)'' }' + #13#10 +
        '} catch { }' + #13#10 +
        '' + #13#10 +
        '$svc = $null' + #13#10 +
        'try { $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue } catch { $svc = $null }' + #13#10 +
        'if (-not $svc) {' + #13#10 +
        '  Write-Host (''[TinySocs][Inno] TB-10: service '' + $svcName + '' missing; attempting to register via installer module...'')' + #13#10 +
        '  foreach ($fn in @(''Ensure-TinySocsOpenSearchService'',''Ensure-TinySocsOpenSearchWindowsService'',''Install-TinySocsOpenSearchService'',''Register-TinySocsOpenSearchService'')) {' + #13#10 +
        '    if (Get-Command $fn -ErrorAction SilentlyContinue) {' + #13#10 +
        '      try { & $fn | Out-Null; break } catch { }' + #13#10 +
        '    }' + #13#10 +
        '  }' + #13#10 +
        '  try { $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue } catch { $svc = $null }' + #13#10 +
        '  if (-not $svc) {' + #13#10 +
        '    throw (''TinySocsOpenSearch service does not exist after attempted registration. This must be created before TLS repair/persistence can run.'')' + #13#10 +
        '  }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +
        '[Environment]::SetEnvironmentVariable(''OPENSEARCH_PATH_CONF'', [string]$pdConf, ''Machine'')' + #13#10 +
        '[Environment]::SetEnvironmentVariable(''OPENSEARCH_PATH_CONF'', [string]$pdConf, ''Process'')' + #13#10 +
        '' + #13#10 +
        'try {' + #13#10 +
        '  $svcKey = ''HKLM:\SYSTEM\CurrentControlSet\Services\TinySocsOpenSearch''' + #13#10 +
        '  if (Test-Path $svcKey) {' + #13#10 +
        '    $cur = @()' + #13#10 +
        '    try { $cur = (Get-ItemProperty -Path $svcKey -Name Environment -ErrorAction SilentlyContinue).Environment } catch { $cur = @() }' + #13#10 +
        '    if ($cur -is [string]) { $cur = @($cur) }' + #13#10 +
        '    $cur = @($cur | Where-Object { $_ -and ($_ -notmatch ''^OPENSEARCH_PATH_CONF='') })' + #13#10 +
        '    $new = @($cur + @(''OPENSEARCH_PATH_CONF='' + $pdConf))' + #13#10 +
        '    New-ItemProperty -Path $svcKey -Name Environment -PropertyType MultiString -Value $new -Force | Out-Null' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-10: failed to update service env (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +
        '$installRoot = $null' + #13#10 +
        'try { $installRoot = (Get-TinySocsInstallRoot | Select-Object -First 1) } catch { $installRoot = $null }' + #13#10 +
        'if (-not $installRoot) { $installRoot = (Join-Path ${env:ProgramFiles} ''TinySocs'') }' + #13#10 +
        '$openSearchRoot = Join-Path $installRoot ''OpenSearch''' + #13#10 +
        '' + #13#10 +

        '# PATCH(2026-01-16): Repair keystore ACLs BEFORE any keystore writes/CLI touches' + #13#10 +
        'Write-Host ''[TinySocs][Inno] TB-10a: Repair-TinySocsOpenSearchKeystoreAcls (pre)''' + #13#10 +
        'try {' + #13#10 +
        '  if (Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue) {' + #13#10 +
        '    $cmdAcl = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction Stop' + #13#10 +
        '    $ap = @{}' + #13#10 +
        '    if ($cmdAcl.Parameters.ContainsKey(''OpenSearchRoot''))   { $ap.OpenSearchRoot = $openSearchRoot }' + #13#10 +
        '    if ($cmdAcl.Parameters.ContainsKey(''ProgramDataConf''))  { $ap.ProgramDataConf = $pdConf }' + #13#10 +
        '    if ($cmdAcl.Parameters.ContainsKey(''CertsDir''))         { $ap.CertsDir = $certsDir }' + #13#10 +
        '    if ($cmdAcl.Parameters.ContainsKey(''ServiceName''))      { $ap.ServiceName = $svcName }' + #13#10 +
        '    & $cmdAcl @ap | Out-Null' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-10a keystore ACL repair failed (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +

        'if (Get-Command Repair-TinySocsOpenSearchTlsKeystore -ErrorAction SilentlyContinue) {' + #13#10 +
        '  $cmd = Get-Command Repair-TinySocsOpenSearchTlsKeystore -ErrorAction Stop' + #13#10 +
        '  $pp = @{}' + #13#10 +
        '  if ($cmd.Parameters.ContainsKey(''OpenSearchRoot''))  { $pp.OpenSearchRoot = $openSearchRoot }' + #13#10 +
        '  if ($cmd.Parameters.ContainsKey(''ProgramDataConf'')) { $pp.ProgramDataConf = $pdConf }' + #13#10 +
        '  if ($cmd.Parameters.ContainsKey(''CertsDir''))        { $pp.CertsDir = $certsDir }' + #13#10 +
        '  & $cmd @pp | Out-Null' + #13#10 +
        '} else {' + #13#10 +
        '  throw ''Repair-TinySocsOpenSearchTlsKeystore not found in installer module. TB-10 cannot continue.''' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        '# PATCH(2026-01-16): Repair keystore ACLs AFTER keystore creation/repair (creation can inherit broken ACLs)' + #13#10 +
        'Write-Host ''[TinySocs][Inno] TB-10b: Repair-TinySocsOpenSearchKeystoreAcls (post)''' + #13#10 +
        'try {' + #13#10 +
        '  if (Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue) {' + #13#10 +
        '    $cmdAcl2 = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction Stop' + #13#10 +
        '    $ap2 = @{}' + #13#10 +
        '    if ($cmdAcl2.Parameters.ContainsKey(''OpenSearchRoot''))   { $ap2.OpenSearchRoot = $openSearchRoot }' + #13#10 +
        '    if ($cmdAcl2.Parameters.ContainsKey(''ProgramDataConf''))  { $ap2.ProgramDataConf = $pdConf }' + #13#10 +
        '    if ($cmdAcl2.Parameters.ContainsKey(''CertsDir''))         { $ap2.CertsDir = $certsDir }' + #13#10 +
        '    if ($cmdAcl2.Parameters.ContainsKey(''ServiceName''))      { $ap2.ServiceName = $svcName }' + #13#10 +
        '    & $cmdAcl2 @ap2 | Out-Null' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-10b keystore ACL repair failed (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +

        'try { sc.exe stop  $svcName | Out-Null } catch { }' + #13#10 +
        'Start-Sleep -Seconds 2' + #13#10 +
        'try { sc.exe start $svcName | Out-Null } catch { }' + #13#10 +
        '' + #13#10 +

        'Write-Host ''[TinySocs][Inno] TB-11 (HARD): OpenSearch.Persistence.ps1 (restarts + waits for port)''' + #13#10 +
        '$conf = $pdConf' + #13#10 +
        '& ''' + PsEscape(PersistScriptPath) + ''' -ConfDir $conf -ServiceName $svcName -HttpPort 9201 -NetworkHost ''127.0.0.1''' + #13#10 +
        '' + #13#10 +

        '# PATCH(2026-01-16): Persistence can also recreate keystore; re-apply keystore ACL repair.' + #13#10 +
        'Write-Host ''[TinySocs][Inno] TB-11b: Repair-TinySocsOpenSearchKeystoreAcls (post persistence)''' + #13#10 +
        'try {' + #13#10 +
        '  if (Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction SilentlyContinue) {' + #13#10 +
        '    $cmdAcl3 = Get-Command Repair-TinySocsOpenSearchKeystoreAcls -ErrorAction Stop' + #13#10 +
        '    $ap3 = @{}' + #13#10 +
        '    if ($cmdAcl3.Parameters.ContainsKey(''OpenSearchRoot''))   { $ap3.OpenSearchRoot = $openSearchRoot }' + #13#10 +
        '    if ($cmdAcl3.Parameters.ContainsKey(''ProgramDataConf''))  { $ap3.ProgramDataConf = $pdConf }' + #13#10 +
        '    if ($cmdAcl3.Parameters.ContainsKey(''CertsDir''))         { $ap3.CertsDir = $certsDir }' + #13#10 +
        '    if ($cmdAcl3.Parameters.ContainsKey(''ServiceName''))      { $ap3.ServiceName = $svcName }' + #13#10 +
        '    & $cmdAcl3 @ap3 | Out-Null' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-11b keystore ACL repair failed (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +

        'Write-Host ''[TinySocs][Inno] TB-12: Readiness gate + best-effort security init (do NOT fail install)''' + #13#10 +
        'try {' + #13#10 +
        '  # Probe unauth /_cluster/health with headers+body so we can detect "not initialized".' + #13#10 +
        '  $deadline = (Get-Date).AddSeconds(240)' + #13#10 +
        '  $initTried = 0' + #13#10 +
        '  do {' + #13#10 +
        '    $out = _curl_i ''/_cluster/health''' + #13#10 +
        '    $c = _code_from_i $out' + #13#10 +
        '    Write-Host (''[TinySocs][Inno] readiness probe http='' + $c)' + #13#10 +
        '' + #13#10 +
        '    if (($c -eq ''401'') -or ($c -eq ''200'')) { break }' + #13#10 +
        '' + #13#10 +
        '    if (($c -eq ''503'') -and ($out -match ''OpenSearch Security not initialized'') -and ($initTried -lt 3)) {' + #13#10 +
        '      $initTried++' + #13#10 +
        '      Write-Host (''[TinySocs][Inno] TB-12: detected "not initialized" (503). Attempting security bootstrap (attempt '' + $initTried + ''/3)...'')' + #13#10 +
        '      foreach ($fn in @(''Ensure-TinySocsOpenSearchSecurityInitialized'',''Initialize-TinySocsOpenSearchSecurity'',''Invoke-TinySocsSecurityAdmin'',''Initialize-OpenSearchSecurity'')) {' + #13#10 +
        '        if (Get-Command $fn -ErrorAction SilentlyContinue) {' + #13#10 +
        '          Write-Host (''[TinySocs][Inno] TB-12: calling security init helper: '' + $fn)' + #13#10 +
        '          try {' + #13#10 +
        '            if ($fn -eq ''Initialize-TinySocsOpenSearchSecurity'') {' + #13#10 +
        '              $cmd = Get-Command Initialize-TinySocsOpenSearchSecurity -ErrorAction Stop' + #13#10 +
        '              $pp = @{}' + #13#10 +
        '              if ($cmd.Parameters.ContainsKey(''SiemUrl''))   { $pp.SiemUrl   = $siemUrl }' + #13#10 +
        '              if ($cmd.Parameters.ContainsKey(''AdminUser'')) { $pp.AdminUser = $u_in }' + #13#10 +
        '              if ($cmd.Parameters.ContainsKey(''AdminPass'')) { $pp.AdminPass = $p_in }' + #13#10 +
        '              if ($cmd.Parameters.ContainsKey(''SkipTlsVerify'')) { $pp.SkipTlsVerify = $true }' + #13#10 +
        '              if ($cmd.Parameters.ContainsKey(''DisableTlsRevocationCheck'')) { $pp.DisableTlsRevocationCheck = $true }' + #13#10 +
        '              if ($cmd.Parameters.ContainsKey(''HttpClientAuthMode'')) { $pp.HttpClientAuthMode = ''NONE'' }' + #13#10 +
        '              & $cmd @pp | Out-Null' + #13#10 +
        '            } else {' + #13#10 +
        '              & $fn | Out-Null' + #13#10 +
        '            }' + #13#10 +
        '          } catch { Write-Warning (''[TinySocs][Inno] TB-12 security init failed (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '          break' + #13#10 +
        '        }' + #13#10 +
        '      }' + #13#10 +
        '    }' + #13#10 +
        '' + #13#10 +
        '    Start-Sleep -Seconds 2' + #13#10 +
        '  } while ((Get-Date) -lt $deadline)' + #13#10 +
        '' + #13#10 +
        '  # IMPORTANT: if we got 401, security is UP. Do NOT run init "because 401".' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-12 encountered error (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +

        '{ PATCH(2026-01-16): CRED PRESET probe must be unforgeable. Use /_plugins/_security/authinfo and require 200. }' + #13#10 +
        'Write-Host ''[TinySocs][Inno] CRED PRESET (post TB-12): select creds that actually authenticate; store before TB-3''' + #13#10 +
        '$probePath = ''/_plugins/_security/authinfo''' + #13#10 +
        '$candidates = @(@($u_in,$p_in), @(''admin'',''admin''), @($u_in,''admin''), @(''admin'',$p_in))' + #13#10 +
        '$u = $u_in; $p = $p_in; $ok = $false; $okCode = ''000''' + #13#10 +
        '$probeDeadline = (Get-Date).AddSeconds(120)' + #13#10 +
        'while ((Get-Date) -lt $probeDeadline -and (-not $ok)) {' + #13#10 +
        '  foreach ($pair in $candidates) {' + #13#10 +
        '    $cu = $pair[0]; $cp = $pair[1]' + #13#10 +
        '    $hc = _http $cu $cp $probePath' + #13#10 +
        '    Write-Host (''[TinySocs][Inno] auth probe(authinfo) user='' + $cu + '' http='' + $hc)' + #13#10 +
        '    if ($hc -eq ''200'') { $u = $cu; $p = $cp; $ok = $true; $okCode = $hc; break }' + #13#10 +
        '    if ($hc -eq ''503'') { Start-Sleep -Seconds 2 }' + #13#10 +
        '  }' + #13#10 +
        '  if (-not $ok) { Start-Sleep -Seconds 2 }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +
        'if ($ok) {' + #13#10 +
        '  Write-Host (''[TinySocs][Inno] Using creds that AUTHENTICATED: user='' + $u + '' http='' + $okCode)' + #13#10 +
        '  try {' + #13#10 +
        '    if (Get-Command Set-TinySocsSiemCredential -ErrorAction SilentlyContinue) {' + #13#10 +
        '      $sc = Get-Command Set-TinySocsSiemCredential -ErrorAction Stop' + #13#10 +
        '      $sp = @{}' + #13#10 +
        '      if ($sc.Parameters.ContainsKey(''SiemUrl''))        { $sp.SiemUrl = $siemUrl }' + #13#10 +
        '      if ($sc.Parameters.ContainsKey(''SiemUser''))       { $sp.SiemUser = $u }' + #13#10 +
        '      if ($sc.Parameters.ContainsKey(''SiemPass''))       { $sp.SiemPass = $p }' + #13#10 +
        '      if ($sc.Parameters.ContainsKey(''SiemSslVerify''))  { $sp.SiemSslVerify = $false }' + #13#10 +
        '      Write-Host (''[TinySocs][Inno] Credential preset via Set-TinySocsSiemCredential keys: '' + ($sp.Keys -join '', ''))' + #13#10 +
        '      & $sc @sp | Out-Null' + #13#10 +
        '    }' + #13#10 +
        '  } catch { Write-Warning (''[TinySocs][Inno] Credential preset failed (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '} else {' + #13#10 +
        '  Write-Warning ''[TinySocs][Inno] No credential candidate AUTHENTICATED (authinfo never returned 200); skipping TB-3 to avoid 401 loops. OpenSearch persistence succeeded.'' ' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        '# Ensure admin-keystore.p12 exists BEFORE TB-3 (avoids Export-PfxCertificate non-exportable key failure path)' + #13#10 +
        'try { _ensure_admin_p12 $certsDir | Out-Null } catch { }' + #13#10 +
        '' + #13#10 +

        'Write-Host ''[TinySocs][Inno] TB-3 (NON-FATAL): Install-TinySocsLocalSiem (LAST, but ONLY if auth works)''' + #13#10 +
        '$ErrorActionPreference = ''Continue''' + #13#10 +
        'if (-not $ok) {' + #13#10 +
        '  Write-Warning ''[TinySocs][Inno] No credential candidate AUTHENTICATED (/_plugins/_security/authinfo). Skipping TB-3 to avoid 401 loops. OpenSearch persistence succeeded.'' ' + #13#10 +
        '} else {' + #13#10 +
        '  Write-Host (''[TinySocs][Inno] Using AUTHENTICATED creds: user='' + $u + '' http='' + $okCode)' + #13#10 +
        '  try {' + #13#10 +
        '    $cmd = Get-Command Install-TinySocsLocalSiem -ErrorAction Stop' + #13#10 +
        '    $pp = @{}' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''SiemUser'')) { $pp.SiemUser = $u }' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''SiemPass'')) { $pp.SiemPass = $p }' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''ApiPort''))  { $pp.ApiPort  = 9201 }' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''ForceConfig'')) { $pp.ForceConfig = ' + BoolToPs(ForceTinyBoxConfig) + ' }' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''TrustLocalCA'')) { $pp.TrustLocalCA = $true }' + #13#10 +
        '    Write-Host (''[TinySocs][Inno] calling Install-TinySocsLocalSiem with params: '' + ($pp.Keys -join '', ''))' + #13#10 +
        '    & $cmd @pp' + #13#10 +
        '  } catch {' + #13#10 +
        '    Write-Warning (''[TinySocs][Inno] Install-TinySocsLocalSiem threw (continuing): '' + $_.Exception.Message)' + #13#10 +
        '  }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +
        'try { Stop-Transcript | Out-Null } catch { }' + #13#10;

      Log('ORDER CHECK: about to run ONE postinstall chain powershell');
      if not RunPowerShellScript(Script) then
      begin
        Log('CurStepChanged: deterministic postinstall chain FAILED.');
        MsgBox('TinyBox install failed during deterministic OpenSearch persistence chain. See ProgramData\TinySocs\logs\postinstall-powershell*.log and the Inno /LOG output.', mbError, MB_OK);
        Abort;
      end;

      DidRunLocalSiem := True;
      Log('CurStepChanged: DidRunLocalSiem=True (ran inside one-chain postinstall).');
    end
    else
      Log('CurStepChanged: InstallTinyBox=False');

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