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
AppVersion=0.8.0
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
; Primary location: Collector\agent-config.yml (matches NSSM TINYSOCS_AGENT_CONFIG)
; (Do not overwrite on upgrade; operator may have edited it)
Source: "..\..\config\agent-config.yml"; \
    DestDir: "{commonappdata}\TinySocs\Collector"; \
    Flags: ignoreversion onlyifdoesntexist

; Legacy location: Collector\agent\config.yml (kept for backwards compatibility)
Source: "..\..\config\agent-config.yml"; \
    DestDir: "{commonappdata}\TinySocs\Collector\agent"; \
    DestName: "config.yml"; \
    Flags: ignoreversion onlyifdoesntexist

; Detection rules → ProgramData\TinySocs\Collector\rules\rules.yml
; (matches DetectionConfig.RulesFile default; do not overwrite operator edits)
Source: "..\..\packaging\detection\rules.yml"; \
    DestDir: "{commonappdata}\TinySocs\Collector\rules"; \
    Flags: ignoreversion onlyifdoesntexist

; NSSM is optional — include only if present at build time
#if FileExists('..\..\thirdparty\nssm.exe')
Source: "..\..\thirdparty\nssm.exe";       DestDir: "{app}\bin"; Flags: ignoreversion
#endif

; TinySocs LLM Assistant (PyInstaller bundle — optional at build time)
#if FileExists('..\..\dist\TinySocs-Quickstart\TinySocs-Quickstart.exe')
Source: "..\..\dist\TinySocs-Quickstart\*"; \
    DestDir: "{app}\Assistant"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
#endif

; Assistant environment template → ProgramData (do not overwrite operator edits)
Source: "..\..\config\assistant.env"; \
    DestDir: "{commonappdata}\TinySocs\Assistant"; \
    Flags: ignoreversion onlyifdoesntexist

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

; OpenSearch ISM retention policies for TinySocs
Source: "..\opensearch\policies\*.json"; \
    DestDir: "{app}\OpenSearch\policies"; \
    Flags: ignoreversion

; Phase 12: OpenSearch Dashboard saved objects (NDJSON)
Source: "..\opensearch\dashboards\tinysocs-dashboards.ndjson"; \
    DestDir: "{app}\OpenSearch\dashboards"; \
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

; Phase 14 M2: Sysmon binary + config (bundled during build, gitignored)
#if FileExists('..\..\sysmon-bin\Sysmon64.exe')
Source: "..\..\sysmon-bin\Sysmon64.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
#endif
Source: "..\..\integrations\sysmon\sysmon-config.xml"; \
    DestDir: "{commonappdata}\TinySocs\Sysmon"; \
    Flags: ignoreversion onlyifdoesntexist

[Dirs]
Name: "{commonappdata}\TinySocs"
Name: "{commonappdata}\TinySocs\logs"; Permissions: users-modify
Name: "{commonappdata}\TinySocs\queue"
Name: "{commonappdata}\TinySocs\config"
Name: "{commonappdata}\TinySocs\rules"
Name: "{commonappdata}\TinySocs\anchors\state"
Name: "{commonappdata}\TinySocs\ledger"
Name: "{commonappdata}\TinySocs\Sysmon"

; TinySocs collector agent directories under ProgramData
Name: "{commonappdata}\TinySocs\Collector"
Name: "{commonappdata}\TinySocs\Collector\agent"
Name: "{commonappdata}\TinySocs\Collector\agent\queue"
Name: "{commonappdata}\TinySocs\Collector\agent\bookmarks"
Name: "{commonappdata}\TinySocs\Collector\rules"
Name: "{commonappdata}\TinySocs\Collector\logs"; Permissions: users-modify

; TinySocs LLM Assistant runtime directories
Name: "{commonappdata}\TinySocs\Assistant"
Name: "{commonappdata}\TinySocs\Assistant\logs"; Permissions: users-modify

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
; "Launch Dashboard" checkbox shown on the finish page (postinstall flag).
Filename: "http://localhost:8090/dashboard/"; Description: "Open TinySocs Dashboard"; \
  Flags: postinstall nowait shellexec skipifsilent

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
Name: "{group}\TinySocs Dashboard"; Filename: "http://localhost:8090/dashboard/"; IconFilename: "{sys}\shell32.dll"; IconIndex: 13
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
  SecurityPage: TWizardPage;
  LlmPage: TWizardPage;
  NotifPage: TWizardPage;
  DashAccessPage: TWizardPage;

  RoleNodeRadio: TRadioButton;
  RoleMasterRadio: TRadioButton;
  RoleTinyBoxRadio: TRadioButton;

  SharedSecretEdit: TNewEdit;
  SiemPassEdit: TNewEdit;

  LlmModeRadioOpenAI: TRadioButton;
  LlmModeRadioAnthropic: TRadioButton;
  LlmModeRadioOllama: TRadioButton;
  LlmModeRadioNone: TRadioButton;
  LlmApiKeyEdit: TNewEdit;
  LlmApiKeyLabel: TNewStaticText;
  OllamaUrlEdit: TNewEdit;
  OllamaUrlLabel: TNewStaticText;

  WebhookUrlEdit: TNewEdit;
  TestWebhookBtn: TNewButton;
  WebhookTestLabel: TNewStaticText;
  EmailEnableCheck: TNewCheckBox;
  SmtpHostEdit: TNewEdit;
  EmailFromEdit: TNewEdit;
  EmailToEdit: TNewEdit;

  DashLocalhostRadio: TRadioButton;
  DashNetworkRadio: TRadioButton;
  DashboardBind: String;

  SysmonPage: TWizardPage;
  SysmonInstallCheck: TNewCheckBox;

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

  LlmMode: String;
  LlmApiKey: String;
  OllamaUrl: String;

  WebhookUrl: String;
  SmtpHost: String;
  SmtpPort: String;
  EmailFrom: String;
  EmailTo: String;
  EmailEnabled: Boolean;

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

procedure CopyToClipboard(const Text: String);
var
  ResultCode: Integer;
  PsExe: String;
begin
  { Copy text to Windows clipboard via PowerShell Set-Clipboard }
  PsExe := GetPowerShellExePath;
  try
    Exec(PsExe, '-NoLogo -NoProfile -NonInteractive -Command "Set-Clipboard -Value ''' + Text + '''"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  except
    Log('CopyToClipboard: exception (non-fatal)');
  end;
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
  I: Integer;
  Idx: Integer;
  Hi, Lo: Integer;
begin
  Alphabet :=
    'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

  Seed :=
    GetDateTimeString('yyyymmddhhnnsszzz', '-', ':') + '|' +
    GetEnv('COMPUTERNAME') + '|' +
    GetEnv('USERNAME');

  { Simple hash: sum of char codes (no overflow risk) }
  Hi := 0;
  Lo := 0;
  for I := 1 to Length(Seed) do
  begin
    Lo := Lo + Ord(Seed[I]);
    if Lo > 30000 then
    begin
      Hi := Hi + 1;
      Lo := Lo - 30000;
    end;
  end;
  if Lo = 0 then Lo := 42;

  Result := '';
  for I := 1 to Len do
  begin
    { LCG with small multiplier to avoid overflow }
    Lo := (Lo * 421 + 1663) mod 29989;
    Hi := (Hi * 353 + I) mod 29989;
    Idx := ((Lo + Hi) mod Length(Alphabet)) + 1;
    Result := Result + Copy(Alphabet, Idx, 1);
  end;
end;

procedure UpdateLlmFieldVisibility;
var
  ShowApiKey, ShowOllama: Boolean;
begin
  ShowApiKey := LlmModeRadioOpenAI.Checked or LlmModeRadioAnthropic.Checked;
  ShowOllama := LlmModeRadioOllama.Checked;

  LlmApiKeyLabel.Visible := ShowApiKey;
  LlmApiKeyEdit.Visible := ShowApiKey;
  OllamaUrlLabel.Visible := ShowOllama;
  OllamaUrlEdit.Visible := ShowOllama;

  { Update API key label to match selected provider }
  if LlmModeRadioOpenAI.Checked then
    LlmApiKeyLabel.Caption := 'OpenAI API key:'
  else if LlmModeRadioAnthropic.Checked then
    LlmApiKeyLabel.Caption := 'Anthropic API key:';
end;

procedure LlmRadioClick(Sender: TObject);
begin
  UpdateLlmFieldVisibility;
end;

procedure TestWebhookBtnClick(Sender: TObject);
var
  Url: String;
  PsExe: String;
  PsCmd: String;
  ResultCode: Integer;
begin
  Url := Trim(WebhookUrlEdit.Text);
  if Url = '' then
  begin
    WebhookTestLabel.Caption := 'Enter a webhook URL first.';
    WebhookTestLabel.Font.Color := clRed;
    Exit;
  end;

  WebhookTestLabel.Caption := 'Sending test...';
  WebhookTestLabel.Font.Color := clWindowText;
  WizardForm.Refresh;

  PsExe := GetPowerShellExePath;
  PsCmd :=
    '-NoProfile -ExecutionPolicy Bypass -Command "' +
    'try { ' +
    '$body = @{text=''TinySocs test webhook -- if you see this, notifications are working.''} | ConvertTo-Json -Compress; ' +
    '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ' +
    '[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; ' +
    '$r = Invoke-RestMethod -Uri '''' + PsEscape(Url) + ''''' +
    ' -Method Post -ContentType ''application/json'' -Body $body -TimeoutSec 10; ' +
    'exit 0 ' +
    '} catch { exit 1 }"';

  if Exec(PsExe, PsCmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
    begin
      WebhookTestLabel.Caption := 'Success -- test message sent.';
      WebhookTestLabel.Font.Color := clGreen;
    end
    else
    begin
      WebhookTestLabel.Caption := 'Failed (HTTP error or unreachable). Check URL.';
      WebhookTestLabel.Font.Color := clRed;
    end;
  end
  else
  begin
    WebhookTestLabel.Caption := 'Could not run PowerShell.';
    WebhookTestLabel.Font.Color := clRed;
  end;
end;

procedure InitializeWizard;
var
  L: TNewStaticText;
  DescLabel: TNewStaticText;
begin
  { ---- Page 1: Role ---- }
  RolePage := CreateCustomPage(wpSelectDir, 'TinySocs Role', 'Select what this machine will do.');

  L := TNewStaticText.Create(RolePage.Surface);
  L.Parent := RolePage.Surface;
  L.Left := 0;
  L.Top := 0;
  L.Width := RolePage.SurfaceWidth;
  L.Caption := 'Choose the role for this machine:';

  RoleTinyBoxRadio := TRadioButton.Create(RolePage.Surface);
  RoleTinyBoxRadio.Parent := RolePage.Surface;
  RoleTinyBoxRadio.Left := 0;
  RoleTinyBoxRadio.Top := ScaleY(28);
  RoleTinyBoxRadio.Width := RolePage.SurfaceWidth;
  RoleTinyBoxRadio.Height := ScaleY(20);
  RoleTinyBoxRadio.Caption := '&TinyBox (recommended)';
  RoleTinyBoxRadio.Checked := True;

  DescLabel := TNewStaticText.Create(RolePage.Surface);
  DescLabel.Parent := RolePage.Surface;
  DescLabel.Left := ScaleX(20);
  DescLabel.Top := RoleTinyBoxRadio.Top + ScaleY(20);
  DescLabel.Width := RolePage.SurfaceWidth - ScaleX(20);
  DescLabel.Caption := 'All-in-one: collector + SIEM datastore + LLM assistant on this machine.';
  DescLabel.Font.Color := $666666;

  RoleNodeRadio := TRadioButton.Create(RolePage.Surface);
  RoleNodeRadio.Parent := RolePage.Surface;
  RoleNodeRadio.Left := 0;
  RoleNodeRadio.Top := DescLabel.Top + ScaleY(32);
  RoleNodeRadio.Width := RolePage.SurfaceWidth;
  RoleNodeRadio.Height := ScaleY(20);
  RoleNodeRadio.Caption := '&Node';

  DescLabel := TNewStaticText.Create(RolePage.Surface);
  DescLabel.Parent := RolePage.Surface;
  DescLabel.Left := ScaleX(20);
  DescLabel.Top := RoleNodeRadio.Top + ScaleY(20);
  DescLabel.Width := RolePage.SurfaceWidth - ScaleX(20);
  DescLabel.Caption := 'Collect Windows events and ship them to a remote SIEM.';
  DescLabel.Font.Color := $666666;

  RoleMasterRadio := TRadioButton.Create(RolePage.Surface);
  RoleMasterRadio.Parent := RolePage.Surface;
  RoleMasterRadio.Left := 0;
  RoleMasterRadio.Top := DescLabel.Top + ScaleY(32);
  RoleMasterRadio.Width := RolePage.SurfaceWidth;
  RoleMasterRadio.Height := ScaleY(20);
  RoleMasterRadio.Caption := '&Master';

  DescLabel := TNewStaticText.Create(RolePage.Surface);
  DescLabel.Parent := RolePage.Surface;
  DescLabel.Left := ScaleX(20);
  DescLabel.Top := RoleMasterRadio.Top + ScaleY(20);
  DescLabel.Width := RolePage.SurfaceWidth - ScaleX(20);
  DescLabel.Caption := 'Orchestrate nodes and run the LLM assistant (no local SIEM).';
  DescLabel.Font.Color := $666666;

  { ---- Page 2: Security ---- }
  SecurityPage := CreateCustomPage(RolePage.ID, 'Security', 'Set your shared secret and SIEM password.');

  L := TNewStaticText.Create(SecurityPage.Surface);
  L.Parent := SecurityPage.Surface;
  L.Left := 0;
  L.Top := ScaleY(4);
  L.Width := SecurityPage.SurfaceWidth;
  L.Caption := 'Shared secret (authenticates all TinySocs components):';

  SharedSecretEdit := TNewEdit.Create(SecurityPage.Surface);
  SharedSecretEdit.Parent := SecurityPage.Surface;
  SharedSecretEdit.Left := 0;
  SharedSecretEdit.Top := L.Top + ScaleY(18);
  SharedSecretEdit.Width := SecurityPage.SurfaceWidth;
  SharedSecretEdit.PasswordChar := '*';

  L := TNewStaticText.Create(SecurityPage.Surface);
  L.Parent := SecurityPage.Surface;
  L.Left := 0;
  L.Top := SharedSecretEdit.Top + ScaleY(36);
  L.Width := SecurityPage.SurfaceWidth;
  L.Caption := 'SIEM + Dashboard password (leave blank to auto-generate a strong one):';

  SiemPassEdit := TNewEdit.Create(SecurityPage.Surface);
  SiemPassEdit.Parent := SecurityPage.Surface;
  SiemPassEdit.Left := 0;
  SiemPassEdit.Top := L.Top + ScaleY(18);
  SiemPassEdit.Width := SecurityPage.SurfaceWidth;
  SiemPassEdit.PasswordChar := '*';

  L := TNewStaticText.Create(SecurityPage.Surface);
  L.Parent := SecurityPage.Surface;
  L.Left := 0;
  L.Top := SiemPassEdit.Top + ScaleY(28);
  L.Width := SecurityPage.SurfaceWidth;
  L.WordWrap := True;
  L.AutoSize := True;
  L.Caption := 'This password protects both the OpenSearch datastore and the TinySocs dashboard.'
    + ' If left blank, a strong password will be generated and stored in Windows'
    + ' Credential Manager.';

  { ---- Page 3: LLM Provider ---- }
  LlmPage := CreateCustomPage(SecurityPage.ID, 'LLM Provider', 'Choose an AI provider for the TinySocs assistant.');

  L := TNewStaticText.Create(LlmPage.Surface);
  L.Parent := LlmPage.Surface;
  L.Left := 0;
  L.Top := 0;
  L.Width := LlmPage.SurfaceWidth;
  L.Caption := 'The assistant uses an LLM to analyze alerts and suggest actions.';

  LlmModeRadioOpenAI := TRadioButton.Create(LlmPage.Surface);
  LlmModeRadioOpenAI.Parent := LlmPage.Surface;
  LlmModeRadioOpenAI.Left := 0;
  LlmModeRadioOpenAI.Top := ScaleY(28);
  LlmModeRadioOpenAI.Width := LlmPage.SurfaceWidth;
  LlmModeRadioOpenAI.Height := ScaleY(20);
  LlmModeRadioOpenAI.Caption := '&OpenAI (GPT-4o-mini)';

  LlmModeRadioAnthropic := TRadioButton.Create(LlmPage.Surface);
  LlmModeRadioAnthropic.Parent := LlmPage.Surface;
  LlmModeRadioAnthropic.Left := 0;
  LlmModeRadioAnthropic.Top := LlmModeRadioOpenAI.Top + ScaleY(26);
  LlmModeRadioAnthropic.Width := LlmPage.SurfaceWidth;
  LlmModeRadioAnthropic.Height := ScaleY(20);
  LlmModeRadioAnthropic.Caption := '&Anthropic (Claude)';

  LlmModeRadioOllama := TRadioButton.Create(LlmPage.Surface);
  LlmModeRadioOllama.Parent := LlmPage.Surface;
  LlmModeRadioOllama.Left := 0;
  LlmModeRadioOllama.Top := LlmModeRadioAnthropic.Top + ScaleY(26);
  LlmModeRadioOllama.Width := LlmPage.SurfaceWidth;
  LlmModeRadioOllama.Height := ScaleY(20);
  LlmModeRadioOllama.Caption := 'O&llama (local, no API key needed)';

  LlmModeRadioNone := TRadioButton.Create(LlmPage.Surface);
  LlmModeRadioNone.Parent := LlmPage.Surface;
  LlmModeRadioNone.Left := 0;
  LlmModeRadioNone.Top := LlmModeRadioOllama.Top + ScaleY(26);
  LlmModeRadioNone.Width := LlmPage.SurfaceWidth;
  LlmModeRadioNone.Height := ScaleY(20);
  LlmModeRadioNone.Caption := '&None (skip LLM setup for now)';
  LlmModeRadioNone.Checked := True;

  LlmApiKeyLabel := TNewStaticText.Create(LlmPage.Surface);
  LlmApiKeyLabel.Parent := LlmPage.Surface;
  LlmApiKeyLabel.Left := 0;
  LlmApiKeyLabel.Top := LlmModeRadioNone.Top + ScaleY(36);
  LlmApiKeyLabel.Width := LlmPage.SurfaceWidth;
  LlmApiKeyLabel.Caption := 'API key:';

  LlmApiKeyEdit := TNewEdit.Create(LlmPage.Surface);
  LlmApiKeyEdit.Parent := LlmPage.Surface;
  LlmApiKeyEdit.Left := 0;
  LlmApiKeyEdit.Top := LlmApiKeyLabel.Top + ScaleY(18);
  LlmApiKeyEdit.Width := LlmPage.SurfaceWidth;
  LlmApiKeyEdit.PasswordChar := '*';
  LlmApiKeyEdit.Text := '';

  OllamaUrlLabel := TNewStaticText.Create(LlmPage.Surface);
  OllamaUrlLabel.Parent := LlmPage.Surface;
  OllamaUrlLabel.Left := 0;
  OllamaUrlLabel.Top := LlmApiKeyEdit.Top + ScaleY(32);
  OllamaUrlLabel.Width := LlmPage.SurfaceWidth;
  OllamaUrlLabel.Caption := 'Ollama URL (default: http://localhost:11434):';

  OllamaUrlEdit := TNewEdit.Create(LlmPage.Surface);
  OllamaUrlEdit.Parent := LlmPage.Surface;
  OllamaUrlEdit.Left := 0;
  OllamaUrlEdit.Top := OllamaUrlLabel.Top + ScaleY(18);
  OllamaUrlEdit.Width := LlmPage.SurfaceWidth;
  OllamaUrlEdit.Text := 'http://localhost:11434';

  { Wire up radio button click handlers to toggle field visibility }
  LlmModeRadioOpenAI.OnClick := @LlmRadioClick;
  LlmModeRadioAnthropic.OnClick := @LlmRadioClick;
  LlmModeRadioOllama.OnClick := @LlmRadioClick;
  LlmModeRadioNone.OnClick := @LlmRadioClick;

  { Set initial visibility (None is checked by default, so hide both) }
  LlmApiKeyLabel.Visible := False;
  LlmApiKeyEdit.Visible := False;
  OllamaUrlLabel.Visible := False;
  OllamaUrlEdit.Visible := False;

  { ---- Page 4: Notifications (merged webhook + email) ---- }
  NotifPage := CreateCustomPage(LlmPage.ID, 'Notifications', 'Configure alert notifications (all optional).');

  L := TNewStaticText.Create(NotifPage.Surface);
  L.Parent := NotifPage.Surface;
  L.Left := 0;
  L.Top := ScaleY(4);
  L.Width := NotifPage.SurfaceWidth;
  L.Caption := 'Webhook URL (Slack/Teams -- leave empty to skip):';

  WebhookUrlEdit := TNewEdit.Create(NotifPage.Surface);
  WebhookUrlEdit.Parent := NotifPage.Surface;
  WebhookUrlEdit.Left := 0;
  WebhookUrlEdit.Top := L.Top + ScaleY(18);
  WebhookUrlEdit.Width := NotifPage.SurfaceWidth;
  WebhookUrlEdit.Text := '';

  TestWebhookBtn := TNewButton.Create(NotifPage.Surface);
  TestWebhookBtn.Parent := NotifPage.Surface;
  TestWebhookBtn.Left := 0;
  TestWebhookBtn.Top := WebhookUrlEdit.Top + ScaleY(28);
  TestWebhookBtn.Width := ScaleX(110);
  TestWebhookBtn.Height := ScaleY(25);
  TestWebhookBtn.Caption := '&Test Webhook';
  TestWebhookBtn.OnClick := @TestWebhookBtnClick;

  WebhookTestLabel := TNewStaticText.Create(NotifPage.Surface);
  WebhookTestLabel.Parent := NotifPage.Surface;
  WebhookTestLabel.Left := TestWebhookBtn.Left + TestWebhookBtn.Width + ScaleX(10);
  WebhookTestLabel.Top := TestWebhookBtn.Top + ScaleY(4);
  WebhookTestLabel.Width := NotifPage.SurfaceWidth - TestWebhookBtn.Width - ScaleX(10);
  WebhookTestLabel.Caption := '';

  EmailEnableCheck := TNewCheckBox.Create(NotifPage.Surface);
  EmailEnableCheck.Parent := NotifPage.Surface;
  EmailEnableCheck.Left := 0;
  EmailEnableCheck.Top := TestWebhookBtn.Top + ScaleY(36);
  EmailEnableCheck.Width := NotifPage.SurfaceWidth;
  EmailEnableCheck.Height := ScaleY(20);
  EmailEnableCheck.Caption := '&Enable email alert notifications';
  EmailEnableCheck.Checked := False;

  L := TNewStaticText.Create(NotifPage.Surface);
  L.Parent := NotifPage.Surface;
  L.Left := 0;
  L.Top := EmailEnableCheck.Top + ScaleY(28);
  L.Width := NotifPage.SurfaceWidth;
  L.Caption := 'SMTP host:';

  SmtpHostEdit := TNewEdit.Create(NotifPage.Surface);
  SmtpHostEdit.Parent := NotifPage.Surface;
  SmtpHostEdit.Left := 0;
  SmtpHostEdit.Top := L.Top + ScaleY(18);
  SmtpHostEdit.Width := NotifPage.SurfaceWidth;
  SmtpHostEdit.Text := '';

  L := TNewStaticText.Create(NotifPage.Surface);
  L.Parent := NotifPage.Surface;
  L.Left := 0;
  L.Top := SmtpHostEdit.Top + ScaleY(30);
  L.Width := NotifPage.SurfaceWidth;
  L.Caption := 'From address:';

  EmailFromEdit := TNewEdit.Create(NotifPage.Surface);
  EmailFromEdit.Parent := NotifPage.Surface;
  EmailFromEdit.Left := 0;
  EmailFromEdit.Top := L.Top + ScaleY(18);
  EmailFromEdit.Width := NotifPage.SurfaceWidth;
  EmailFromEdit.Text := '';

  L := TNewStaticText.Create(NotifPage.Surface);
  L.Parent := NotifPage.Surface;
  L.Left := 0;
  L.Top := EmailFromEdit.Top + ScaleY(30);
  L.Width := NotifPage.SurfaceWidth;
  L.Caption := 'To address:';

  EmailToEdit := TNewEdit.Create(NotifPage.Surface);
  EmailToEdit.Parent := NotifPage.Surface;
  EmailToEdit.Left := 0;
  EmailToEdit.Top := L.Top + ScaleY(18);
  EmailToEdit.Width := NotifPage.SurfaceWidth;
  EmailToEdit.Text := '';

  { ---- Page 5: Dashboard Access (Phase 14 M0) ---- }
  DashAccessPage := CreateCustomPage(NotifPage.ID, 'Dashboard Access',
    'Choose how the dashboard can be accessed.');

  L := TNewStaticText.Create(DashAccessPage.Surface);
  L.Parent := DashAccessPage.Surface;
  L.Left := 0;
  L.Top := ScaleY(4);
  L.Width := DashAccessPage.SurfaceWidth;
  L.WordWrap := True;
  L.AutoSize := True;
  L.Caption := 'The TinySocs dashboard provides a web UI for managing alerts and detections. ' +
    'Choose whether the dashboard should be accessible only from this machine or from the local network.';

  DashLocalhostRadio := TRadioButton.Create(DashAccessPage.Surface);
  DashLocalhostRadio.Parent := DashAccessPage.Surface;
  DashLocalhostRadio.Left := 0;
  DashLocalhostRadio.Top := ScaleY(48);
  DashLocalhostRadio.Width := DashAccessPage.SurfaceWidth;
  DashLocalhostRadio.Height := ScaleY(20);
  DashLocalhostRadio.Caption := '&Localhost only (recommended)';
  DashLocalhostRadio.Checked := True;

  L := TNewStaticText.Create(DashAccessPage.Surface);
  L.Parent := DashAccessPage.Surface;
  L.Left := ScaleX(20);
  L.Top := DashLocalhostRadio.Top + ScaleY(20);
  L.Width := DashAccessPage.SurfaceWidth - ScaleX(20);
  L.WordWrap := True;
  L.AutoSize := True;
  L.Caption := 'Dashboard accessible only from this machine (http://localhost:8090/dashboard). No TLS certificate required.';
  L.Font.Color := $666666;

  DashNetworkRadio := TRadioButton.Create(DashAccessPage.Surface);
  DashNetworkRadio.Parent := DashAccessPage.Surface;
  DashNetworkRadio.Left := 0;
  DashNetworkRadio.Top := L.Top + ScaleY(36);
  DashNetworkRadio.Width := DashAccessPage.SurfaceWidth;
  DashNetworkRadio.Height := ScaleY(20);
  DashNetworkRadio.Caption := '&Network accessible (generates TLS certificate)';

  L := TNewStaticText.Create(DashAccessPage.Surface);
  L.Parent := DashAccessPage.Surface;
  L.Left := ScaleX(20);
  L.Top := DashNetworkRadio.Top + ScaleY(20);
  L.Width := DashAccessPage.SurfaceWidth - ScaleX(20);
  L.WordWrap := True;
  L.AutoSize := True;
  L.Caption := 'Dashboard accessible from other machines on the network via HTTPS. ' +
    'A TLS certificate will be generated automatically using the TinySocs CA.';
  L.Font.Color := $666666;

  { ---- Page 6: Sysmon (Phase 14 M2) ---- }
  SysmonPage := CreateCustomPage(DashAccessPage.ID, 'Enhanced Detection',
    'Install Sysmon for advanced endpoint visibility.');

  L := TNewStaticText.Create(SysmonPage.Surface);
  L.Parent := SysmonPage.Surface;
  L.Left := 0;
  L.Top := ScaleY(4);
  L.Width := SysmonPage.SurfaceWidth;
  L.WordWrap := True;
  L.AutoSize := True;
  L.Caption := 'Sysmon (System Monitor) provides detailed logging of process creation, ' +
    'network connections, file changes, registry modifications, and DNS queries. ' +
    'Many TinySocs detection rules depend on Sysmon events for full coverage.';

  SysmonInstallCheck := TNewCheckBox.Create(SysmonPage.Surface);
  SysmonInstallCheck.Parent := SysmonPage.Surface;
  SysmonInstallCheck.Left := 0;
  SysmonInstallCheck.Top := ScaleY(80);
  SysmonInstallCheck.Width := SysmonPage.SurfaceWidth;
  SysmonInstallCheck.Height := ScaleY(22);
  SysmonInstallCheck.Caption := '&Install Sysmon with TinySocs configuration (recommended)';
  SysmonInstallCheck.Checked := True;

  L := TNewStaticText.Create(SysmonPage.Surface);
  L.Parent := SysmonPage.Surface;
  L.Left := ScaleX(20);
  L.Top := SysmonInstallCheck.Top + ScaleY(28);
  L.Width := SysmonPage.SurfaceWidth - ScaleX(20);
  L.WordWrap := True;
  L.AutoSize := True;
  L.Caption := 'Requires administrator rights. Sysmon can be removed later ' +
    'via the uninstaller or by running: Uninstall-TinySocsSysmon';
  L.Font.Color := $666666;

  { ---- Smart defaults ---- }
  SelectedRole := ROLE_TINYBOX;
  InstallTinyBox := True;
  ForceTinyBoxConfig := False;
  AnchorsRetentionDays := 45;
  HeartbeatMinutes := 15;
  RemoveDataOnUninstall := False;
  NodePort := '8081';
  Nodes := 'http://127.0.0.1:8081';
  SiemUrl := 'https://127.0.0.1:9201';
  SiemUser := 'admin';
  SiemPass := '';
  LlmMode := 'none';
  LlmApiKey := '';
  OllamaUrl := 'http://localhost:11434';
  WebhookUrl := '';
  SmtpHost := '';
  SmtpPort := '587';
  EmailFrom := '';
  EmailTo := '';
  EmailEnabled := False;
  DashboardBind := '127.0.0.1';
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
begin
  Result := True;

  if CurPageID = RolePage.ID then
  begin
    SelectedRole := GetSelectedRole;
    InstallTinyBox := (SelectedRole = ROLE_TINYBOX);
    ForceTinyBoxConfig := False;

    { Smart defaults based on role }
    NodePort := '8081';
    SiemUser := 'admin';
    if InstallTinyBox then
    begin
      SiemUrl := 'https://127.0.0.1:9201';
      Nodes := 'http://127.0.0.1:8081';
    end
    else if SelectedRole = ROLE_MASTER then
    begin
      SiemUrl := 'https://127.0.0.1:9201';
      Nodes := 'http://127.0.0.1:8081';
    end
    else
    begin
      SiemUrl := 'https://127.0.0.1:9201';
      Nodes := '';
    end;
  end
  else if CurPageID = SecurityPage.ID then
  begin
    SharedSecret := Trim(SharedSecretEdit.Text);
    if SharedSecret = '' then
    begin
      MsgBox('Shared secret is required.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    SiemPass := Trim(SiemPassEdit.Text);

    { Auto-generate SIEM password if blank and TinyBox role }
    if InstallTinyBox then
    begin
      if SiemPass = '' then
      begin
        SiemPass := GeneratePassword(24);
        CopyToClipboard(SiemPass);
        MsgBox(
          'SIEM password was blank, so a strong one was generated.' + CRLF + CRLF +
          'User: admin' + CRLF +
          'Password: ' + SiemPass + CRLF + CRLF +
          'This password protects both the SIEM datastore and the TinySocs dashboard.' + CRLF +
          'The password has been copied to your clipboard.' + CRLF +
          'It will also be stored securely in Windows Credential Manager.',
          mbInformation,
          MB_OK
        );
        { Show the generated password in the field so the user can see/copy it }
        SiemPassEdit.Text := SiemPass;
      end;
    end;
  end
  else if CurPageID = LlmPage.ID then
  begin
    if LlmModeRadioOpenAI.Checked then
      LlmMode := 'openai'
    else if LlmModeRadioAnthropic.Checked then
      LlmMode := 'anthropic'
    else if LlmModeRadioOllama.Checked then
      LlmMode := 'ollama'
    else
      LlmMode := 'none';

    LlmApiKey := Trim(LlmApiKeyEdit.Text);
    OllamaUrl := Trim(OllamaUrlEdit.Text);
    if OllamaUrl = '' then
      OllamaUrl := 'http://localhost:11434';

    { Validate: if OpenAI or Anthropic selected, API key should be provided }
    if ((LlmMode = 'openai') or (LlmMode = 'anthropic')) and (LlmApiKey = '') then
    begin
      if MsgBox(
        'You selected ' + LlmMode + ' but did not provide an API key.'#13#10 +
        'The assistant will not work without it.'#13#10#13#10 +
        'Continue anyway? You can add the key later in assistant.env.',
        mbConfirmation,
        MB_YESNO
      ) = IDNO then
      begin
        Result := False;
        Exit;
      end;
    end;
  end
  else if CurPageID = NotifPage.ID then
  begin
    WebhookUrl := Trim(WebhookUrlEdit.Text);
    EmailEnabled := EmailEnableCheck.Checked;
    SmtpHost := Trim(SmtpHostEdit.Text);
    SmtpPort := '587';
    EmailFrom := Trim(EmailFromEdit.Text);
    EmailTo := Trim(EmailToEdit.Text);
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
    Log('TinySocs installer build stamp: 2026-02-20-v18-PHASE13-UPGRADE-PATH');

    { ---- Phase 13 M5: Restore operator-edited configs if overwritten by upgrade ---- }
    { The [Files] section uses onlyifdoesntexist, so configs should survive, but }
    { this is a safety net: if the .bak is newer/different, the operator had edits. }
    Log('CurStepChanged: Phase 13 M5 — verifying config backups');
    Script :=
      '$ErrorActionPreference = ''SilentlyContinue''' + CRLF +
      '$dataRoot = Join-Path $env:ProgramData ''TinySocs''' + CRLF +
      '$pairs = @(' + CRLF +
      '  @{ Live = Join-Path $dataRoot ''Collector\agent-config.yml'';      Bak = Join-Path $dataRoot ''Collector\agent-config.yml.pre-upgrade.bak'' },' + CRLF +
      '  @{ Live = Join-Path $dataRoot ''Collector\agent\config.yml'';       Bak = Join-Path $dataRoot ''Collector\agent\config.yml.pre-upgrade.bak'' },' + CRLF +
      '  @{ Live = Join-Path $dataRoot ''Assistant\assistant.env'';          Bak = Join-Path $dataRoot ''Assistant\assistant.env.pre-upgrade.bak'' },' + CRLF +
      '  @{ Live = Join-Path $dataRoot ''Collector\rules\rules.yml'';        Bak = Join-Path $dataRoot ''Collector\rules\rules.yml.pre-upgrade.bak'' }' + CRLF +
      ')' + CRLF +
      'foreach ($p in $pairs) {' + CRLF +
      '  if (Test-Path -LiteralPath $p.Bak -PathType Leaf) {' + CRLF +
      '    if (-not (Test-Path -LiteralPath $p.Live -PathType Leaf)) {' + CRLF +
      '      Write-Host (''[TinySocs][Inno] Restoring missing config from backup: '' + $p.Bak)' + CRLF +
      '      Copy-Item -LiteralPath $p.Bak -Destination $p.Live -Force' + CRLF +
      '    } else {' + CRLF +
      '      # Compare; if live file is different (installer overwrote), restore operator version' + CRLF +
      '      $bakHash = (Get-FileHash -LiteralPath $p.Bak -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash' + CRLF +
      '      $liveHash = (Get-FileHash -LiteralPath $p.Live -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash' + CRLF +
      '      if ($bakHash -and $liveHash -and ($bakHash -ne $liveHash)) {' + CRLF +
      '        Write-Host (''[TinySocs][Inno] Config changed during upgrade; restoring operator version: '' + $p.Live)' + CRLF +
      '        Copy-Item -LiteralPath $p.Bak -Destination $p.Live -Force' + CRLF +
      '      }' + CRLF +
      '    }' + CRLF +
      '    # Clean up backup file after successful restore/verify' + CRLF +
      '    try { Remove-Item -LiteralPath $p.Bak -Force } catch { }' + CRLF +
      '  }' + CRLF +
      '}' + CRLF +
      'Write-Host ''[TinySocs][Inno] Phase 13 M5: Config backup verification complete.''' + CRLF;
    RunPowerShellScript(Script);
    Log('CurStepChanged: Phase 13 M5 — config backup verification done');

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
        'Write-Host ''[TinySocs][Inno] build stamp: 2026-02-20-v18-PHASE13-UPGRADE-PATH''' + #13#10 +
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
        '    $code = & curl.exe -k -s -o NUL -w ''%{http_code}'' --connect-timeout 5 -m 10 -u $pair ($siemUrl + $path) 2>$null' + #13#10 +
        '    if (-not $code) { $code = ''000'' }' + #13#10 +
        '    return [string]$code' + #13#10 +
        '  } catch { return ''000'' }' + #13#10 +
        '}' + #13#10 +
        '' + #13#10 +

        'function _curl_i($path) {' + #13#10 +
        '  try {' + #13#10 +
        '    return (& curl.exe -k -sS -i --connect-timeout 5 -m 10 ($siemUrl + $path) 2>&1 | Out-String)' + #13#10 +
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
        '# Write env vars to BOTH the service Environment key AND NSSM AppEnvironmentExtra.' + #13#10 +
        '# NSSM reads AppEnvironmentExtra under the Parameters subkey, NOT the standard service Environment key.' + #13#10 +
        'try {' + #13#10 +
        '  $svcKey = ''HKLM:\SYSTEM\CurrentControlSet\Services\TinySocsOpenSearch''' + #13#10 +
        '  if (Test-Path $svcKey) {' + #13#10 +
        '    $cur = @()' + #13#10 +
        '    try { $cur = (Get-ItemProperty -Path $svcKey -Name Environment -ErrorAction SilentlyContinue).Environment } catch { $cur = @() }' + #13#10 +
        '    if ($cur -is [string]) { $cur = @($cur) }' + #13#10 +
        '    $cur = @($cur | Where-Object { $_ -and ($_ -notmatch ''^OPENSEARCH_PATH_CONF='') -and ($_ -notmatch ''^OPENSEARCH_INITIAL_ADMIN_PASSWORD='') })' + #13#10 +
        '    $new = @($cur + @(''OPENSEARCH_PATH_CONF='' + $pdConf) + @(''OPENSEARCH_INITIAL_ADMIN_PASSWORD=' + PsEscape(SiemPass) + '''))' + #13#10 +
        '    New-ItemProperty -Path $svcKey -Name Environment -PropertyType MultiString -Value $new -Force | Out-Null' + #13#10 +
        '    Write-Host ''[TinySocs][Inno] TB-10: Set OPENSEARCH_PATH_CONF + OPENSEARCH_INITIAL_ADMIN_PASSWORD in service Environment key''' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-10: failed to update service Environment key (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +
        '# Also write to NSSM AppEnvironmentExtra (Parameters subkey) — this is what NSSM actually reads.' + #13#10 +
        'try {' + #13#10 +
        '  $nssmParamsKey = ''HKLM:\SYSTEM\CurrentControlSet\Services\TinySocsOpenSearch\Parameters''' + #13#10 +
        '  if (Test-Path $nssmParamsKey) {' + #13#10 +
        '    $aeLines = @()' + #13#10 +
        '    try { $aeLines = (Get-ItemProperty -Path $nssmParamsKey -Name AppEnvironmentExtra -ErrorAction SilentlyContinue).AppEnvironmentExtra } catch { $aeLines = @() }' + #13#10 +
        '    if ($aeLines -is [string]) { $aeLines = @($aeLines) }' + #13#10 +
        '    $aeLines = @($aeLines | Where-Object { $_ -and ($_ -notmatch ''^OPENSEARCH_PATH_CONF='') -and ($_ -notmatch ''^OPENSEARCH_INITIAL_ADMIN_PASSWORD='') })' + #13#10 +
        '    $aeNew = @($aeLines + @(''OPENSEARCH_PATH_CONF='' + $pdConf) + @(''OPENSEARCH_INITIAL_ADMIN_PASSWORD=' + PsEscape(SiemPass) + '''))' + #13#10 +
        '    New-ItemProperty -Path $nssmParamsKey -Name AppEnvironmentExtra -PropertyType MultiString -Value $aeNew -Force | Out-Null' + #13#10 +
        '    Write-Host ''[TinySocs][Inno] TB-10: Set OPENSEARCH_PATH_CONF + OPENSEARCH_INITIAL_ADMIN_PASSWORD in NSSM AppEnvironmentExtra''' + #13#10 +
        '  } else {' + #13#10 +
        '    Write-Host ''[TinySocs][Inno] TB-10: NSSM Parameters key not yet created; AppEnvironmentExtra will be set by service registration''' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-10: failed to update NSSM AppEnvironmentExtra (continuing): '' + $_.Exception.Message) }' + #13#10 +
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

        'try {' + #13#10 +
        '  if (Get-Command Repair-TinySocsOpenSearchTlsKeystore -ErrorAction SilentlyContinue) {' + #13#10 +
        '    $cmd = Get-Command Repair-TinySocsOpenSearchTlsKeystore -ErrorAction Stop' + #13#10 +
        '    $pp = @{}' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''OpenSearchRoot''))  { $pp.OpenSearchRoot = $openSearchRoot }' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''ProgramDataConf'')) { $pp.ProgramDataConf = $pdConf }' + #13#10 +
        '    if ($cmd.Parameters.ContainsKey(''CertsDir''))        { $pp.CertsDir = $certsDir }' + #13#10 +
        '    & $cmd @pp | Out-Null' + #13#10 +
        '  } else {' + #13#10 +
        '    Write-Warning ''[TinySocs][Inno] TB-10: Repair-TinySocsOpenSearchTlsKeystore not found (will be handled by persistence script).''' + #13#10 +
        '  }' + #13#10 +
        '} catch {' + #13#10 +
        '  Write-Warning (''[TinySocs][Inno] TB-10: TLS keystore repair skipped (fresh install; persistence script will handle): '' + $_.Exception.Message)' + #13#10 +
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

        '# TB-10c: Bootstrap TLS certs + DPAPI storepass (MUST run before persistence script)' + CRLF +
        'Write-Host ''[TinySocs][Inno] TB-10c: Ensure-TinySocsLocalCaAndServerCert (TLS bootstrap)''' + CRLF +
        'try {' + CRLF +
        '  if (Get-Command Ensure-TinySocsLocalCaAndServerCert -ErrorAction SilentlyContinue) {' + CRLF +
        '    Ensure-TinySocsLocalCaAndServerCert -CertsDir $certsDir' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10c: TLS certs bootstrapped OK''' + CRLF +
        '  } else {' + CRLF +
        '    Write-Warning ''[TinySocs][Inno] TB-10c: Ensure-TinySocsLocalCaAndServerCert not found in module; persistence script will need pre-existing certs.''' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning (''[TinySocs][Inno] TB-10c: TLS cert bootstrap failed (persistence script may still recover): '' + $_.Exception.Message)' + CRLF +
        '}' + CRLF +
        '' + CRLF +

        '# TB-10d: Seed ProgramData config from vendor config (opensearch.yml, jvm.options, etc.)' + CRLF +
        'Write-Host ''[TinySocs][Inno] TB-10d: Seed ProgramData OpenSearch config from vendor''' + CRLF +
        '$vendorCfg = Join-Path $openSearchRoot ''config''' + CRLF +
        'if (Test-Path -LiteralPath $vendorCfg -PathType Container) {' + CRLF +
        '  $essentials = @(''opensearch.yml'',''jvm.options'',''log4j2.properties'')' + CRLF +
        '  foreach ($f in $essentials) {' + CRLF +
        '    $src = Join-Path $vendorCfg $f' + CRLF +
        '    $dst = Join-Path $pdConf $f' + CRLF +
        '    if ((Test-Path -LiteralPath $src -PathType Leaf) -and (-not (Test-Path -LiteralPath $dst -PathType Leaf))) {' + CRLF +
        '      Copy-Item -LiteralPath $src -Destination $dst -Force' + CRLF +
        '      Write-Host (''[TinySocs][Inno] TB-10d: Seeded '' + $f + '' into ProgramData config'')' + CRLF +
        '    }' + CRLF +
        '  }' + CRLF +
        '  # Also seed jvm.options.d directory' + CRLF +
        '  $srcD = Join-Path $vendorCfg ''jvm.options.d''' + CRLF +
        '  $dstD = Join-Path $pdConf ''jvm.options.d''' + CRLF +
        '  if ((Test-Path -LiteralPath $srcD -PathType Container) -and (-not (Test-Path -LiteralPath $dstD -PathType Container))) {' + CRLF +
        '    Copy-Item -LiteralPath $srcD -Destination $dstD -Recurse -Force' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10d: Seeded jvm.options.d into ProgramData config''' + CRLF +
        '  }' + CRLF +
        '  # Also seed opensearch-security directory' + CRLF +
        '  foreach ($secName in @(''opensearch-security'',''security'')) {' + CRLF +
        '    $srcS = Join-Path $vendorCfg $secName' + CRLF +
        '    $dstS = Join-Path $pdConf $secName' + CRLF +
        '    if (Test-Path -LiteralPath $srcS -PathType Container) {' + CRLF +
        '      if (-not (Test-Path -LiteralPath $dstS -PathType Container)) {' + CRLF +
        '        New-Item -ItemType Directory -Path $dstS -Force | Out-Null' + CRLF +
        '      }' + CRLF +
        '      # Seed missing files using content-copy (not Copy-Item) so new files' + CRLF +
        '      # inherit ACLs from the destination directory instead of carrying' + CRLF +
        '      # broken ACLs from the vendor zip source.' + CRLF +
        '      Get-ChildItem -LiteralPath $srcS -File -ErrorAction SilentlyContinue | ForEach-Object {' + CRLF +
        '        $dstF = Join-Path $dstS $_.Name' + CRLF +
        '        if (-not (Test-Path -LiteralPath $dstF -PathType Leaf)) {' + CRLF +
        '          [System.IO.File]::WriteAllBytes($dstF, [System.IO.File]::ReadAllBytes($_.FullName))' + CRLF +
        '          Write-Host (''[TinySocs][Inno] TB-10d: Seeded missing '' + $_.Name + '' into '' + $secName)' + CRLF +
        '        }' + CRLF +
        '      }' + CRLF +
        '    }' + CRLF +
        '  }' + CRLF +
        '} else {' + CRLF +
        '  Write-Warning (''[TinySocs][Inno] TB-10d: Vendor config not found at: '' + $vendorCfg)' + CRLF +
        '}' + CRLF +
        '' + CRLF +

        '# TB-10d-acl: Fix ACLs on seeded opensearch-security dir so OpenSearch + securityadmin can read config.' + CRLF +
        '# WriteAllBytes files inherit no ACEs and have inheritance DISABLED (zip-extraction artifact).' + CRLF +
        '# Re-enable inheritance so the directory ACEs (Administrators:F, SYSTEM:F) propagate to files.' + CRLF +
        'try {' + CRLF +
        '  $secCfgDir = Join-Path $pdConf ''opensearch-security''' + CRLF +
        '  if (Test-Path -LiteralPath $secCfgDir -PathType Container) {' + CRLF +
        '    $sysSid  = New-Object System.Security.Principal.SecurityIdentifier(''S-1-5-18'')' + CRLF +
        '    $admSid  = New-Object System.Security.Principal.SecurityIdentifier(''S-1-5-32-544'')' + CRLF +
        '    $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule($sysSid, ''FullControl'', ''Allow'')' + CRLF +
        '    $admRule = New-Object System.Security.AccessControl.FileSystemAccessRule($admSid, ''FullControl'', ''Allow'')' + CRLF +
        '    $fixed = 0' + CRLF +
        '    foreach ($f in (Get-ChildItem -LiteralPath $secCfgDir -File -ErrorAction SilentlyContinue)) {' + CRLF +
        '      try {' + CRLF +
        '        $acl = Get-Acl -LiteralPath $f.FullName' + CRLF +
        '        $acl.SetAccessRuleProtection($false, $true)' + CRLF +
        '        $acl.AddAccessRule($sysRule)' + CRLF +
        '        $acl.AddAccessRule($admRule)' + CRLF +
        '        Set-Acl -LiteralPath $f.FullName -AclObject $acl' + CRLF +
        '        $fixed++' + CRLF +
        '      } catch {' + CRLF +
        '        Write-Warning (''[TinySocs][Inno] TB-10d-acl: failed on '' + $f.Name + '': '' + $_.Exception.Message)' + CRLF +
        '      }' + CRLF +
        '    }' + CRLF +
        '    Write-Host (''[TinySocs][Inno] TB-10d-acl: Fixed ACLs on '' + $fixed + '' files in opensearch-security'')' + CRLF +
        '  }' + CRLF +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-10d-acl: ACL fix failed (continuing): '' + $_.Exception.Message) }' + CRLF +
        '' + CRLF +

        '# TB-10e: Bootstrap opensearch.yml with TLS + single-node settings' + CRLF +
        'Write-Host ''[TinySocs][Inno] TB-10e: Ensure-TinySocsOpenSearchDeterministicBootstrap''' + CRLF +
        'try {' + CRLF +
        '  if (Get-Command Ensure-TinySocsOpenSearchDeterministicBootstrap -ErrorAction SilentlyContinue) {' + CRLF +
        '    Ensure-TinySocsOpenSearchDeterministicBootstrap `' + CRLF +
        '      -OpenSearchRoot $openSearchRoot `' + CRLF +
        '      -ProgramDataConf $pdConf `' + CRLF +
        '      -CertsDir $certsDir `' + CRLF +
        '      -HttpPort 9201 `' + CRLF +
        '      -AllowDefaultInitSecurityIndex $true' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10e: OpenSearch deterministic bootstrap OK''' + CRLF +
        '  } else {' + CRLF +
        '    Write-Warning ''[TinySocs][Inno] TB-10e: Ensure-TinySocsOpenSearchDeterministicBootstrap not found in module''' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning (''[TinySocs][Inno] TB-10e: deterministic bootstrap failed: '' + $_.Exception.Message)' + CRLF +
        '}' + CRLF +
        '' + CRLF +

        '# Also ensure discovery.type and node settings for single-node TinyBox' + CRLF +
        '$pdYml = Join-Path $pdConf ''opensearch.yml''' + CRLF +
        'if (Test-Path -LiteralPath $pdYml -PathType Leaf) {' + CRLF +
        '  $ymlRaw = Get-Content -LiteralPath $pdYml -Raw' + CRLF +
        '  $needsWrite = $false' + CRLF +
        '  if ($ymlRaw -notmatch ''(?m)^\s*discovery\.type\s*:'') {' + CRLF +
        '    $ymlRaw = $ymlRaw.TrimEnd() + "`r`ndiscovery.type: single-node`r`n"' + CRLF +
        '    $needsWrite = $true' + CRLF +
        '  }' + CRLF +
        '  if ($ymlRaw -notmatch ''(?m)^\s*network\.host\s*:'') {' + CRLF +
        '    $ymlRaw = $ymlRaw.TrimEnd() + "`r`nnetwork.host: 127.0.0.1`r`n"' + CRLF +
        '    $needsWrite = $true' + CRLF +
        '  }' + CRLF +
        '  if ($needsWrite) {' + CRLF +
        '    [System.IO.File]::WriteAllText($pdYml, $ymlRaw, (New-Object System.Text.UTF8Encoding($false)))' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10e: Added discovery.type/network.host to opensearch.yml''' + CRLF +
        '  }' + CRLF +
        '}' + CRLF +
        '' + CRLF +

        '# TB-10e2: Ensure admin_dn is in opensearch.yml and ACLs are correct on security config.' + CRLF +
        '# These functions exist in the module but were never wired into the installer flow.' + CRLF +
        '# Without admin_dn, securityadmin cannot authenticate as an admin user.' + CRLF +
        '# Without correct ACLs, securityadmin cannot read the security YAML files.' + CRLF +
        'Write-Host ''[TinySocs][Inno] TB-10e2: Ensure admin_dn + security config ACLs''' + CRLF +
        'try {' + CRLF +
        '  $pdYml = Join-Path $pdConf ''opensearch.yml''' + CRLF +
        '  if (Get-Command Ensure-TinySocsOpenSearchAdminDn -ErrorAction SilentlyContinue) {' + CRLF +
        '    Ensure-TinySocsOpenSearchAdminDn -OpenSearchYmlPath $pdYml -AdminDn ''CN=TinySocs-OpenSearch-Admin''' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10e2: admin_dn set in opensearch.yml''' + CRLF +
        '  } else {' + CRLF +
        '    Write-Warning ''[TinySocs][Inno] TB-10e2: Ensure-TinySocsOpenSearchAdminDn not found in module''' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning (''[TinySocs][Inno] TB-10e2: admin_dn setup failed: '' + $_.Exception.Message)' + CRLF +
        '}' + CRLF +
        'try {' + CRLF +
        '  $secCfgDir = Join-Path $pdConf ''opensearch-security''' + CRLF +
        '  if (Get-Command Ensure-TinySocsAclForOpenSearchSecurityConfig -ErrorAction SilentlyContinue) {' + CRLF +
        '    Ensure-TinySocsAclForOpenSearchSecurityConfig -SecurityConfigDir $secCfgDir' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10e2: Security config ACLs normalized''' + CRLF +
        '  } else {' + CRLF +
        '    Write-Warning ''[TinySocs][Inno] TB-10e2: Ensure-TinySocsAclForOpenSearchSecurityConfig not found in module''' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning (''[TinySocs][Inno] TB-10e2: ACL normalization failed: '' + $_.Exception.Message)' + CRLF +
        '}' + CRLF +
        '' + CRLF +

        '# TB-10f: Hash wizard password into internal_users.yml BEFORE first service start' + CRLF +
        '# This ensures OpenSearch initializes its security index with the correct admin hash.' + CRLF +
        '# Without this, the bundled static hash is used and the wizard password never works.' + CRLF +
        'Write-Host ''[TinySocs][Inno] TB-10f: Pre-hashing wizard password into internal_users.yml''' + CRLF +
        'try {' + CRLF +
        '  if (Get-Command Set-TinySocsOpenSearchAdminPasswordInConfig -ErrorAction SilentlyContinue) {' + CRLF +
        '    Set-TinySocsOpenSearchAdminPasswordInConfig `' + CRLF +
        '      -OpenSearchRoot $openSearchRoot `' + CRLF +
        '      -ConfigRoot $pdConf `' + CRLF +
        '      -AdminPassword $p_in' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10f: internal_users.yml updated with wizard password hash (pre-boot)''' + CRLF +
        '  } else {' + CRLF +
        '    Write-Warning ''[TinySocs][Inno] TB-10f: Set-TinySocsOpenSearchAdminPasswordInConfig not found; first boot may use bundled hash''' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning (''[TinySocs][Inno] TB-10f: Pre-boot password hash failed (TB-12 fallback will retry): '' + $_.Exception.Message)' + CRLF +
        '}' + CRLF +
        '' + CRLF +

        '# TB-10g: Write DPAPI admin-pass file BEFORE first boot so wrapper STAGE 3 can read it.' + CRLF +
        '# Without this, the wrapper can''t set OPENSEARCH_INITIAL_ADMIN_PASSWORD on first boot' + CRLF +
        '# (CredMan is unavailable under SYSTEM and the DPAPI file doesn''t exist yet).' + CRLF +
        'Write-Host ''[TinySocs][Inno] TB-10g: Writing DPAPI admin-pass file (pre-boot)''' + CRLF +
        'try {' + CRLF +
        '  if (Get-Command Write-TinySocsSiemAdminPassToDpapiFile -ErrorAction SilentlyContinue) {' + CRLF +
        '    Write-TinySocsSiemAdminPassToDpapiFile -CertsDir $certsDir -AdminPass $p_in | Out-Null' + CRLF +
        '    Write-Host ''[TinySocs][Inno] TB-10g: DPAPI admin-pass file written OK''' + CRLF +
        '  } else {' + CRLF +
        '    Write-Warning ''[TinySocs][Inno] TB-10g: Write-TinySocsSiemAdminPassToDpapiFile not found; STAGE 3 DPAPI fallback won''''t be available on first boot''' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning (''[TinySocs][Inno] TB-10g: DPAPI admin-pass file write failed (continuing): '' + $_.Exception.Message)' + CRLF +
        '}' + CRLF +
        '' + CRLF +

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
        '  # If 401, security is UP but password may not match wizard. Try to fix.' + #13#10 +
        '  if ($c -eq ''401'') {' + #13#10 +
        '    Write-Host ''[TinySocs][Inno] TB-12: Got 401 -- rehashing admin password into internal_users.yml''' + #13#10 +
        '    try {' + #13#10 +
        '      if (Get-Command Set-TinySocsOpenSearchAdminPasswordInConfig -ErrorAction SilentlyContinue) {' + #13#10 +
        '        Set-TinySocsOpenSearchAdminPasswordInConfig `' + #13#10 +
        '          -OpenSearchRoot $openSearchRoot `' + #13#10 +
        '          -ConfigRoot $pdConf `' + #13#10 +
        '          -AdminPassword $p_in' + #13#10 +
        '        Write-Host ''[TinySocs][Inno] TB-12: internal_users.yml updated with wizard password hash''' + #13#10 +
        '      } else { Write-Warning ''[TinySocs][Inno] Set-TinySocsOpenSearchAdminPasswordInConfig not found'' }' + #13#10 +
        '    } catch { Write-Warning (''[TinySocs][Inno] TB-12 admin hash failed: '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +
        '    Write-Host ''[TinySocs][Inno] TB-12: Pushing updated security config via securityadmin''' + #13#10 +
        '    try {' + #13#10 +
        '      if (Get-Command Ensure-TinySocsOpenSearchSecurityInitialized -ErrorAction SilentlyContinue) {' + #13#10 +
        '        Ensure-TinySocsOpenSearchSecurityInitialized `' + #13#10 +
        '          -OpenSearchRoot $openSearchRoot `' + #13#10 +
        '          -ProgramDataConf $pdConf `' + #13#10 +
        '          -Url ''https://localhost:9201''' + #13#10 +
        '        Write-Host ''[TinySocs][Inno] TB-12: securityadmin push completed''' + #13#10 +
        '      } else { Write-Warning ''[TinySocs][Inno] Ensure-TinySocsOpenSearchSecurityInitialized not found'' }' + #13#10 +
        '    } catch { Write-Warning (''[TinySocs][Inno] TB-12 securityadmin push failed: '' + $_.Exception.Message) }' + #13#10 +
        '  }' + #13#10 +
        '} catch { Write-Warning (''[TinySocs][Inno] TB-12 encountered error (continuing): '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +
        '# Brief pause after potential securityadmin push to let cluster reload' + #13#10 +
        'Start-Sleep -Seconds 3' + #13#10 +
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
        '' + #13#10 +
        '  # Write proven credentials directly into assistant.env (Phase 11 CredMan reconciliation may be too late)' + #13#10 +
        '  $aEnv = Join-Path $env:ProgramData ''TinySocs\Assistant\assistant.env''' + #13#10 +
        '  if (Test-Path $aEnv) {' + #13#10 +
        '    try {' + #13#10 +
        '      $ec = Get-Content $aEnv -Raw' + #13#10 +
        '      $ec = $ec -replace ''(?m)^SIEM_PASS=.*$'', (''SIEM_PASS='' + $p)' + #13#10 +
        '      $ec = $ec -replace ''(?m)^SIEM_USER=.*$'', (''SIEM_USER='' + $u)' + #13#10 +
        '      $ec = $ec -replace ''(?m)^SIEM_URL=.*$'',  (''SIEM_URL='' + $siemUrl)' + #13#10 +
        '      Set-Content -Path $aEnv -Value $ec -Force' + #13#10 +
        '      Write-Host (''[TinySocs][Inno] assistant.env updated with PROVEN credentials (user='' + $u + '')'')' + #13#10 +
        '    } catch { Write-Warning (''[TinySocs][Inno] assistant.env credential write failed: '' + $_.Exception.Message) }' + #13#10 +
        '  }' + #13#10 +
        '} else {' + #13#10 +
        '  Write-Warning ''[TinySocs][Inno] No credential candidate AUTHENTICATED (authinfo never returned 200).''' + #13#10 +
        '  Write-Host ''[TinySocs][Inno] FALLBACK: attempting password rehash + securityadmin push since no creds worked''' + #13#10 +
        '  try {' + #13#10 +
        '    if (Get-Command Set-TinySocsOpenSearchAdminPasswordInConfig -ErrorAction SilentlyContinue) {' + #13#10 +
        '      Set-TinySocsOpenSearchAdminPasswordInConfig `' + #13#10 +
        '        -OpenSearchRoot $openSearchRoot `' + #13#10 +
        '        -ConfigRoot $pdConf `' + #13#10 +
        '        -AdminPassword $p_in' + #13#10 +
        '      Write-Host ''[TinySocs][Inno] FALLBACK: internal_users.yml updated with wizard password hash''' + #13#10 +
        '    } else { Write-Warning ''Set-TinySocsOpenSearchAdminPasswordInConfig not found'' }' + #13#10 +
        '  } catch { Write-Warning (''[TinySocs][Inno] FALLBACK admin hash failed: '' + $_.Exception.Message) }' + #13#10 +
        '  try {' + #13#10 +
        '    if (Get-Command Ensure-TinySocsOpenSearchSecurityInitialized -ErrorAction SilentlyContinue) {' + #13#10 +
        '      Ensure-TinySocsOpenSearchSecurityInitialized `' + #13#10 +
        '        -OpenSearchRoot $openSearchRoot `' + #13#10 +
        '        -ProgramDataConf $pdConf `' + #13#10 +
        '        -Url ''https://localhost:9201''' + #13#10 +
        '      Write-Host ''[TinySocs][Inno] FALLBACK: securityadmin push completed''' + #13#10 +
        '    } else { Write-Warning ''Ensure-TinySocsOpenSearchSecurityInitialized not found'' }' + #13#10 +
        '  } catch { Write-Warning (''[TinySocs][Inno] FALLBACK securityadmin push failed: '' + $_.Exception.Message) }' + #13#10 +
        '' + #13#10 +
        '  # Re-probe after fallback rehash' + #13#10 +
        '  Write-Host ''[TinySocs][Inno] FALLBACK: waiting 5s then re-probing credentials...''' + #13#10 +
        '  Start-Sleep -Seconds 5' + #13#10 +
        '  $reProbeDeadline = (Get-Date).AddSeconds(60)' + #13#10 +
        '  while ((Get-Date) -lt $reProbeDeadline -and (-not $ok)) {' + #13#10 +
        '    foreach ($pair in $candidates) {' + #13#10 +
        '      $cu = $pair[0]; $cp = $pair[1]' + #13#10 +
        '      $hc = _http $cu $cp $probePath' + #13#10 +
        '      Write-Host (''[TinySocs][Inno] FALLBACK re-probe user='' + $cu + '' http='' + $hc)' + #13#10 +
        '      if ($hc -eq ''200'') { $u = $cu; $p = $cp; $ok = $true; $okCode = $hc; break }' + #13#10 +
        '    }' + #13#10 +
        '    if (-not $ok) { Start-Sleep -Seconds 3 }' + #13#10 +
        '  }' + #13#10 +
        '  if ($ok) {' + #13#10 +
        '    Write-Host (''[TinySocs][Inno] FALLBACK: creds now AUTHENTICATED after rehash: user='' + $u)' + #13#10 +
        '    $aEnv = Join-Path $env:ProgramData ''TinySocs\Assistant\assistant.env''' + #13#10 +
        '    if (Test-Path $aEnv) {' + #13#10 +
        '      try {' + #13#10 +
        '        $ec = Get-Content $aEnv -Raw' + #13#10 +
        '        $ec = $ec -replace ''(?m)^SIEM_PASS=.*$'', (''SIEM_PASS='' + $p)' + #13#10 +
        '        $ec = $ec -replace ''(?m)^SIEM_USER=.*$'', (''SIEM_USER='' + $u)' + #13#10 +
        '        $ec = $ec -replace ''(?m)^SIEM_URL=.*$'',  (''SIEM_URL='' + $siemUrl)' + #13#10 +
        '        Set-Content -Path $aEnv -Value $ec -Force' + #13#10 +
        '        Write-Host ''[TinySocs][Inno] FALLBACK: assistant.env updated with proven credentials''' + #13#10 +
        '      } catch { Write-Warning (''[TinySocs][Inno] FALLBACK assistant.env write failed: '' + $_.Exception.Message) }' + #13#10 +
        '    }' + #13#10 +
        '  } else {' + #13#10 +
        '    Write-Warning ''[TinySocs][Inno] FALLBACK: credentials still not working after rehash. Manual intervention required.''' + #13#10 +
        '  }' + #13#10 +
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

    { ---- Phase 11: Register LLM Assistant service (if bundle was deployed) ---- }
    Log('CurStepChanged: Phase 11 — checking for Assistant bundle');
    if FileExists(ExpandConstant('{app}\Assistant\TinySocs-Quickstart.exe')) then
    begin
      Log('CurStepChanged: Assistant bundle found. Registering TinySocsAssistant service.');

      Script :=
        '$ErrorActionPreference = ''Continue''' + CRLF +
        'Import-Module ''' + PsEscape(InstallerModule) + ''' -Force' + CRLF +
        '' + CRLF +
        '# Inject SIEM credentials into assistant.env from wizard inputs' + CRLF +
        '$envFile = Join-Path $env:ProgramData ''TinySocs\Assistant\assistant.env''' + CRLF +
        'if (Test-Path $envFile) {' + CRLF +
        '  $content = Get-Content $envFile -Raw' + CRLF +
        '  $content = $content -replace ''(?m)^SIEM_URL=.*$'', (''SIEM_URL='' + ''' + PsEscape(SiemUrl) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^SIEM_USER=.*$'', (''SIEM_USER='' + ''' + PsEscape(SiemUser) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^SIEM_PASS=.*$'', (''SIEM_PASS='' + ''' + PsEscape(SiemPass) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^MASTER_SHARED_SECRET=.*$'', (''MASTER_SHARED_SECRET='' + ''' + PsEscape(SharedSecret) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^BOT_SHARED_SECRET=.*$'', (''BOT_SHARED_SECRET='' + ''' + PsEscape(SharedSecret) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^LLM_MODE=.*$'', (''LLM_MODE='' + ''' + PsEscape(LlmMode) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^OPENAI_API_KEY=.*$'', (''OPENAI_API_KEY='' + ''' + PsEscape(LlmApiKey) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^ANTHROPIC_API_KEY=.*$'', (''ANTHROPIC_API_KEY='' + ''' + PsEscape(LlmApiKey) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^OFFLINE_LLM_URL=.*$'', (''OFFLINE_LLM_URL='' + ''' + PsEscape(OllamaUrl) + ''')' + CRLF +
        '  $content = $content -replace ''(?m)^WEBHOOK_URL=.*$'', (''WEBHOOK_URL='' + ''' + PsEscape(WebhookUrl) + ''')' + CRLF +
        '  if (''' + PsEscape(WebhookUrl) + ''' -ne '''') {' + CRLF +
        '    $content = $content -replace ''(?m)^WEBHOOK_ENABLED=.*$'', ''WEBHOOK_ENABLED=1''' + CRLF +
        '  }' + CRLF +
        '  Set-Content -Path $envFile -Value $content -Force' + CRLF +
        '  Write-Host ''[TinySocs][Inno] assistant.env updated with SIEM + LLM + webhook credentials''' + CRLF +
        '}' + CRLF +
        '' + CRLF +
        '# Reconcile SIEM_PASS with CredMan (Phase 10 credential probe may have' + CRLF +
        '# discovered a different working password than the wizard provided).' + CRLF +
        '# CredMan is the source of truth after OpenSearch first-boot.' + CRLF +
        'try {' + CRLF +
        '  $cmCreds = Get-TSSiemCredsCanonical' + CRLF +
        '  if ($cmCreds -and -not [string]::IsNullOrWhiteSpace($cmCreds.Pass)) {' + CRLF +
        '    $cmPass = $cmCreds.Pass' + CRLF +
        '    $cmUser = $cmCreds.User; if (-not $cmUser) { $cmUser = ''admin'' }' + CRLF +
        '    $cmUrl  = $cmCreds.Url;  if (-not $cmUrl)  { $cmUrl  = ''' + PsEscape(SiemUrl) + ''' }' + CRLF +
        '    if (Test-Path $envFile) {' + CRLF +
        '      $c2 = Get-Content $envFile -Raw' + CRLF +
        '      $c2 = $c2 -replace ''(?m)^SIEM_PASS=.*$'', (''SIEM_PASS='' + $cmPass)' + CRLF +
        '      $c2 = $c2 -replace ''(?m)^SIEM_USER=.*$'', (''SIEM_USER='' + $cmUser)' + CRLF +
        '      $c2 = $c2 -replace ''(?m)^SIEM_URL=.*$'',  (''SIEM_URL=''  + $cmUrl)' + CRLF +
        '      Set-Content -Path $envFile -Value $c2 -Force' + CRLF +
        '      Write-Host (''[TinySocs][Inno] assistant.env reconciled with CredMan (user='' + $cmUser + '')'')' + CRLF +
        '    }' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Host (''[TinySocs][Inno] CredMan reconciliation skipped: '' + $_.Exception.Message)' + CRLF +
        '}' + CRLF +
        '' + CRLF +
        '# Register assistant service (reads assistant.env and bakes into NSSM registry)' + CRLF +
        'if (Get-Command Ensure-TinySocsAssistantService -ErrorAction SilentlyContinue) {' + CRLF +
        '  Ensure-TinySocsAssistantService -InstallRoot ''' + PsEscape(AppDir) + '''' + CRLF +
        '} else {' + CRLF +
        '  Write-Warning ''[TinySocs][Inno] Ensure-TinySocsAssistantService not found in module; skipping assistant service.''' + CRLF +
        '}' + CRLF;

      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Assistant service registration failed (non-fatal).')
      else
        Log('CurStepChanged: Assistant service registered successfully.');
    end
    else
      Log('CurStepChanged: Assistant bundle not found; skipping TinySocsAssistant registration.');

    { ---- Phase 12: Import OpenSearch Dashboards (if TinyBox was installed) ---- }
    if InstallTinyBox then
    begin
      Log('CurStepChanged: Phase 12 — importing dashboards');
      Script :=
        '$ErrorActionPreference = ''Continue''' + CRLF +
        'Import-Module ''' + PsEscape(InstallerModule) + ''' -Force' + CRLF +
        '' + CRLF +
        '$ndjson = Join-Path ''' + PsEscape(AppDir) + ''' ''OpenSearch\dashboards\tinysocs-dashboards.ndjson''' + CRLF +
        'if (Test-Path $ndjson) {' + CRLF +
        '  Import-TinySocsDashboards `' + CRLF +
        '    -DashboardsUrl ''https://localhost:5602'' `' + CRLF +
        '    -NdjsonPath $ndjson `' + CRLF +
        '    -SiemUser ''' + PsEscape(SiemUser) + ''' `' + CRLF +
        '    -SiemPass ''' + PsEscape(SiemPass) + '''' + CRLF +
        '} else {' + CRLF +
        '  Write-Warning ''[TinySocs][Inno] Dashboard NDJSON not found; skipping import.''' + CRLF +
        '}' + CRLF;

      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Dashboard import failed (non-fatal).')
      else
        Log('CurStepChanged: Dashboards imported successfully.');
    end;

    { ---- Phase 12: Write notification config to agent-config.yml ---- }
    if (WebhookUrl <> '') or ((EmailEnabled) and (SmtpHost <> '')) then
    begin
      Log('CurStepChanged: Phase 12 — writing notification config');
      Script :=
        '$ErrorActionPreference = ''Continue''' + CRLF +
        'Import-Module ''' + PsEscape(InstallerModule) + ''' -Force' + CRLF +
        '' + CRLF +
        '$configPath = Join-Path $env:ProgramData ''TinySocs\Collector\agent-config.yml''' + CRLF +
        'if (-not (Test-Path $configPath)) {' + CRLF +
        '  $configPath = Join-Path $env:ProgramData ''TinySocs\Collector\agent\config.yml''' + CRLF +
        '}' + CRLF +
        '' + CRLF +
        '# Use regex replacement to preserve YAML nesting (Set-TinySocsYamlScalar writes to root level)' + CRLF +
        'if (Test-Path $configPath) {' + CRLF +
        '  $content = Get-Content $configPath -Raw' + CRLF;

      if WebhookUrl <> '' then
        Script := Script +
          '  $content = $content -replace ''(?m)(^\s+webhook_url:\s*).*$'', (''${1}' + PsEscape(WebhookUrl) + ''')' + CRLF +
          '  Write-Host ''[TinySocs][Inno] Set webhook_url in agent-config.yml (nested)''' + CRLF;

      if (EmailEnabled) and (SmtpHost <> '') then
        Script := Script +
          '  $content = $content -replace ''(?m)(^\s+smtp_host:\s*).*$'', (''${1}' + PsEscape(SmtpHost) + ''')' + CRLF +
          '  $content = $content -replace ''(?m)(^\s+smtp_port:\s*).*$'', (''${1}' + PsEscape(SmtpPort) + ''')' + CRLF +
          '  $content = $content -replace ''(?m)(^\s+(?:email_)?from:\s*).*$'', (''${1}' + PsEscape(EmailFrom) + ''')' + CRLF +
          '  $content = $content -replace ''(?m)(^\s+(?:email_)?to:\s*).*$'', (''${1}' + PsEscape(EmailTo) + ''')' + CRLF +
          '  Write-Host ''[TinySocs][Inno] Set email notification config in agent-config.yml (nested)''' + CRLF;

      Script := Script +
        '  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)' + CRLF +
        '  [System.IO.File]::WriteAllText($configPath, $content, $utf8NoBom)' + CRLF +
        '} else {' + CRLF +
        '  Write-Warning ''[TinySocs][Inno] agent-config.yml not found; cannot write notification config.''' + CRLF +
        '}' + CRLF;

      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Notification config write failed (non-fatal).')
      else
        Log('CurStepChanged: Notification config written successfully.');
    end;

    { ---- Phase 12: Register daily summary scheduled task ---- }
    if (EmailEnabled) and (EmailTo <> '') then
    begin
      Log('CurStepChanged: Phase 12 — registering daily summary scheduled task');
      Script :=
        '$ErrorActionPreference = ''Continue''' + CRLF +
        'Import-Module ''' + PsEscape(InstallerModule) + ''' -Force' + CRLF +
        'Register-TinySocsDailySummaryTask -To ''' + PsEscape(EmailTo) + '''' + CRLF;

      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Daily summary task registration failed (non-fatal).')
      else
        Log('CurStepChanged: Daily summary scheduled task registered successfully.');
    end;

    { ---- Phase 14 M0: Dashboard access mode ---- }
    Log('CurStepChanged: Phase 14 — Dashboard access config');
    if DashNetworkRadio.Checked then
      DashboardBind := '0.0.0.0'
    else
      DashboardBind := '127.0.0.1';

    if DashboardBind = '0.0.0.0' then
    begin
      Script :=
        '$ErrorActionPreference = "Continue"' + CRLF +
        'Import-Module "' + PsEscape(InstallerModule) + '" -Force' + CRLF +
        'try {' + CRLF +
        '  Write-Host "[TinySocs][Inno] Generating dashboard TLS certificate..."' + CRLF +
        '  $certs = New-TinySocsDashboardCert' + CRLF +
        '  $envFile = Join-Path $env:ProgramData "TinySocs\Assistant\assistant.env"' + CRLF +
        '  if (Test-Path $envFile) {' + CRLF +
        '    $lines = @(Get-Content $envFile)' + CRLF +
        '    $lines = $lines | Where-Object { $_ -notmatch "^DASHBOARD_(BIND|TLS_CERT|TLS_KEY)=" }' + CRLF +
        '    $lines += "DASHBOARD_BIND=0.0.0.0"' + CRLF +
        '    $lines += ("DASHBOARD_TLS_CERT=" + $certs.CertPath)' + CRLF +
        '    $lines += ("DASHBOARD_TLS_KEY=" + $certs.KeyPath)' + CRLF +
        '    Set-Content -Path $envFile -Value $lines -Encoding UTF8' + CRLF +
        '  }' + CRLF +
        '  Write-Host "[TinySocs][Inno] Dashboard configured for network access with TLS."' + CRLF +
        '  # Re-register assistant service so NSSM bakes in the new TLS cert paths' + CRLF +
        '  if (Get-Command Ensure-TinySocsAssistantService -ErrorAction SilentlyContinue) {' + CRLF +
        '    Ensure-TinySocsAssistantService -InstallRoot "' + PsEscape(AppDir) + '"' + CRLF +
        '    Write-Host "[TinySocs][Inno] Assistant service env updated with TLS cert paths."' + CRLF +
        '  }' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning ("[TinySocs][Inno] Dashboard TLS cert generation failed (non-fatal): " + $_.Exception.Message)' + CRLF +
        '}' + CRLF;
      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Dashboard TLS cert generation failed (non-fatal).')
      else
        Log('CurStepChanged: Dashboard TLS cert generated successfully.');
    end
    else
      Log('CurStepChanged: Dashboard configured for localhost-only access.');

    { ---- Phase 14 M2: Sysmon deployment ---- }
    if SysmonInstallCheck.Checked then
    begin
      Log('CurStepChanged: Phase 14 — Installing Sysmon');
      Script :=
        '$ErrorActionPreference = "Continue"' + CRLF +
        'Import-Module "' + PsEscape(InstallerModule) + '" -Force' + CRLF +
        'try {' + CRLF +
        '  Install-TinySocsSysmon' + CRLF +
        '  Write-Host "[TinySocs][Inno] Sysmon installed successfully."' + CRLF +
        '} catch {' + CRLF +
        '  Write-Warning ("[TinySocs][Inno] Sysmon install failed (non-fatal): " + $_.Exception.Message)' + CRLF +
        '}' + CRLF;
      if not RunPowerShellScript(Script) then
        Log('CurStepChanged: Sysmon install failed (non-fatal).')
      else
        Log('CurStepChanged: Sysmon installed successfully.');
    end
    else
      Log('CurStepChanged: Sysmon install skipped by user.');

    Log('CurStepChanged(ssPostInstall): end');
  except
    Log('CurStepChanged: exception: ' + GetExceptionMessage);
    Log('CurStepChanged: continuing install.');
  end;
end;

{ ---- Phase 13 M5: Upgrade path validation ---- }
{ PrepareToInstall runs BEFORE files are deployed. Detect existing install, }
{ back up operator-edited configs so the 'onlyifdoesntexist' flag + file overwrite }
{ cannot clobber them, and verify services can be stopped cleanly. }

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  DataRoot: String;
  AgentCfg: String;
  AgentCfgLegacy: String;
  AssistantEnv: String;
  RulesFile: String;
  PrevUninstExe: String;
  PrevVersion: String;
begin
  Result := '';  { empty = OK to continue }
  NeedsRestart := False;

  DataRoot := ExpandConstant('{commonappdata}\TinySocs');
  AgentCfg := DataRoot + '\Collector\agent-config.yml';
  AgentCfgLegacy := DataRoot + '\Collector\agent\config.yml';
  AssistantEnv := DataRoot + '\Assistant\assistant.env';
  RulesFile := DataRoot + '\Collector\rules\rules.yml';

  { Detect previous installation }
  PrevUninstExe := ExpandConstant('{app}\unins000.exe');
  if FileExists(PrevUninstExe) then
  begin
    Log('PrepareToInstall: UPGRADE detected — previous uninstaller found at: ' + PrevUninstExe);

    { Read previous version from registry if available }
    PrevVersion := '';
    try
      if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1',
                             'DisplayVersion', PrevVersion) then
        Log('PrepareToInstall: Previous version: ' + PrevVersion)
      else
        Log('PrepareToInstall: Could not read previous version from registry.');
    except
      Log('PrepareToInstall: Exception reading previous version.');
    end;
  end
  else
    Log('PrepareToInstall: Fresh install (no previous uninstaller found).');

  { Back up operator-edited config files before file deployment }
  if FileExists(AgentCfg) then
  begin
    Log('PrepareToInstall: Backing up ' + AgentCfg);
    try
      FileCopy(AgentCfg, AgentCfg + '.pre-upgrade.bak', False);
    except
      Log('PrepareToInstall: WARNING — failed to back up agent-config.yml');
    end;
  end;

  if FileExists(AgentCfgLegacy) then
  begin
    Log('PrepareToInstall: Backing up ' + AgentCfgLegacy);
    try
      FileCopy(AgentCfgLegacy, AgentCfgLegacy + '.pre-upgrade.bak', False);
    except
      Log('PrepareToInstall: WARNING — failed to back up legacy config.yml');
    end;
  end;

  if FileExists(AssistantEnv) then
  begin
    Log('PrepareToInstall: Backing up ' + AssistantEnv);
    try
      FileCopy(AssistantEnv, AssistantEnv + '.pre-upgrade.bak', False);
    except
      Log('PrepareToInstall: WARNING — failed to back up assistant.env');
    end;
  end;

  if FileExists(RulesFile) then
  begin
    Log('PrepareToInstall: Backing up ' + RulesFile);
    try
      FileCopy(RulesFile, RulesFile + '.pre-upgrade.bak', False);
    except
      Log('PrepareToInstall: WARNING — failed to back up rules.yml');
    end;
  end;

  { Pre-stop services so file replacement can proceed without locks }
  if FileExists(PrevUninstExe) then
  begin
    Log('PrepareToInstall: Stopping TinySocs services for upgrade...');
    try
      RunPowerShellScript(
        '$ErrorActionPreference = ''SilentlyContinue''' + CRLF +
        'foreach ($svc in @(''TinySocsAgent'',''TinySocsNode'',''TinySocsMaster'',''TinySocsAnchors'',''TinySocsAssistant'')) {' + CRLF +
        '  try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch { }' + CRLF +
        '}' + CRLF +
        '# Do NOT stop TinySocsOpenSearch here — persistence script handles restart.' + CRLF +
        'Write-Host ''[TinySocs][Inno] Pre-upgrade: services stopped.'''
      );
    except
      Log('PrepareToInstall: WARNING — service stop failed (non-fatal).');
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataRoot: String;
  FlagPath: String;
  ResultCode: Integer;
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

  { Remove daily summary scheduled task }
  try
    Exec('schtasks.exe', '/Delete /TN "TinySocs\DailySummary" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  except
    Log('CurUninstallStepChanged: failed to remove DailySummary task (may not exist).');
  end;

  if FileExists(FlagPath) then
  begin
    DelTree(DataRoot, True, True, True);
  end;
end;