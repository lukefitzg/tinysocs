[Setup]
AppName=TinySocs
AppVersion=0.7.0
AppPublisher=TinySocs
AppId={{F2DCCF8F-6F5F-4D8B-9EAF-6E2C2C6B1234}
DefaultDirName={commonpf}\TinySocs
DefaultGroupName=TinySocs
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
OutputDir={#SourcePath}
OutputBaseFilename=TinySocs-Setup
PrivilegesRequired=admin
WizardStyle=modern

[Files]
; Binaries (paths relative to this .iss → back out two levels)
Source: "..\..\dist\TinySocsNode.exe";      DestDir: "{app}\bin"; Flags: ignoreversion
Source: "..\..\dist\TinySocsMaster.exe";    DestDir: "{app}\bin"; Flags: ignoreversion
Source: "..\..\dist\TinySocsAnchors.exe";   DestDir: "{app}\bin"; Flags: ignoreversion

; NSSM is optional — include only if present at build time
#ifexist "..\..\thirdparty\nssm.exe"
Source: "..\..\thirdparty\nssm.exe";        DestDir: "{app}\bin"; Flags: ignoreversion
#endif

; Modules / helpers
Source: "..\..\modules\TinySocs.Installer.psm1";  DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\TinySocs.RotateQueue.ps1"; DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Master.ps1";        DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Anchors.ps1";       DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\OPERATOR-README.txt";      DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\PostInstall.ps1";          DestDir: "{app}\modules"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\TinySocs"
Name: "{commonappdata}\TinySocs\logs"
Name: "{commonappdata}\TinySocs\queue"
Name: "{commonappdata}\TinySocs\config"
Name: "{commonappdata}\TinySocs\rules"
Name: "{commonappdata}\TinySocs\anchors\state"
Name: "{commonappdata}\TinySocs\ledger"

[Run]
; Do the post-install work from a script (safer than inline one-liners)
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\modules\PostInstall.ps1"""; \
  Flags: runhidden; StatusMsg: "Configuring TinySocs..."

; Inbound firewall rule for Node port 8081 (idempotent) — NETSH avoids brace parsing
Filename: "cmd.exe"; \
  Parameters: "/c netsh advfirewall firewall show rule name=""TinySocsNode-8081"" >nul 2>&1 || netsh advfirewall firewall add rule name=""TinySocsNode-8081"" dir=in action=allow protocol=TCP localport=8081 profile=domain,private"; \
  Flags: runhidden

[UninstallRun]
; Gracefully tear down service, tasks, env, but keep data by default
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Import-Module '{app}\modules\TinySocs.Installer.psm1'; Uninstall-TinySocs -KeepData"""; \
  Flags: runhidden

[Icons]
Name: "{group}\Operator README"; Filename: "{app}\modules\OPERATOR-README.txt"; WorkingDir: "{app}\modules"

[Code]

const
  ROLE_NODE   = 0;
  ROLE_MASTER = 1;
  ROLE_TINYBOX = 2;

var
  RolePage: TWizardPage;
  ConfigPage: TWizardPage;
  SchedulePage: TWizardPage;

  RoleNodeRadio: TRadioButton;
  RoleMasterRadio: TRadioButton;
  RoleTinyBoxRadio: TRadioButton;

  SharedSecretEdit: TNewEdit;
  NodePortEdit: TNewEdit;
  NodesEdit: TNewEdit;
  SiemUrlEdit: TNewEdit;
  SiemUserEdit: TNewEdit;
  SiemPassEdit: TNewEdit;
  TinyBoxCheck: TNewCheckBox;

  HeartbeatEdit: TNewEdit;
  RetentionEdit: TNewEdit;

  SelectedRole: Integer;
  InstallTinyBox: Boolean;

  SharedSecret: String;
  NodePort: String;
  Nodes: String;
  SiemUrl: String;
  SiemUser: String;
  SiemPass: String;
  HeartbeatMinutes: Integer;
  AnchorsRetentionDays: Integer;

  function PsEscape(const S: String): String;
  begin
    Result := S;
    StringChangeEx(Result, '''', '''''', True);
  end;

  function RunPowerShellScript(const Script: String): Boolean;
  var
    ResultCode: Integer;
    TmpFile: String;
  begin
    { Build a pseudo-unique temp script path under tmp without using GetTempFileName }
    TmpFile := ExpandConstant('{tmp}') + '\TSI_' + IntToStr(Random($7FFFFFFF)) + '.ps1';

    if not SaveStringToFile(TmpFile, Script, False) then
    begin
      Result := False;
      Exit;
    end;

    Result := Exec(
      'powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + TmpFile + '"',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );

    DeleteFile(TmpFile);
  end;

procedure InitializeWizard;
var
  L: TNewStaticText;
begin
  { --- Role selection page --- }
  RolePage := CreateCustomPage(
    wpSelectDir,
    'TinySocs Role',
    ''
  );

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

  { --- Config page: secrets & endpoints --- }
  ConfigPage := CreateCustomPage(
    RolePage.ID,
    'Secrets and Endpoints',
    'Configure shared secret, node endpoints, and SIEM settings.'
  );

  { Shared secret (masked) }
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

  { Node port }
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

  { Nodes list (for Master / TinyBox) }
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

  { SIEM URL }
  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := NodesEdit.Top + 60;
  L.Caption := 'External SIEM URL (if not using TinyBox local SIEM):';

  SiemUrlEdit := TNewEdit.Create(ConfigPage.Surface);
  SiemUrlEdit.Parent := ConfigPage.Surface;
  SiemUrlEdit.Left := 0;
  SiemUrlEdit.Top := L.Top + 32;
  SiemUrlEdit.Width := ConfigPage.SurfaceWidth;
  SiemUrlEdit.Text := 'https://localhost:9201';

  { SIEM user }
  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := SiemUrlEdit.Top + 60;
  L.Caption := 'SIEM user (or TinyBox admin user):';

  SiemUserEdit := TNewEdit.Create(ConfigPage.Surface);
  SiemUserEdit.Parent := ConfigPage.Surface;
  SiemUserEdit.Left := 0;
  SiemUserEdit.Top := L.Top + 32;
  SiemUserEdit.Width := ConfigPage.SurfaceWidth;
  SiemUserEdit.Text := 'tinysocs';

  { SIEM pass }
  L := TNewStaticText.Create(ConfigPage.Surface);
  L.Parent := ConfigPage.Surface;
  L.Left := 0;
  L.Top := SiemUserEdit.Top + 60;
  L.Caption := 'SIEM password (or TinyBox admin password):';

  SiemPassEdit := TNewEdit.Create(ConfigPage.Surface);
  SiemPassEdit.Parent := ConfigPage.Surface;
  SiemPassEdit.Left := 0;
  SiemPassEdit.Top := L.Top + 32;
  SiemPassEdit.Width := ConfigPage.SurfaceWidth;
  SiemPassEdit.PasswordChar := '*';

  { TinyBox local SIEM checkbox }
  TinyBoxCheck := TNewCheckBox.Create(ConfigPage.Surface);
  TinyBoxCheck.Parent := ConfigPage.Surface;
  TinyBoxCheck.Left := 0;
  TinyBoxCheck.Top := SiemPassEdit.Top + 36;
  TinyBoxCheck.Width := ConfigPage.SurfaceWidth + 150;
  TinyBoxCheck.Height := ScaleY(24);
  TinyBoxCheck.Caption := 'Install &TinySocs local datastore (TinyBox SIEM) on this machine';
  TinyBoxCheck.Checked := False;

  { --- Schedules page --- }
  SchedulePage := CreateCustomPage(
    ConfigPage.ID,
    'Schedules and Retention',
    'Configure TinySocs heartbeat and anchor retention.'
  );

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

  { Defaults }
  SelectedRole := ROLE_NODE;
  InstallTinyBox := False;
  AnchorsRetentionDays := 45;
  HeartbeatMinutes := 15;
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
    InstallTinyBox := TinyBoxCheck.Checked;
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
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  InstallerModule: String;
  AppDir: String;
  MasterSiemUrl: String;
  Script: String;
begin
  if CurStep <> ssPostInstall then
    Exit;

  AppDir := ExpandConstant('{app}');
  InstallerModule := AppDir + '\modules\TinySocs.Installer.psm1';

  { Optional TinyBox local SIEM install }
  if InstallTinyBox then
  begin
    if (SiemUser = '') then
      SiemUser := 'tinysocs';

    if (SiemPass = '') then
      SiemPass := 'changeme!TinyBox1';

    Script :=
      'Import-Module ''' + InstallerModule + '''' + #13#10 +
      'Install-TinySocsLocalSiem -SiemUser ''' + PsEscape(SiemUser) +
      ''' -SiemPass ''' + PsEscape(SiemPass) + ''' -SiemSslVerify:$false' + #13#10;

    RunPowerShellScript(Script);
  end;

  { Node pairing (Node role or TinyBox) }
  if (SelectedRole = ROLE_NODE) or (SelectedRole = ROLE_TINYBOX) then
  begin
    if SiemUrl = '' then
      SiemUrl := 'https://localhost:9201';

    Script :=
      'Import-Module ''' + InstallerModule + '''' + #13#10 +
      'Pair-TinySocs -Role Node ' +
      '-SharedSecret ''' + PsEscape(SharedSecret) + ''' ' +
      '-NodePort ''' + PsEscape(NodePort) + ''' ' +
      '-SiemUrl ''' + PsEscape(SiemUrl) + ''' ' +
      '-SiemSslVerify:$false' + #13#10;

    RunPowerShellScript(Script);
  end;

  { Master pairing (Master role or TinyBox) }
  if (SelectedRole = ROLE_MASTER) or (SelectedRole = ROLE_TINYBOX) then
  begin
    if InstallTinyBox then
      MasterSiemUrl := 'https://localhost:9201'
    else if SiemUrl <> '' then
      MasterSiemUrl := SiemUrl
    else
      MasterSiemUrl := 'https://localhost:9201';

    Script :=
      'Import-Module ''' + InstallerModule + '''' + #13#10 +
      'Pair-TinySocs -Role Master ' +
      '-SharedSecret ''' + PsEscape(SharedSecret) + ''' ' +
      '-Nodes ''' + PsEscape(Nodes) + ''' ' +
      '-SiemUrl ''' + PsEscape(MasterSiemUrl) + ''' ' +
      '-SiemUser ''' + PsEscape(SiemUser) + ''' ' +
      '-SiemPass ''' + PsEscape(SiemPass) + ''' ' +
      '-SiemSslVerify:$false ' +
      '-AnchorsRetentionDays ' + IntToStr(AnchorsRetentionDays) + ' ' +
      '-HeartbeatMinutes ' + IntToStr(HeartbeatMinutes) + #13#10;

    RunPowerShellScript(Script);
  end;
end;