; packaging/iss/Quickstart.iss
[Setup]
AppName=TinySocs
AppVersion=0.6.0
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
Source: "..\..\modules\TinySocs.Installer.psm1"; DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\TinySocs.RotateQueue.ps1"; DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Master.ps1";       DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\Launch-Anchors.ps1";      DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\OPERATOR-README.txt";     DestDir: "{app}\modules"; Flags: ignoreversion
Source: "..\..\modules\PostInstall.ps1";         DestDir: "{app}\modules"; Flags: ignoreversion

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