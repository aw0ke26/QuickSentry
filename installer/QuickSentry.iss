; QuickSentry installer (Inno Setup 6)
; Build with build_installer.bat, or:
;   ISCC.exe /DAppVersion=3.0.0 installer\QuickSentry.iss
; Expects dist\QuickSentry.exe to exist (build_exe.bat makes it).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "QuickSentry"
#define AppExe "QuickSentry.exe"
#define AppPublisher "aw0ke26"
#define AppURL "https://github.com/aw0ke26/QuickSentry"

[Setup]
; Never change AppId: it's how upgrades and uninstall find the existing install.
AppId={{6F0C9B2E-3B1E-4C55-9C3A-5E2A7D1B9F41}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
LicenseFile=..\LICENSE
SetupIconFile=..\assets\QuickSentry.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
OutputDir=..\dist
OutputBaseFilename=QuickSentry-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} installer

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start QuickSentry when I sign in (runs in the tray, no UAC prompt)"; GroupDescription: "Protection:"
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "autostart.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{#AppName} (demo - preview only)"; Filename: "{app}\{#AppExe}"; Parameters: "--demo"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Autostart = a scheduled task at sign-in with highest privileges (no UAC prompt each login,
; no 72-hour run limit). A normal Run-key entry can't start an admin app silently.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\autostart.ps1"" -Install -Exe ""{app}\{#AppExe}"" -User ""{username}"""; Flags: runhidden; Tasks: autostart; StatusMsg: "Setting up sign-in autostart..."
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\autostart.ps1"" -Remove"; Flags: runhidden; Tasks: not autostart; StatusMsg: "Removing old autostart..."
; runascurrentuser: postinstall items normally run as the un-elevated user, and QuickSentry.exe
; requires admin, which fails with "CreateProcess failed; code 740". The installer is already elevated.
Filename: "{app}\{#AppExe}"; Description: "Launch QuickSentry now"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "{app}\{#AppExe}"; Parameters: "--cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "GuardCleanup"
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\autostart.ps1"" -Remove"; Flags: runhidden; RunOnceId: "RemoveTask"

[Code]
// Optional removal of settings/logs. Deliberately NOT a recursive delete of the whole data
// folder: the quarantine subfolder can be a mount point for a USB drive, and deleting through
// it would erase that drive's files. --cleanup (above) unmounts those first; here we only remove
// known files and folders that never contain mount points.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  D: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    D := ExpandConstant('{commonappdata}\QuickSentry');
    if DirExists(D) and (SuppressibleMsgBox(
         'Also delete QuickSentry''s settings, remembered networks, logs and reports?' + #13#10 +
         '(' + D + ')', mbConfirmation, MB_YESNO, IDNO) = IDYES) then
    begin
      DeleteFile(D + '\settings.json');
      DeleteFile(D + '\known_networks.json');
      DelTree(D + '\logs', True, True, True);
      DelTree(D + '\reports', True, True, True);
      RemoveDir(D + '\quarantine');   // only removes it if empty
      RemoveDir(D);                   // only removes it if empty
    end;
  end;
end;
