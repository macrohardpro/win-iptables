; winiptables.iss — Inno Setup installer script for winiptables
; Packages winiptables.exe, winiptables-svc.exe, WinDivert runtime, and MSVC CRT.
; Requires Administrator privileges (WinDivert kernel driver).

#define AppName      "winiptables"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define AppPublisher "winiptables"
#define AppURL       "https://github.com/winiptables/winiptables"
#define DistDir      "..\dist\winiptables"

[Setup]
AppId={{A3F2C1D4-7B8E-4F9A-B2C3-D4E5F6A7B8C9}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
; Require admin — WinDivert needs kernel driver installation
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=winiptables-{#AppVersion}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; x64 only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Add install dir to system PATH
ChangesEnvironment=yes
; Uninstall info
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\winiptables.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add install directory to system &PATH"; GroupDescription: "Additional options:"

[Files]
; Main executables
Source: "{#DistDir}\winiptables.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\winiptables-svc.exe"; DestDir: "{app}"; Flags: ignoreversion

; WinDivert runtime (DLL + kernel driver)
Source: "{#DistDir}\WinDivert.dll";    DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\WinDivert64.sys";  DestDir: "{app}"; Flags: ignoreversion

; MSVC CRT
Source: "{#DistDir}\vcruntime140.dll";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\vcruntime140_1.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\msvcp140.dll";       DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\msvcp140_1.dll";     DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\msvcp140_2.dll";     DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\concrt140.dll";      DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\ucrtbase.dll";       DestDir: "{app}"; Flags: ignoreversion

; Documentation
Source: "{#DistDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName} README"; Filename: "{app}\README.txt"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Run]
; Install and start the Windows service after installation
Filename: "{app}\winiptables-svc.exe"; Parameters: "install"; \
    StatusMsg: "Installing winiptables service..."; \
    Flags: runhidden waituntilterminated
Filename: "{app}\winiptables.exe"; Parameters: "service start"; \
    StatusMsg: "Starting winiptables service..."; \
    Flags: runhidden waituntilterminated

[UninstallRun]
; Stop and uninstall the service before files are removed
Filename: "{app}\winiptables.exe";     Parameters: "service stop"; Flags: runhidden waituntilterminated; RunOnceId: "SvcStop"
Filename: "{app}\winiptables-svc.exe"; Parameters: "uninstall";    Flags: runhidden waituntilterminated; RunOnceId: "SvcUninstall"

[Registry]
; Add install dir to system PATH (only when task is selected)
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; \
    ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}')); \
    Tasks: addtopath

[Code]
// Check whether the given path is already in the system PATH.
function NeedsAddPath(InstallPath: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(InstallPath) + ';',
                ';' + Uppercase(OrigPath) + ';') = 0;
end;

// Remove install dir from system PATH on uninstall.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  OrigPath, InstallPath, NewPath: string;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then exit;

  InstallPath := ExpandConstant('{app}');
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then exit;

  NewPath := OrigPath;

  // Remove all occurrences (with or without trailing semicolon)
  P := Pos(';' + Uppercase(InstallPath), Uppercase(NewPath));
  while P > 0 do begin
    Delete(NewPath, P, Length(';' + InstallPath));
    P := Pos(';' + Uppercase(InstallPath), Uppercase(NewPath));
  end;

  if NewPath <> OrigPath then
    RegWriteStringValue(HKLM,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'Path', NewPath);
end;
