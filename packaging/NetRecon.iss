; ===========================================================================
;  NetRecon: Inno Setup 6 installer script
;
;  Build:
;    1. Run:  python -m PyInstaller --noconfirm packaging\NetRecon.spec
;    2. Run:  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\NetRecon.iss
;
;  Or one-shot:  packaging\build.ps1
;
;  Targets:  Windows 10 (1809+) and Windows 11, 64-bit only.
; ===========================================================================

#define MyAppName        "NetRecon Network Toolkit"
#define MyAppVersion     "2.0.4.0"
#define MyAppPublisher   "PradaFit"
#define MyAppURL         "https://github.com/PradaFit/NetRecon"
#define MyAppExeName     "NetRecon.exe"
#define MyCliExeName     "NetRecon-CLI.exe"
#define MyAppDescription "Network Reconnaissance Toolkit"

; Verification builds can override this with /DMyDistDir="<path>" without
; replacing or deleting the normal dist tree.
#ifndef MyDistDir
  #define MyDistDir "..\dist\NetRecon"
#endif

[Setup]
; A fresh GUID identifies this product to Windows. Do not change it on updates.
AppId={{C7E1C2A4-7E2A-4D6B-9B5F-3F1D1C5B2A11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
AppContact={#MyAppURL}
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} {#MyAppDescription}
VersionInfoProductName={#MyAppName}

; Install location (Program Files\NetRecon)
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}

; Windows 10 build 1809 (10.0.17763) is the floor; Win11 is also 10.0.x.
MinVersion=10.0.17763

; x64 only. The bootloader produced by PyInstaller is x64 in this build.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Need admin to write Program Files. Add a per-user fallback if desired.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; UX
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
DisableWelcomePage=no
DisableReadyPage=no
ShowLanguageDialog=auto

; Output
OutputDir=Output
OutputBaseFilename=NetRecon-Setup-{#MyAppVersion}
SetupIconFile=NetRecon.ico

; License + readme shown in installer (plain-text copies created by build.ps1)
LicenseFile=LICENSE.txt
InfoBeforeFile=DISCLAIMER.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";    Description: "{cm:CreateDesktopIcon}";    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Bundle the entire PyInstaller onedir output.
Source: "{#MyDistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}";                Filename: "{app}\{#MyAppExeName}"
Name: "{group}\NetRecon CLI";                 Filename: "{app}\{#MyCliExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";          Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up generated caches in the install dir (do NOT touch user data).
Type: filesandordirs; Name: "{app}\__pycache__"
