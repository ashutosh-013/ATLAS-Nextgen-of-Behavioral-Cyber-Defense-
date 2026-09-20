; =====================================================================
; Inno Setup Script: ATLAS Behavioral Cyber-Defense Platform
; Free, Open-Source Windows Installer Compiler
; =====================================================================

#define MyAppName "ATLAS Behavioral Cyber Defense"
#define MyAppVersion "2.5.4"
#define MyAppPublisher "ATLAS Cyber Intelligence"
#define MyAppURL "https://github.com/ashutosh-013/ATLAS-Nextgen-of-Behavioral-Cyber-Defense-"
#define MyAppExeName "ATLAS.exe"

[Setup]
; Basic Application Identification
AppId={{D37B4C81-89F0-4725-A2D3-7461389A1A5F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation Paths
DefaultDirName={autopf}\ATLAS Cyber Defense
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Output Configuration
OutputDir=dist_installer
OutputBaseFilename=ATLAS_v2.5_Enterprise_Setup
SetupIconFile=frontend\atlas_logo.ico
UninstallDisplayIcon={app}\frontend\atlas_logo.ico

; Compression (Ultra-fast download, maximum compression)
Compression=lzma2/ultra64
SolidCompression=yes

; Elevated Privileges required for system netsh firewall and vssadmin integration
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Automatically launch ATLAS on Windows login"; GroupDescription: "Startup Options:"; Flags: unchecked

[Files]
; Dist directory produced by PyInstaller
Source: "dist\ATLAS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu Shortcut
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\frontend\atlas_logo.ico"
; Start Menu Uninstaller
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
; Desktop Shortcut
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\frontend\atlas_logo.ico"; Tasks: desktopicon
; Windows Startup Shortcut (optional)
Name: "{commonstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: autostart

[Run]
; Run application upon installation completion
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
