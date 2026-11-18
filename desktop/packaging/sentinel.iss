#define ApplicationVersion "1.1.0"

[Setup]
AppId={{901A6C9F-4F29-41FA-8F9F-FD3D11E1C663}
AppName=PUSKESAU SENTINEL Device Inspector
AppVersion={#ApplicationVersion}
DefaultDirName={localappdata}\Programs\PuskesauSentinel
DefaultGroupName=PUSKESAU SENTINEL
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=PUSKESAU_SENTINEL_Advanced_Setup
SetupIconFile=..\src\sentinel_inspector\sentinel.ico
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\PUSKESAU_SENTINEL_Advanced_Portable.exe

[Files]
Source: "..\dist\PUSKESAU_SENTINEL_Advanced_Portable.exe"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Buat pintasan desktop"; Flags: unchecked

[Icons]
Name: "{group}\Device Inspector"; Filename: "{app}\PUSKESAU_SENTINEL_Advanced_Portable.exe"
Name: "{userdesktop}\PUSKESAU SENTINEL"; Filename: "{app}\PUSKESAU_SENTINEL_Advanced_Portable.exe"; Tasks: desktopicon
