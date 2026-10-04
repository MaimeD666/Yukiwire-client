; Per-user installer. Public files come only from the verified portable manifest.
#ifndef PayloadInclude
  #error PayloadInclude is required
#endif

[Setup]
#ifdef InstallerTest
AppId=Yukiwire.Desktop.InstallerTest
AppName=Yukiwire installer test
#else
AppId=Yukiwire.Desktop
AppName=Yukiwire
#endif
AppVersion={#AppVersion}
AppPublisher=Yukiwire
VersionInfoVersion={#VersionInfoVersion}
DefaultDirName={localappdata}\Programs\Yukiwire
DefaultGroupName=Yukiwire
PrivilegesRequired=lowest
; Wintun includes an AMD64 driver: emulation on ARM64 is insufficient.
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0
WizardStyle=modern
DisableProgramGroupPage=yes
AllowNoIcons=yes
UsePreviousAppDir=yes
UsePreviousTasks=yes
AppMutex=Local\Yukiwire.NativeShell
SetupMutex=Local\Yukiwire.Setup
CloseApplications=no
RestartApplications=no
UninstallDisplayIcon={app}\Yukiwire.exe
SetupIconFile={#AppIcon}
OutputDir={#OutputDir}
OutputBaseFilename={#OutputName}
Compression=lzma2/max
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.NetMissing=Yukiwire needs Microsoft .NET Framework 4.8. Install it from https://dotnet.microsoft.com/download/dotnet-framework/net48 and run Setup again.
russian.NetMissing=Для Yukiwire нужен Microsoft .NET Framework 4.8. Установите его с https://dotnet.microsoft.com/download/dotnet-framework/net48 и повторите установку.
english.PendingRecovery=Network recovery is unfinished. Open Yukiwire, disconnect and use the network recovery action in Settings, then close the application and try again. Your network settings and profiles have been preserved.
russian.PendingRecovery=Восстановление сети не завершено. Откройте Yukiwire, отключитесь и выполните восстановление сети в настройках. Затем закройте приложение и повторите попытку. Настройки сети и профили сохранены.
english.CloseApp=Close Yukiwire using Exit in the tray before continuing. This will disconnect its active connection.
russian.CloseApp=Перед продолжением закройте Yukiwire через «Выход» в трее. Активное подключение будет отключено.
english.WebViewInstalling=Installing Microsoft Edge WebView2 Runtime. Internet access is required...
russian.WebViewInstalling=Установка Microsoft Edge WebView2 Runtime. Требуется доступ к Интернету...
english.WebViewFailed=Could not install Microsoft Edge WebView2 Runtime. Check your connection or install the Runtime from https://developer.microsoft.com/microsoft-edge/webview2/ and try again.
russian.WebViewFailed=Не удалось установить Microsoft Edge WebView2 Runtime. Проверьте Интернет или установите Runtime с https://developer.microsoft.com/microsoft-edge/webview2/ и повторите попытку.
english.LaunchApp=Launch Yukiwire
russian.LaunchApp=Запустить Yukiwire

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
#include PayloadInclude
Source: "{#Bootstrapper}"; DestDir: "{tmp}"; Flags: dontcopy

[Icons]
Name: "{group}\Yukiwire"; Filename: "{app}\Yukiwire.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Yukiwire"; Filename: "{app}\Yukiwire.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\Yukiwire.exe"; WorkingDir: "{app}"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[Code]
function HasWebView2: Boolean;
var
  Version: String;
  Key: String;
begin
  Key := 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  Result := RegQueryStringValue(HKLM32, Key, 'pv', Version) and
    (Version <> '') and (Version <> '0.0.0.0');
  if not Result then
    Result := RegQueryStringValue(HKCU, Key, 'pv', Version) and
      (Version <> '') and (Version <> '0.0.0.0');
end;

function InitializeSetup: Boolean;
var
  Release: Cardinal;
begin
  Result := RegQueryDWordValue(HKLM32, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) and
    (Release >= 528040);
  if not Result then
    SuppressibleMsgBox(CustomMessage('NetMissing'), mbCriticalError, MB_OK, IDOK);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ExitCode: Integer;
begin
  Result := '';
  if CheckForMutexes('Local\Yukiwire.NativeShell') then begin
    Result := CustomMessage('CloseApp');
    Exit;
  end;
  if FileExists(ExpandConstant('{app}\state\network-lease.dpapi')) then begin
    Result := CustomMessage('PendingRecovery');
    Exit;
  end;
  if not HasWebView2 then begin
    WizardForm.StatusLabel.Caption := CustomMessage('WebViewInstalling');
    ExtractTemporaryFile('MicrosoftEdgeWebview2Setup.exe');
    if not Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install', '',
        SW_HIDE, ewWaitUntilTerminated, ExitCode) then begin
      Result := CustomMessage('WebViewFailed');
      Exit;
    end;
    if (ExitCode <> 0) or not HasWebView2 then
      Result := CustomMessage('WebViewFailed');
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := not FileExists(ExpandConstant('{app}\state\network-lease.dpapi'));
  if not Result and not UninstallSilent then
    MsgBox(CustomMessage('PendingRecovery'), mbCriticalError, MB_OK);
end;

// No recursive UninstallDelete: profiles, settings, browser data and journals are not payload files.
