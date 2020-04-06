;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

#ifndef NAME_TITLE
#define NAME_TITLE "Foo Bar"
#endif

#ifndef NAME_LOWER
#define NAME_LOWER "foo-bar"
#endif

#ifndef PUBLISHER
#define PUBLISHER "Assured Information Security, Inc."
#endif

#define PS "{sys}\WindowsPowerShell\v1.0\powershell.exe"
#define MAJOR "1"
#define MINOR "4"
#define YEAR GetDateTimeString('yyyy', '', '')

[Setup]
AppName={#NAME_TITLE}
AppVersion={#MAJOR}.{#MINOR}
AppPublisher={#PUBLISHER}
AppCopyright=Copyright (C) {#YEAR} {#PUBLISHER}
DefaultDirName={commonpf}\{#NAME_TITLE}
DefaultGroupName={#NAME_TITLE}
DirExistsWarning=no
Compression=lzma2
SolidCompression=yes
AlwaysRestart=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputDir=output
OutputBaseFilename=install-{#NAME_LOWER}
PrivilegesRequired=admin
#ifdef DEBUG
SetupLogging=yes
#endif
SetupIconFile=assets\{#NAME_LOWER}-logo.ico
UninstallDisplayIcon=assets\{#NAME_LOWER}-logo.ico
WizardSmallImageFile=assets\{#NAME_LOWER}-logo.bmp
WizardStyle=modern

[Icons]
Name: "{commondesktop}\{#NAME_TITLE}"; \
    IconFileName: "{app}\assets\{#NAME_LOWER}-logo.ico"; \
    Comment: "Run {#NAME_TITLE} in the background"; \
    Filename: "{#PS}"; \
    Parameters: "-File ""{app}\scripts\startvms.ps1"""

#ifdef DEBUG
Name: "{commondesktop}\{#NAME_TITLE} - With Console"; \
    IconFileName: "{app}\assets\{#NAME_LOWER}-logo.ico"; \
    Comment: "Run {#NAME_TITLE} with a developer console"; \
    Filename: "{#PS}"; \
    Parameters: "-File ""{app}\scripts\startvms.ps1"" -Console"
#endif

Name: "{commondesktop}\{#NAME_TITLE} - Submit Issue"; \
    IconFileName: "{app}\assets\{#NAME_LOWER}-logo.ico"; \
    Filename: "https://gitlab.ainfosec.com/{#NAME_LOWER}/programmatics/issues";

[Files]
Source: "assets\{#NAME_LOWER}-logo.ico"; DestDir: "{app}\assets"

#ifdef BOOT_SHELL
Source: "shell.efi"; DestDir: "P:\EFI\Boot\"
#endif
Source: "bareflank.efi"; DestDir: "P:\EFI\Boot\"
Source: "extras\uvctl.exe"; DestDir: "{app}\extras"
Source: "extras\netctl-wifi-setup.exe"; DestDir: "{app}\extras"
Source: "images\*"; DestDir: "{app}\storage\images"
Source: "util\certmgr.exe"; DestDir: "{app}\util"
Source: "util\devcon.exe"; DestDir: "{app}\util"
Source: "redist\x64\dpinst.exe"; DestDir: "{app}\util"
Source: "redist\x64\vs2019\vcredist_x64.exe"; DestDir: "{app}\util"
Source: "redist\wdf\WdfCoInstaller01011.dll"; DestDir: "{app}\drivers\builder"
Source: "redist\wdf\WdfCoInstaller01011.dll"; DestDir: "{app}\drivers\visr"

Source: "drivers\builder\builder.cer"; DestDir: "{app}\drivers\builder"
Source: "drivers\builder\builder.inf"; DestDir: "{app}\drivers\builder"
Source: "drivers\builder\builder.sys"; DestDir: "{app}\drivers\builder"
Source: "drivers\builder\builder.cat"; DestDir: "{app}\drivers\builder"

Source: "drivers\visr\visr.inf"; DestDir: "{app}\drivers\visr"
Source: "drivers\visr\visr.sys"; DestDir: "{app}\drivers\visr"
Source: "drivers\visr\visr.cat"; DestDir: "{app}\drivers\visr"

Source: "drivers\xenbus\xen.pdb"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xen.sys"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus.cat"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus.cer"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus.inf"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus.pdb"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus.sys"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus_coinst.dll"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus_coinst.pdb"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus_monitor.dll"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus_monitor.exe"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenbus_monitor.pdb"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenfilt.pdb"; DestDir: "{app}\drivers\xenbus"
Source: "drivers\xenbus\xenfilt.sys"; DestDir: "{app}\drivers\xenbus"

Source: "drivers\xenvif\xenvif.cat"; DestDir: "{app}\drivers\xenvif"
Source: "drivers\xenvif\xenvif.cer"; DestDir: "{app}\drivers\xenvif"
Source: "drivers\xenvif\xenvif.inf"; DestDir: "{app}\drivers\xenvif"
Source: "drivers\xenvif\xenvif.pdb"; DestDir: "{app}\drivers\xenvif"
Source: "drivers\xenvif\xenvif.sys"; DestDir: "{app}\drivers\xenvif"
Source: "drivers\xenvif\xenvif_coinst.dll"; DestDir: "{app}\drivers\xenvif"
Source: "drivers\xenvif\xenvif_coinst.pdb"; DestDir: "{app}\drivers\xenvif"

Source: "drivers\xennet\xennet.cat"; DestDir: "{app}\drivers\xennet"
Source: "drivers\xennet\xennet.cer"; DestDir: "{app}\drivers\xennet"
Source: "drivers\xennet\xennet.inf"; DestDir: "{app}\drivers\xennet"
Source: "drivers\xennet\xennet.pdb"; DestDir: "{app}\drivers\xennet"
Source: "drivers\xennet\xennet.sys"; DestDir: "{app}\drivers\xennet"
Source: "drivers\xennet\xennet_coinst.dll"; DestDir: "{app}\drivers\xennet"
Source: "drivers\xennet\xennet_coinst.pdb"; DestDir: "{app}\drivers\xennet"

Source: "scripts\setenv.ps1"; DestDir: "{app}\scripts"
Source: "scripts\startvms.ps1"; DestDir: "{app}\scripts"
Source: "scripts\pcictl.ps1"; DestDir: "{app}\scripts"
Source: "scripts\vifctl.ps1"; DestDir: "{app}\scripts"
Source: "scripts\vifconnect.ps1"; DestDir: "{app}\scripts"
Source: "scripts\powerctl.ps1"; DestDir: "{app}\scripts"
Source: "scripts\rmfilters.ps1"; DestDir: "{app}\scripts"
Source: "scripts\smbshare.ps1"; DestDir: "{app}\scripts"
#ifdef AUTO_START
Source: "scripts\taskctl.ps1"; DestDir: "{app}\scripts"
#endif

[Run]
; Allow our powershell scripts to run
Filename: "{#PS}"; Parameters: "-Command Set-ExecutionPolicy RemoteSigned"; Flags: runhidden

; Install hypervisor and point bootmgr to the VMM's binary
Filename: "{cmd}"; Parameters: "/C mountvol P: /D"; Flags: runhidden
#ifdef BOOT_SHELL
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\shell.efi"; Flags: runhidden
#else
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\bareflank.efi"; Flags: runhidden
#endif

; Enable testsigning
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning on"; Flags: runhidden

; Install vs2019 redistributables (needed for uvctl.exe)
Filename: "{app}\util\vcredist_x64.exe"; Parameters: "/install /quiet"; StatusMsg: "Installing VC++ libraries..."; Flags: runhidden

; Install builder (and visr - they use the same) driver cert
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\builder\builder.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\builder\builder.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden

; Install Xen PV driver certs
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenbus\xenbus.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenvif\xenvif.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xennet\xennet.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenbus\xenbus.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenvif\xenvif.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xennet\xennet.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden

; Install driver binaries
Filename: "{app}\util\devcon.exe"; Parameters: "/install ""{app}\drivers\builder\builder.inf"" ROOT\builder"; StatusMsg: "Installing driver binaries..."; Flags: runhidden
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\visr"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\xenbus"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\xenvif"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\xennet"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden

; Install netctl-wifi gui. Use the /S parameter to run the installer silently
Filename: "{app}\extras\netctl-wifi-setup.exe"; Parameters: "/S /D=""{app}\extras\netctl-wifi"""; StatusMsg: "Installing netctl wifi..."; Flags: runhidden

; Set environment variables
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\setenv.ps1"" -ProductName {#NAME_TITLE} -Init"; Flags: runhidden

; Disable suspend/resume
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\powerctl.ps1"" -Init"; Flags: runhidden

#ifdef AUTO_START
; Register uvctl task
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\taskctl.ps1"" -TaskPath ""{app}\scripts\startvms.ps1"" -TaskName StartVms -Register"; Flags: runhidden
#endif

; Disable PCI network devices
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\pcictl.ps1"" -Init"; Flags: runhidden

; Register vifconnect.ps1 as a handler for network connection events
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\vifctl.ps1"" -ProductName {#NAME_LOWER} -Register"; Flags: runhidden

; Create SMB share for persistent storage
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\smbshare.ps1"" -RootDir ""{app}"" -Add"; Flags: runhidden

[UninstallRun]
; Remove xenfilt from the UpperFilters registry value in the system and hdc classes
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\rmfilters.ps1"""; Flags: runhidden

; Remove builder and visr drivers. Note we dont remove the Xen PV drivers
; because Windows fails to boot with a "Boot critical file is corrupt" error
; pointing to xenbus.sys. We should fix this by determining what makes a file
; "boot critical" and convince Windows that xenbus.sys and friends are not in
; fact "boot critical".
;
; In the meantime, it should be harmless to not uninstall them since xenbus
; is only loaded if the VMM is running and presents the Xen Platform PCI device
; to Windows.
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /d /u ""{app}\drivers\visr\visr.inf"""; Flags: runhidden
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /d /u ""{app}\drivers\builder\builder.inf"""; Flags: runhidden
Filename: "{app}\util\devcon.exe"; Parameters: "/remove ROOT\builder"; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/del /c /n ""{#WDK_CERT_CN}"" /s /r localMachine trustedpublisher"; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/del /c /n ""{#WDK_CERT_CN}"" /s /r localMachine root"; Flags: runhidden

; Uninstall vs2019 redistributables
Filename: "{app}\util\vcredist_x64.exe"; Parameters: "/uninstall /quiet"; Flags: runhidden

; Uninstall netctl-wifi gui
Filename: "{app}\extras\netctl-wifi\Uninstall netctl-wifi.exe"; Parameters: "/S _?=""{app}\extras\netctl-wifi"""; Flags: runhidden

; Point bootmgr to the standard Windows loader
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\bootx64.efi"; Flags: runhidden

; Disable testsigning
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning off"; Flags: runhidden

; Delete the VMM binary
Filename: "{cmd}"; Parameters: "/C mountvol P: /S"; Flags: runhidden
#ifdef BOOT_SHELL
Filename: "{cmd}"; Parameters: "/C del P:\EFI\Boot\shell.efi"; Flags: runhidden
#endif
Filename: "{cmd}"; Parameters: "/C del P:\EFI\Boot\bareflank.efi"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C mountvol P: /D"; Flags: runhidden

; Remove SMB share
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\smbshare.ps1"" -Remove"; Flags: runhidden

; Unregister vifconnect.ps1 as a handler for network connection events
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\vifctl.ps1"" -ProductName {#NAME_LOWER} -Unregister"; Flags: runhidden

#ifdef AUTO_START
; Unregister the uvctl task
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\taskctl.ps1"" -TaskName StartVms -Unregister"; Flags: runhidden
#endif

; Restore suspend/resume settings
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\powerctl.ps1"" -Fini"; Flags: runhidden

; Enable PCI network devices
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\pcictl.ps1"" -Fini"; Flags: runhidden

; Clear environment variables
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\setenv.ps1"" -Fini"; Flags: runhidden

; Restrict powershell execution
Filename: "{#PS}"; Parameters: "-Command Set-ExecutionPolicy Restricted"; Flags: runhidden

[Code]
function InitializeSetup(): Boolean;
var
    ResultCode: integer;
begin
    Exec('cmd.exe', '/C mountvol P: /S', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Result := True;
end;

function UninstallNeedRestart(): Boolean;
begin
  Result := True;
end;
