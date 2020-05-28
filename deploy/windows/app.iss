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
#define BUILD "1"
#define YEAR GetDateTimeString('yyyy', '', '')

[Setup]
AppName={#NAME_TITLE}
AppVersion={#MAJOR}.{#MINOR}.{#BUILD}
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
SetupLogging=yes
SetupIconFile=assets\{#NAME_LOWER}-logo.ico
UninstallDisplayIcon=assets\{#NAME_LOWER}-logo.ico
WizardSmallImageFile=assets\{#NAME_LOWER}-logo.bmp
WizardStyle=modern

[Types]
Name: standard; Description: "Standard Installation"
Name: custom; Description: "Custom Installation"; Flags: iscustom

[Components]
Name: images; Description: "VM Images"; Types: standard custom;

Name: drivers; Description: "Drivers"; Types: standard custom;
Name: drivers/xenbus; Description: "Xen PV Bus"; Types: standard custom;
Name: drivers/xenvif; Description: "Xen PV Vif"; Types: standard custom;
Name: drivers/xennet; Description: "Xen PV Net"; Types: standard custom;
Name: drivers/builder; Description: "Microv VM Builder"; Types: standard custom;
Name: drivers/visr; Description: "Microv Visr"; Types: standard custom;

Name: efi; Description: "EFI Binaries"; Types: standard custom;
Name: efi/vmm; Description: "Microv Hypervisor"; Types: standard custom;
Name: efi/shell; Description: "Tianocore EDK2 Shell"; Types: custom

Name: programs; Description: "Programs"; Types: standard custom;
Name: programs/uvctl; Description: "Microv Control"; Types: standard custom;
Name: programs/netctlwifi; Description: "Wifi Menu"; Types: standard custom;
Name: programs/compatibility; Description: "System Compatibility Checks"; Types: standard;
Name: programs/compatibility/module; Description: "System Compatibility Check Modules"; Types: standard;

Name: shortcuts; Description: "Desktop Shortcuts"; Types: standard custom;
Name: shortcuts/daemon; Description: "{#NAME_TITLE} - Run In Background"; Types: standard custom;
Name: shortcuts/console; Description: "{#NAME_TITLE} - Run With Console"; Types: custom;
Name: shortcuts/issue; Description: "{#NAME_TITLE} - Submit Issue"; Types: standard custom;

[Tasks]
Name: boot; Description: "EFI Boot Selection"; Components: efi/vmm and efi/shell
Name: boot/vmm; Description: "Boot Microv Hypervisor"; Flags: exclusive
Name: boot/shell; Description: "Boot EFI Shell"; Flags: exclusive unchecked

[Icons]
Name: "{commondesktop}\{#NAME_TITLE}"; \
    IconFileName: "{app}\assets\{#NAME_LOWER}-logo.ico"; \
    Comment: "Run {#NAME_TITLE} in the background"; \
    Filename: "{#PS}"; \
    Parameters: "-File ""{app}\scripts\startvms.ps1"""; \
    Components: shortcuts/daemon

Name: "{commondesktop}\{#NAME_TITLE} - With Console"; \
    IconFileName: "{app}\assets\{#NAME_LOWER}-logo.ico"; \
    Comment: "Run {#NAME_TITLE} with a developer console"; \
    Filename: "{#PS}"; \
    Parameters: "-File ""{app}\scripts\startvms.ps1"" -Console"; \
    Components: shortcuts/console

Name: "{commondesktop}\{#NAME_TITLE} - Submit Issue"; \
    IconFileName: "{app}\assets\{#NAME_LOWER}-logo.ico"; \
    Filename: "https://gitlab.ainfosec.com/{#NAME_LOWER}/programmatics/issues"; \
    Components: shortcuts/issue

[Files]
Source: "assets\{#NAME_LOWER}-logo.ico"; DestDir: "{app}\assets"
Source: "shell.efi"; DestDir: "P:\EFI\Boot\"; Flags: ignoreversion; Components: efi/shell
Source: "bareflank.efi"; DestDir: "P:\EFI\Boot\"; Flags: ignoreversion; Components: efi/vmm
Source: "extras\uvctl.exe"; DestDir: "{app}\extras"; Flags: ignoreversion; Components: programs/uvctl
Source: "extras\netctl-wifi-setup.exe"; DestDir: "{app}\extras"; Flags: ignoreversion; Components: programs/netctlwifi
Source: "images\*"; DestDir: "{app}\storage\images"; Flags: ignoreversion; Components: images
Source: "util\certmgr.exe"; DestDir: "{app}\util"
Source: "util\devcon.exe"; DestDir: "{app}\util"
Source: "redist\x64\dpinst.exe"; DestDir: "{app}\util"
Source: "redist\x64\vs2019\vcredist_x64.exe"; DestDir: "{app}\util"
Source: "redist\wdf\WdfCoInstaller01011.dll"; DestDir: "{app}\drivers\builder"; Components: drivers/builder
Source: "redist\wdf\WdfCoInstaller01011.dll"; DestDir: "{app}\drivers\visr"; Components: drivers/visr

Source: "compatibility/*"; DestDir: "{app}/compatibility"; Flags: ignoreversion; Components: programs/compatibility
Source: "compatibility/module/*"; DestDir: "{app}/compatibility/module"; Flags: ignoreversion; Components: programs/compatibility/module

Source: "drivers\builder\builder.cer"; DestDir: "{app}\drivers\builder"; Components: drivers/builder
Source: "drivers\builder\builder.inf"; DestDir: "{app}\drivers\builder"; Components: drivers/builder
Source: "drivers\builder\builder.sys"; DestDir: "{app}\drivers\builder"; Components: drivers/builder
Source: "drivers\builder\builder.cat"; DestDir: "{app}\drivers\builder"; Components: drivers/builder

Source: "drivers\visr\visr.inf"; DestDir: "{app}\drivers\visr"; Components: drivers/visr
Source: "drivers\visr\visr.sys"; DestDir: "{app}\drivers\visr"; Components: drivers/visr
Source: "drivers\visr\visr.cat"; DestDir: "{app}\drivers\visr"; Components: drivers/visr

Source: "drivers\xenbus\xen.pdb"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xen.sys"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus.cat"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus.cer"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus.inf"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus.pdb"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus.sys"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus_coinst.dll"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus_coinst.pdb"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus_monitor.dll"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus_monitor.exe"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenbus_monitor.pdb"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenfilt.pdb"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus
Source: "drivers\xenbus\xenfilt.sys"; DestDir: "{app}\drivers\xenbus"; Components: drivers/xenbus

Source: "drivers\xenvif\xenvif.cat"; DestDir: "{app}\drivers\xenvif"; Components: drivers/xenvif
Source: "drivers\xenvif\xenvif.cer"; DestDir: "{app}\drivers\xenvif"; Components: drivers/xenvif
Source: "drivers\xenvif\xenvif.inf"; DestDir: "{app}\drivers\xenvif"; Components: drivers/xenvif
Source: "drivers\xenvif\xenvif.pdb"; DestDir: "{app}\drivers\xenvif"; Components: drivers/xenvif
Source: "drivers\xenvif\xenvif.sys"; DestDir: "{app}\drivers\xenvif"; Components: drivers/xenvif
Source: "drivers\xenvif\xenvif_coinst.dll"; DestDir: "{app}\drivers\xenvif"; Components: drivers/xenvif
Source: "drivers\xenvif\xenvif_coinst.pdb"; DestDir: "{app}\drivers\xenvif"; Components: drivers/xenvif

Source: "drivers\xennet\xennet.cat"; DestDir: "{app}\drivers\xennet"; Components: drivers/xennet
Source: "drivers\xennet\xennet.cer"; DestDir: "{app}\drivers\xennet"; Components: drivers/xennet
Source: "drivers\xennet\xennet.inf"; DestDir: "{app}\drivers\xennet"; Components: drivers/xennet
Source: "drivers\xennet\xennet.pdb"; DestDir: "{app}\drivers\xennet"; Components: drivers/xennet
Source: "drivers\xennet\xennet.sys"; DestDir: "{app}\drivers\xennet"; Components: drivers/xennet
Source: "drivers\xennet\xennet_coinst.dll"; DestDir: "{app}\drivers\xennet"; Components: drivers/xennet
Source: "drivers\xennet\xennet_coinst.pdb"; DestDir: "{app}\drivers\xennet"; Components: drivers/xennet

Source: "scripts\setenv.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\startvms.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\pcictl.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\vifctl.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\vifconnect.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\powerctl.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\rmfilters.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "scripts\smbshare.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
#ifdef AUTO_START
Source: "scripts\taskctl.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
#endif

[Run]
; Allow our powershell scripts to run
Filename: "{#PS}"; Parameters: "-Command Set-ExecutionPolicy RemoteSigned"; Flags: runhidden

; Set environment variables.
; This needs to be run early (before any other ps1 scripts at the latest)
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\setenv.ps1"" -ProductName {#NAME_TITLE} -Init"; Flags: runhidden

; Install hypervisor and point bootmgr to the VMM's binary
Filename: "{cmd}"; Parameters: "/C mountvol P: /D"; Flags: runhidden
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\bareflank.efi"; Flags: runhidden; Components: efi/vmm
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\bareflank.efi"; Flags: runhidden; Tasks: boot/vmm
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\shell.efi"; Flags: runhidden; Tasks: boot/shell

; Enable testsigning
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning on"; Flags: runhidden

; Install vs2019 redistributables (needed for uvctl.exe)
Filename: "{app}\util\vcredist_x64.exe"; Parameters: "/install /quiet"; StatusMsg: "Installing VC++ libraries..."; Flags: runhidden; Components: programs

; Install builder (and visr - they use the same) driver cert
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\builder\builder.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/builder
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\builder\builder.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/builder

; Install Xen PV driver certs
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenbus\xenbus.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/xenbus
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenvif\xenvif.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/xenvif
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xennet\xennet.cer"" /s /r localMachine root"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/xennet
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenbus\xenbus.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/xenbus
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xenvif\xenvif.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/xenvif
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\xennet\xennet.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing driver certs..."; Flags: runhidden; Components: drivers/xennet

; Install driver binaries. Note that builder is a non-pnp driver, so
; dpinst cannot be used to install it (although it can uninstall it
; partially). Because of this, if the installer is run again after an
; install, builder will be installed again too, even if it is the same
; version. This manifests as more than one "Microv VM Builder" entry
; under Device Manager. To prevent any possible confusion from this,
; we uninstall builder before installing it (note if it doesn't exist
; the two uninstall commands below will return with an error but the
; install step will otherwise be unaffected).
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /d /u ""{app}\drivers\builder\builder.inf"""; Flags: runhidden; Components: drivers/builder
Filename: "{app}\util\devcon.exe"; Parameters: "/remove ROOT\builder"; Flags: runhidden; Components: drivers/builder
Filename: "{app}\util\devcon.exe"; Parameters: "/install ""{app}\drivers\builder\builder.inf"" ROOT\builder"; StatusMsg: "Installing driver binaries..."; Flags: runhidden; Components: drivers/builder
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\visr"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden; Components: drivers/visr
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\xenbus"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden; Components: drivers/xenbus
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\xenvif"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden; Components: drivers/xenvif
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\xennet"""; StatusMsg: "Installing driver binaries..."; Flags: runhidden; Components: drivers/xennet

; Install netctl-wifi gui. Use the /S parameter to run the installer silently
Filename: "{app}\extras\netctl-wifi-setup.exe"; Parameters: "/S /D=""{app}\extras\netctl-wifi"""; StatusMsg: "Installing netctl wifi..."; Flags: runhidden; Components: programs/netctlwifi

; Disable suspend/resume
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\powerctl.ps1"" -Init"; Flags: runhidden

#ifdef AUTO_START
; Register uvctl task
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\taskctl.ps1"" -TaskPath ""{app}\scripts\startvms.ps1"" -TaskName StartVms -Register"; Flags: runhidden
#endif

; Disable PCI network devices
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\pcictl.ps1"" -Init"; Flags: runhidden

; Register vifconnect.ps1 as a handler for network connection events.
; This needs to run after netctl-wifi-setup.exe.
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\vifctl.ps1"" -ProductName {#NAME_LOWER} -Register"; Flags: runhidden

; Create SMB share for persistent storage
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\smbshare.ps1"" -RootDir ""{app}"" -Add"; Flags: runhidden

; Run a dummy command that kicks off system compatibility checks during the "AfterInstall" stage
Filename: "change.exe"; WorkingDir: "{tmp}"; StatusMsg: "Running system compatibility checks";  Flags: runhidden; AfterInstall: RunCompatibilityChecks

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
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /d /u ""{app}\drivers\visr\visr.inf"""; Flags: runhidden; Components: drivers/visr
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /d /u ""{app}\drivers\builder\builder.inf"""; Flags: runhidden; Components: drivers/builder
Filename: "{app}\util\devcon.exe"; Parameters: "/remove ROOT\builder"; Flags: runhidden; Components: drivers/builder
Filename: "{app}\util\certmgr.exe"; Parameters: "/del /c /n ""{#WDK_CERT_CN}"" /s /r localMachine trustedpublisher"; Flags: runhidden; Components: drivers/builder or drivers/visr
Filename: "{app}\util\certmgr.exe"; Parameters: "/del /c /n ""{#WDK_CERT_CN}"" /s /r localMachine root"; Flags: runhidden; Components: drivers/builder or drivers/visr

; Uninstall vs2019 redistributables
Filename: "{app}\util\vcredist_x64.exe"; Parameters: "/uninstall /quiet"; Flags: runhidden; Components: programs

; Uninstall netctl-wifi gui
Filename: "{app}\extras\netctl-wifi\Uninstall netctl-wifi.exe"; Parameters: "/S _?=""{app}\extras\netctl-wifi"""; Flags: runhidden; Components: programs/netctlwifi

; Point bootmgr to the standard Windows loader
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\bootx64.efi"; Flags: runhidden

; Disable testsigning
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning off"; Flags: runhidden

; Delete the VMM binary
Filename: "{cmd}"; Parameters: "/C mountvol P: /S"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C del P:\EFI\Boot\shell.efi"; Flags: runhidden; Components: efi/shell
Filename: "{cmd}"; Parameters: "/C del P:\EFI\Boot\bareflank.efi"; Flags: runhidden; Components: efi/vmm
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

// Execute the compatibility checks for this installer. Upon failure of one or
// more compatibility checks, this procedure will display a failure messsage,
// and then fail + rollback the entire installation
procedure RunCompatibilityChecks();
var
    CmdArgs: string;        // Arguments to pass to cmd.exe
    ResultCode: integer;    // Result (exit code) from running the compatibility checks
    ErrorFile: string;      // Path to a file that will collect stderr output from all compatibility checks
    ErrorText: AnsiString;  // Text from stderr output after running all compatibility checks
    ErrMsgText: string;     // Text to be displayed to the user upon compatibility check failure
begin
    ErrorFile := ExpandConstant('{app}') + '\compatibility_results.txt';
    CmdArgs := ExpandConstant('/U /C {#PS} -File "{app}\compatibility\run_all.ps1"') + ' 2> "' + ErrorFile + '"'

    if Exec(ExpandConstant('{cmd}'), CmdArgs, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    then begin
        if not (ResultCode = 0)
        then begin
            ErrMsgText := ExpandConstant('This envirnoment is not compatible with {#NAME_TITLE} version {#MAJOR}.{#MINOR}.{#BUILD}. ');
            ErrMsgText := ErrMsgText + ExpandConstant('{#NAME_TITLE} will be uninstalled now.');
            if LoadStringFromFile(ErrorFile, ErrorText) then
                ErrMsgText := ErrMsgText + ' Errors:' + #13#10 + ErrorText;
            MsgBox(ErrMsgText, mbCriticalError, MB_OK);
            DeleteFile(ErrorFile)
            Exec(ExpandConstant('{uninstallexe}'), '/SILENT', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        end
    end
    else
        MsgBox('Failed to execute compatibility checks, error: ' + SysErrorMessage(ResultCode), mbCriticalError, MB_OK);
    end;
end.
