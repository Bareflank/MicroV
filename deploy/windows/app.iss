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

#define NAME_UC "Beam"
#define NAME_LC "beam"
#define PUBLISHER "Assured Information Security, Inc."
#define MAJOR "0"
#define MINOR "9"
#define PATCH "0"
#define PS "{sys}\WindowsPowerShell\v1.0\powershell.exe"
#define POWER_BUTTONS_GUID

[Setup]
AppName={#NAME_UC}
AppVersion={#MAJOR}.{#MINOR}.{#PATCH}
AppPublisher={#PUBLISHER}
AppCopyright=Copyright (C) 2019 {#PUBLISHER}
DefaultDirName={commonpf}\{#NAME_UC}
DefaultGroupName={#NAME_UC}
DirExistsWarning=no
Compression=lzma2
SolidCompression=yes
AlwaysRestart=yes
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=install-{#NAME_LC}
PrivilegesRequired=admin
SetupLogging=yes
SetupIconFile=assets\beam-logo.ico
UninstallDisplayIcon=assets\beam-logo.ico
;WizardImageFile=assets\Francois.bmp
WizardSmallImageFile=assets\beam-logo.bmp
WizardStyle=modern

[Files]
Source: "bareflank.efi"; DestDir: "P:\EFI\Boot\"
Source: "uvctl.exe"; DestDir: "{app}"
Source: "xsvm-vmlinux"; DestDir: "{app}"
Source: "xsvm-rootfs.cpio.gz"; DestDir: "{app}"
Source: "util\certmgr.exe"; DestDir: "{app}\util"
Source: "util\devcon.exe"; DestDir: "{app}\util"
Source: "redist\x64\dpinst.exe"; DestDir: "{app}\util"
Source: "redist\x64\vs2019\vcredist_x64.exe"; DestDir: "{app}\util"
Source: "redist\wdf\WdfCoInstaller01011.dll"; DestDir: "{app}\drivers\builder"
Source: "redist\wdf\WdfCoInstaller01011.dll"; DestDir: "{app}\drivers\visr"
Source: "drivers\builder.cer"; DestDir: "{app}\drivers\builder"
Source: "drivers\builder.inf"; DestDir: "{app}\drivers\builder"
Source: "drivers\builder.sys"; DestDir: "{app}\drivers\builder"
Source: "drivers\builder.cat"; DestDir: "{app}\drivers\builder"
Source: "drivers\visr.inf"; DestDir: "{app}\drivers\visr"
Source: "drivers\visr.sys"; DestDir: "{app}\drivers\visr"
Source: "drivers\visr.cat"; DestDir: "{app}\drivers\visr"
Source: "scripts\start-vms.ps1"; DestDir: "{app}\scripts"
Source: "scripts\taskctl.ps1"; DestDir: "{app}\scripts"
Source: "scripts\powerctl.ps1"; DestDir: "{app}\scripts"

[Run]
Filename: "{#PS}"; Parameters: "-Command Set-ExecutionPolicy RemoteSigned"; Flags: runhidden
Filename: "{#PS}"; Parameters: "-Command New-Item -Path ""{app}"" -Name logs -ItemType ""directory"""; Flags: runhidden
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\powerctl.ps1"" -Init"; Flags: runhidden
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\taskctl.ps1"" -TaskPath ""{app}\scripts\start-vms.ps1"" -TaskName StartVms -Register"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C mountvol P: /D"; Flags: runhidden
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning on"; Flags: runhidden
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\bareflank.efi"; Flags: runhidden
Filename: "{app}\util\vcredist_x64.exe"; Parameters: "/install /quiet"; StatusMsg: "Installing VC++ libraries..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\builder\builder.cer"" /s /r localMachine root"; StatusMsg: "Installing WDK test certificate..."; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/add ""{app}\drivers\builder\builder.cer"" /s /r localMachine trustedpublisher"; StatusMsg: "Installing WDK test certificate..."; Flags: runhidden
Filename: "{app}\util\devcon.exe"; Parameters: "/install ""{app}\drivers\builder\builder.inf"" ROOT\builder"; StatusMsg: "Installing builder driver..."; Flags: runhidden
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /path ""{app}\drivers\visr"""; StatusMsg: "Installing visr driver..."; Flags: runhidden

[UninstallRun]
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /d /u ""{app}\drivers\visr\visr.inf"""; Flags: runhidden
Filename: "{app}\util\dpinst.exe"; Parameters: "/s /d /u ""{app}\drivers\builder\builder.inf"""; Flags: runhidden
Filename: "{app}\util\devcon.exe"; Parameters: "/remove ROOT\builder"; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/del /c /n ""WDKTestCert dev"" /s /r localMachine trustedpublisher"; Flags: runhidden
Filename: "{app}\util\certmgr.exe"; Parameters: "/del /c /n ""WDKTestCert dev"" /s /r localMachine root"; Flags: runhidden
Filename: "{app}\util\vcredist_x64.exe"; Parameters: "/uninstall /quiet"; Flags: runhidden
Filename: "{sys}\bcdedit.exe"; Parameters: "/set {{bootmgr} path \EFI\Boot\bootx64.efi"; Flags: runhidden
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning off"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C mountvol P: /S"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C del P:\EFI\Boot\bareflank.efi"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C mountvol P: /D"; Flags: runhidden
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\taskctl.ps1"" -TaskName StartVms -Unregister"; Flags: runhidden
Filename: "{#PS}"; Parameters: "-File ""{app}\scripts\powerctl.ps1"" -Fini"; Flags: runhidden
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
