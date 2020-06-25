#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

Param(
    [string]$CredFile,
    [switch]$Console,
    [switch]$NdvmOnly
)

$product_name = [System.Environment]::GetEnvironmentVariable(
                    'UVCTL_PRODUCT_NAME',
                    [System.EnvironmentVariableTarget]::Machine
                )

$pciback_hide = [System.Environment]::GetEnvironmentVariable(
                    'UVCTL_PCIBACK_HIDE',
                    [System.EnvironmentVariableTarget]::Machine
                )

# Check if running as admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Type -AssemblyName PresentationFramework

    $message = "This application must be run as Administrator"
    $caption = "$product_name Runtime Error"
    $button = [System.Windows.MessageBoxButton]::OK
    $icon = "Error"

    [System.Windows.MessageBox]::Show($message, $caption, $button, $icon)
    return
}

# Check if started already
$uvctl_ps = Get-Process "uvctl" -ErrorAction SilentlyContinue
if ($uvctl_ps) {
    Add-Type -AssemblyName PresentationFramework

    $message = "$product_name is already running. Reboot before starting again."
    $caption = "$product_name Runtime Error"
    $button = [System.Windows.MessageBoxButton]::OK
    $icon = "Warning"

    [System.Windows.MessageBox]::Show($message, $caption, $button, $icon)
    return
}

cd $PSScriptRoot

$license = "$PSScriptRoot\..\storage\.license"
if (!(Test-Path $license)) {
    Set-Content $license "9999999999"
}

$caption = "$product_name User Authentication"
$message = "Please enter your username and password:"

$cred = $host.ui.PromptForCredential($caption, $message, "", "")
$user = $cred.UserName
$pass = $cred.GetNetworkCredential().Password

$uvctl_user = "UVCTL_USER=$user"
$uvctl_pass = "UVCTL_PASS=$pass"

$kernel_cmdline = ""

if (![string]::IsNullOrEmpty($pciback_hide) -and ($pciback_hide -ne "NONE")) {
    $kernel_cmdline += " xen-pciback.hide=$pciback_hide"
}

$kernel_cmdline += " xen-pciback.passthrough=1"
$kernel_cmdline += " systemd.setenv=$uvctl_user"
$kernel_cmdline += " systemd.setenv=$uvctl_pass"

if ($NdvmOnly) {
    $kernel_cmdline += " systemd.mask=rootvm-vif-tunnel systemd.mask=start-vpnvms"
} else {
    $kernel_cmdline += " systemd.mask=rootvm-vif-dirty"
}

$uvctl_args = " --verbose --hvc --xsvm --ram 450000000"
$uvctl_args += " --kernel .\..\storage\images\vmlinux"
$uvctl_args += " --initrd .\..\storage\images\xsvm-rootfs.cpio.gz"
$uvctl_args += " --cmdline `"$kernel_cmdline`""

$uvctl_path = ".\..\extras\uvctl.exe"

if ($Console) {
    Start-Process -Wait -NoNewWindow -FilePath $uvctl_path -ArgumentList $uvctl_args
} else {
    $timestamp = Get-Date -Format FileDateTime

    Start-Process -FilePath $uvctl_path `
                  -ArgumentList $uvctl_args `
                  -NoNewWindow `
                  -RedirectStandardOutput "C:\Windows\Temp\uvctl-out-$timestamp.txt" `
                  -RedirectStandardError "C:\Windows\Temp\uvctl-err-$timestamp.txt"
}
