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
    [string] $RootDir,
    [switch] $Add,
    [switch] $Remove
)

$share_name = "storage"
$share_path = "$RootDir\$share_name"

if ($Add) {
    $share = Get-SmbShare | Where-Object -Property Path -Eq $share_path
    if ($share -ne $null) {
        return
    }

    # Make sure that file sharing is enabled
    Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True

    if (!(Test-Path $share_path)) {
        mkdir -p $share_path
    }

    # TODO: use more restricted access with -NoAccess
    New-SmbShare -Name $share_name -Path $share_path -FullAccess "Users"

    $acl = Get-Acl $share_path
    $ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($ar)

    Set-Acl $share_path $acl
}

if ($Remove) {
    Remove-SmbShare -Name $share_name `
                    -Confirm:$false

    Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" `
                        -Enabled False `
                        -Confirm:$false
}
