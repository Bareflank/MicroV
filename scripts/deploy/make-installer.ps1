#
# Copyright (C) 2020 Assured Information Security, Inc.
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

param(
    [parameter(mandatory)] [string] $ProductName,
    [string] $IssPath,
    [switch] $AutoStart
)

function parse-wdk-cert-cn {
    # extract the CN from the WDK test cert used to sign builder and visr
    $deploy = "$PSScriptRoot\..\..\deploy\windows\drivers"
    $matchinfo = certutil -dump $deploy\builder\builder.cer | Select-String -CaseSensitive -Pattern "CN=.+,"

    if ($matchinfo) {
        $line = $matchinfo[0].Line

        # sanity check to ensure each match is the same (i.e. one CN per cert)
        for ($i = 1; $i -lt $matchinfo.Length; $i++) {
            if ($line -ne $matchinfo[$i].Line) {
                Throw
            }
        }

        $name = $line.Split(',')[0]
        $name = $name.Split('=')[1]

        Write-Host "Using WDK cert with CN = $name"
        Return $name
    } else {
        Throw "Unable to extract CN from builder cert"
    }
}

if ([string]::IsNullOrEmpty($IssPath)) {
    $IssPath = "$PSScriptRoot\..\..\deploy\windows\app.iss"
}

$name_lower = $ProductName.ToLower()
$name_title = (Get-Culture).TextInfo.ToTitleCase($ProductName)
$installer = "install-$name_lower"
$iscc = 'C:\Program Files (x86)\Inno Setup 6\iscc.exe'

if (!(Test-Path $iscc)) {
    throw "ERROR: Inno Setup compiler $iscc not found. Is Inno Setup installed?"
}

if (!(Test-Path $IssPath)) {
    throw "ERROR: Invalid path to iss file: $IssPath"
}

& $PSScriptRoot\copy-drivers.ps1 | Out-Null
$wdk_cert_cn = parse-wdk-cert-cn

$cmd = "& `'$iscc`' /F`"$installer`" "
$cmd += "`"/DNAME_LOWER=$name_lower`" "
$cmd += "`"/DNAME_TITLE=$name_title`" "
$cmd += "`"/DWDK_CERT_CN=$wdk_cert_cn`" "

if ($AutoStart) {
    $cmd += "`"/DAUTO_START`" "
}

$cmd += "`"$IssPath`""

iex $cmd
