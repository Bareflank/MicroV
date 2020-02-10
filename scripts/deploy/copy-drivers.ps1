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

function make-dir (
    [parameter(mandatory)] [string] $path
) {
    if (!(Test-Path $path)) {
        mkdir -p $path
    }
}

function diff-files (
    [parameter(mandatory)] [string] $left,
    [parameter(mandatory)] [string] $right
) {
    if (!(Test-Path $left)) {
        Throw "non-existent path: $left"
    }

    if (!(Test-Path $right)) {
        Throw "non-existent path: $right"
    }

    $files = @{
        ReferenceObject = (Get-Content -Path $left)
        DifferenceObject = (Get-Content -Path $right)
    }

    return Compare-Object @files
}

function copy-winpv-cert (
    [parameter(mandatory)] [string] $drv_name,
    [parameter(mandatory)] [string] $drv_path,
    [parameter(mandatory)] [string] $dst_dir
) {
    $cert = $null
    $dbg_cert = "$drv_path\vs2019\Windows10Debug\x64\$drv_name.cer"
    $rel_cert = "$drv_path\vs2019\Windows10Release\x64\$drv_name.cer"

    if (!(Test-Path $dst_dir)) {
        mkdir -p $dst_dir
    }

    if ((Test-Path $dbg_cert) -and (Test-Path $rel_cert)) {
        if (diff-files $dbg_cert $rel_cert) {
            Throw "$drv_name certs differ: debug: $dbg_cert release: $rel_cert"
        }

        $cert = $rel_cert
    } elseif (Test-Path $dbg_cert) {
        $cert = $dbg_cert
    } elseif (Test-Path $rel_cert) {
        $cert = $rel_cert
    } else {
        Throw "winpv certs not found: debug: $dbg_cert release: $rel_cert"
    }

    Write-Host "Using $drv_name cert: $cert"
    cp $cert $dst_dir
}

$xenbus = "$PSScriptRoot\..\..\drivers\winpv\xenbus"
$xenvif = "$PSScriptRoot\..\..\drivers\winpv\xenvif"
$xennet = "$PSScriptRoot\..\..\drivers\winpv\xennet"
$xeniface = "$PSScriptRoot\..\..\drivers\winpv\xeniface"
$visr = "$PSScriptRoot\..\..\drivers\visr\windows\x64"
$builder = "$PSScriptRoot\..\..\drivers\builder\windows\x64"
$deploy = "$PSScriptRoot\..\..\deploy\windows\drivers"

make-dir -path $deploy\xenbus
make-dir -path $deploy\xenvif
make-dir -path $deploy\xennet
make-dir -path $deploy\xeniface
make-dir -path $deploy\visr
make-dir -path $deploy\builder

copy-winpv-cert xenbus $xenbus $deploy\xenbus\
copy-winpv-cert xenvif $xenvif $deploy\xenvif\
copy-winpv-cert xennet $xennet $deploy\xennet\
copy-winpv-cert xeniface $xeniface $deploy\xeniface\

# check that visr's cert is the same as builder's
$diff = diff-files $builder\Release\builder.cer $visr\Release\visr.cer
if ($diff) {
    Throw "builder cert != visr cert"
}

# since they're the same, just copy builder's
cp $builder\Release\builder.cer $deploy\builder\

# copy binaries
cp $xenbus\xenbus\x64\xen* $deploy\xenbus\
cp $xenvif\xenvif\x64\xen* $deploy\xenvif\
cp $xennet\xennet\x64\xen* $deploy\xennet\
cp $xeniface\xeniface\x64\xen* $deploy\xeniface\
cp $builder\Release\builder\builder.* $deploy\builder\
cp $visr\Release\visr\visr.* $deploy\visr\
