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

$desc = "Xen PV Network Device #0"

$net = Get-NetAdapter -InterfaceDescription $desc `
                      -ErrorAction SilentlyContinue

while ($net -eq $null) {
    Start-Sleep -Seconds 1
    Write-Host "Waiting for $desc"
    $net = Get-NetAdapter -InterfaceDescription $desc `
                          -ErrorAction SilentlyContinue
}

Set-NetConnectionProfile -InterfaceIndex $net.InterfaceIndex `
                         -NetworkCategory Public | Out-Null

# Check if we've set IP info previously; if not, do so now
$addr = Get-NetIPAddress -InterfaceIndex $net.InterfaceIndex
if ($addr -eq $null) {
    New-NetIPAddress -IPAddress 192.168.5.2 `
                     -DefaultGateway 192.168.5.1 `
                     -PrefixLength 24 `
                     -InterfaceIndex $net.InterfaceIndex | Out-Null
}

Set-DnsClientServerAddress -InterfaceIndex $net.InterfaceIndex `
                           -ServerAddresses 8.8.8.8 | Out-Null

Write-Host "${desc}: NetworkCategory : Public"
Write-Host "${desc}: IPv4            : 192.168.5.2"
Write-Host "${desc}: Gateway         : 192.168.5.1"
Write-Host "${desc}: DNS             : 8.8.8.8"
