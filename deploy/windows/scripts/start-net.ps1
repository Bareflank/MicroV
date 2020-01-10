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
$log = "C:\Program Files\Beam\logs\net-log.txt"
$net = Get-NetAdapter -InterfaceDescription "${desc}" -ErrorAction Continue

while ($net -eq $null) {
    Start-Sleep -Seconds 1
    $net = Get-NetAdapter -InterfaceDescription "${desc}" -ErrorAction Continue
}

$index = $net.InterfaceIndex
$addr = Get-NetIPAddress -InterfaceIndex $index -ErrorAction Continue *>> $log

if ($addr -ne $null) {
    Remove-NetIPAddress -InterfaceIndex $index `
                        -Confirm:$false `
                        -ErrorAction Continue *>> $log
    Remove-NetRoute     -InterfaceIndex $index `
                        -Confirm:$false `
                        -ErrorAction Continue *>> $log
}

New-NetIPAddress -IPAddress 192.168.5.2 `
                 -DefaultGateway 192.168.5.1 `
                 -AddressFamily IPv4 `
                 -PrefixLength 24 `
                 -Type Unicast `
                 -InterfaceIndex $index `
                 -Confirm:$false `
                 -ErrorAction Continue *>> $log

Set-DnsClientServerAddress -InterfaceIndex $index `
                           -ServerAddresses ("8.8.8.8","8.8.4.4") `
                           -Confirm:$false `
                           -ErrorAction Continue *>> $log
