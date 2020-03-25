
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

Param(
    [switch]$Init,
    [switch]$Fini
)

$net_devs = $(Get-PnpDevice -class net).instanceid | Select-String "^PCI"

if ($Init) {
    $net_info = Get-NetAdapterHardwareInfo

    # Disable each network device. This is used as a workaround for a quirk
    # that prevents integrated wifi devices from working properly in the NDVM
    # the first time it tries to enumerate the device.

    foreach ($id in $($net_devs -split "`r`n")) {
        Disable-PnpDevice -InstanceId $id -Confirm:$false
    }

    # Now get the PCI BDFs of each network device and add them to the
    # environment variable used by uvctl for passthrough. This value will
    # be passed directly to xen-pciback.hide of the xsvm.

    $pciback_hide = $null

    foreach ($info in $net_info) {
        $bus = $info.Bus
        $dev = $info.Device
        $fun = $info.Function

        $pciback_hide += "({0:x2}:{1:x2}.{2:x1})" -f $bus, $dev, $fun
    }

    [System.Environment]::SetEnvironmentVariable(
        'UVCTL_PCIBACK_HIDE',
        $pciback_hide,
        [System.EnvironmentVariableTarget]::Machine
    )
}

if ($Fini) {
    [System.Environment]::SetEnvironmentVariable(
        'UVCTL_PCIBACK_HIDE',
        $null,
        [System.EnvironmentVariableTarget]::Machine
    )

    foreach ($id in $($net_devs -split "`r`n")) {
        Enable-PnpDevice -InstanceId $id -Confirm:$false
    }
}
