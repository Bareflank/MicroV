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
    [string]$VifTag
)

$VIF_MGMT_MAC = "00-16-3E-00-13-40"
$VIF_MGMT_IPV6 = "fd12:edf1:e1d0:1337::5"
$VIF_MGMT_GATEWAY = "fd12:edf1:e1d0:1337::1"

$VIF_DIRTY_MAC = "00-16-3E-37-13-00"
$VIF_TUNNEL_MAC = "00-16-3E-37-13-01"

$VifTag = $VifTag.ToLower()

if ([string]::IsNullOrEmpty($VifTag)) {
    $vif_name_prefix = "vif"
    $vif_prof_suffix = "vif.net"
} else {
    $vif_name_prefix = $VifTag.Insert(0, "vif-")
    $vif_prof_suffix = "$VifTag.net"
}

Function Rename-VifProfile {
    Param(
        [string]$VifAlias,
        [string]$VifProfileName
    )

    $ncp = Get-NetConnectionProfile -InterfaceAlias $VifAlias
    if ($ncp -eq $null) {
        return
    }

    # Now we have the profile of this vif, we need to check its
    # ProfileName in the registry and rename it if it isn't
    # the same as $VifProfileName.

    $profiles = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\"

    foreach ($p in $profiles) {
        $pname = $p | Get-ItemPropertyValue -Name ProfileName
        if ($pname -ne $ncp.Name) {
            continue
        }

        if ($pname -eq $VifProfileName) {
            return
        }

        $p | Set-ItemProperty -Name ProfileName -Value $VifProfileName
        return
    }
}

Function Connect-VifMgmt {
    Param([string]$Name)

    if ($Name -ne "$vif_name_prefix-mgmt") {
        Rename-NetAdapter -Name $Name `
                          -NewName "$vif_name_prefix-mgmt" `
                          -Confirm:$false

        $Name = "$vif_name_prefix-mgmt"
    }

    Rename-VifProfile $Name "mgmt.$vif_prof_suffix"

    # Enable file sharing on the mgmt interface
    $binding = Get-NetAdapterBinding -Name $Name -ComponentID ms_server
    if ($binding.Disabled) {
        Enable-NetAdapterBinding -Name $Name `
                                 -ComponentID ms_server `
                                 -Confirm:$false
    }

    # Disable IPv4 on the mgmt interface
    $binding = Get-NetAdapterBinding -Name $Name -ComponentID ms_tcpip
    if ($binding.Enabled) {
        Disable-NetAdapterBinding -Name $Name `
                                  -ComponentID ms_tcpip `
                                  -Confirm:$false
    }

    $found = $false
    $addrs = Get-NetIPAddress -InterfaceAlias $Name -AddressFamily ipv6

    foreach ($addr in $addrs) {
        if ($addr.IPAddress -eq $VIF_MGMT_IPV6) {
            $found = $true
            break
        }
    }

    if (!$found) {
        New-NetIPAddress -InterfaceAlias $Name `
                         -AddressFamily ipv6 `
                         -IPAddress $VIF_MGMT_IPV6 `
                         -DefaultGateway $VIF_MGMT_GATEWAY `
                         -PrefixLength 64 `
                         -Confirm:$false
    }

    $ifaces = Get-NetIPInterface -InterfaceAlias $Name
    foreach ($iface in $ifaces) {
        if ($iface.Dhcp -eq "Enabled") {
            Set-NetIPInterface -InputObject $iface -Dhcp "Disabled"
        }
    }
}

Function Connect-VifDirty {
    Param([string]$Name)

    if ($Name -ne "$vif_name_prefix-dirty") {
        Rename-NetAdapter -Name $Name `
                          -NewName "$vif_name_prefix-dirty" `
                          -Confirm:$false
        $Name = "$vif_name_prefix-dirty"
    }

    Rename-VifProfile $Name "dirty.$vif_prof_suffix"
}

Function Connect-VifTunnel {
    Param([string]$Name)

    if ($Name -ne "$vif_name_prefix-tunnel") {
        Rename-NetAdapter -Name $Name `
                          -NewName "$vif_name_prefix-tunnel" `
                          -Confirm:$false

        $Name = "$vif_name_prefix-tunnel"
    }

    Rename-VifProfile $Name "tunnel.$vif_prof_suffix"

    # Disable file sharing on the tunnel interface
    $binding = Get-NetAdapterBinding -Name $Name -ComponentID ms_server
    if ($binding.Enabled) {
        Disable-NetAdapterBinding -Name $Name `
                                  -ComponentID ms_server `
                                  -Confirm:$false
    }
}

$adapters = Get-NetAdapter -Physical

foreach ($a in $adapters) {
    if ($a.MacAddress -eq $VIF_MGMT_MAC) {
        Connect-VifMgmt $a.Name

        # Start up the wifi menu if it isnt already running
# TODO: activate this once netctl-wifi is working better
#        $netctl_wifi = Get-ScheduledTask -TaskName NetctlWifi `
#                                         -ErrorAction SilentlyContinue
#        if ($netctl_wifi -ne $null) {
#            if ($netctl_wifi.State -ne "Running") {
#                Start-ScheduledTask -TaskName NetctlWifi
#            }
#        }
    } elseif ($a.MacAddress -eq $VIF_DIRTY_MAC) {
        Connect-VifDirty $a.Name
    } elseif ($a.MacAddress -eq $VIF_TUNNEL_MAC) {
        Connect-VifTunnel $a.Name
    }
}
