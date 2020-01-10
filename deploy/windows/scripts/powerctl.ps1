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
    [switch]$Init,
    [switch]$Fini
)

$flyout_prefix = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
$flyout_path = "$flyout_prefix\FlyoutMenuSettings"
$power_path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power\'

if ($Init) {
    Set-ItemProperty -Path $power_path -Name HiberbootEnabled -Value 0

    $flyout_key = Get-Item -Path $flyout_path
    if ($flyout_key -eq $null) {
        New-Item -Path $flyout_prefix -Name FlyoutMenuSettings
    }

    Set-ItemProperty -Path $flyout_path -Name ShowSleepOption -Value 0

    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0
    powercfg /hibernate off

    # Active power scheme GUID
    $scheme = (powercfg /getactivescheme).split()[3]

    # Power button GUIDs
    $sub_button = "4f971e89-eebd-4455-a8de-9e59040e7347"
    $lid_action = "5ca83367-6e45-459f-a27b-476b1d01c936"
    $pbutton_action = "7648efa3-dd9c-4e3e-b566-50f929386280"
    $sbutton_action = "96996bc0-ad50-47ec-923b-6f41874dd9eb"
    $uibutton_action = "a7066653-8d6c-40a8-910e-a1f54b84c7e5"

    # Do nothing on lid close
    powercfg /setacvalueindex $scheme $sub_button $lid_action 0
    powercfg /setdcvalueindex $scheme $sub_button $lid_action 0

    # Shutdown on power button
    powercfg /setacvalueindex $scheme $sub_button $pbutton_action 3
    powercfg /setdcvalueindex $scheme $sub_button $pbutton_action 3

    # Shutdown on sleep button
    powercfg /setacvalueindex $scheme $sub_button $sbutton_action 3
    powercfg /setdcvalueindex $scheme $sub_button $sbutton_action 3

    # Shutdown on Start Menu power button
    powercfg /setacvalueindex $scheme $sub_button $uibutton_action 2
    powercfg /setdcvalueindex $scheme $sub_button $uibutton_action 2
}

if ($Fini) {
    # Active power scheme GUID
    $scheme = (powercfg /getactivescheme).split()[3]

    # Power button GUIDs
    $sub_button = "4f971e89-eebd-4455-a8de-9e59040e7347"
    $lid_action = "5ca83367-6e45-459f-a27b-476b1d01c936"
    $pbutton_action = "7648efa3-dd9c-4e3e-b566-50f929386280"
    $sbutton_action = "96996bc0-ad50-47ec-923b-6f41874dd9eb"
    $uibutton_action = "a7066653-8d6c-40a8-910e-a1f54b84c7e5"

    # Sleep on Start Menu power button
    powercfg /setacvalueindex $scheme $sub_button $uibutton_action 0
    powercfg /setdcvalueindex $scheme $sub_button $uibutton_action 0

    # Sleep on sleep button
    powercfg /setacvalueindex $scheme $sub_button $sbutton_action 1
    powercfg /setdcvalueindex $scheme $sub_button $sbutton_action 1

    # Sleep on power button
    powercfg /setacvalueindex $scheme $sub_button $pbutton_action 1
    powercfg /setdcvalueindex $scheme $sub_button $pbutton_action 1

    # Sleep on lid close
    powercfg /setacvalueindex $scheme $sub_button $lid_action 1
    powercfg /setdcvalueindex $scheme $sub_button $lid_action 1

    powercfg /hibernate on
    powercfg /change standby-timeout-dc 15
    powercfg /change standby-timeout-ac 30

    Set-ItemProperty -Path $flyout_path -Name ShowSleepOption -Value 1
    Set-ItemProperty -Path $power_path -Name HiberbootEnabled -Value 1
}
