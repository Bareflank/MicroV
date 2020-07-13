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
    [parameter(mandatory)] [string]$ProductName,
    [switch]$Register,
    [switch]$Unregister
)

$task_file = "$PSScriptRoot\vifconnect.ps1"
$task_name = "VifConnect"

if ($Register) {
    $task = Get-ScheduledTask -TaskName $task_name -ErrorAction SilentlyContinue
    if ($task -ne $null) {
        Unregister-ScheduledTask -TaskName $task_name -Confirm:$false
    }

    $ps_args = "-NonInteractive -WindowStyle Hidden "
    $ps_args += "-File `"$task_file`" -VifTag $ProductName"

    $A = New-ScheduledTaskAction -Execute 'powershell.exe' `
                                 -Argument $ps_args

    $S = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                                      -DontStopIfGoingOnBatteries `
                                      -DontStopOnIdleEnd `
                                      -MultipleInstances Queue `
                                      -RestartCount 0

    $P = New-ScheduledTaskPrincipal -UserId SYSTEM `
                                    -LogonType ServiceAccount `
                                    -RunLevel Highest

    $I = New-ScheduledTask -Action $A -Settings $S -Principal $P

    Register-ScheduledTask -TaskName $task_name -InputObject $I

    # Now the task is registered, we need to modify the XML to add an
    # EventTrigger on Microsoft-Windows-NetworkProfile/Operational events. This
    # will cause the vifconnect.ps1 to be called, which can handle the event
    # as necessary.

    $xml_path = "$PSScriptRoot\tmp-vifconnect.xml"
    Export-ScheduledTask -TaskName $task_name | Out-File -FilePath $xml_path
    $val = Get-Content $xml_path | Select-String -Pattern '<Triggers />' -NotMatch
    Set-Content -Path $xml_path -Value $val -Encoding Unicode

    $xml = New-Object -TypeName XML
    $xml.Load($xml_path)

    # Add a subtree of nodes in one go. Note that the enclosing "@ below
    # must be at the beginning of the line.

    [xml]$child_xml = @"
    <Triggers>
      <EventTrigger>
        <Enabled>true</Enabled>
        <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      </EventTrigger>
    </Triggers>
"@

    $xml.Task.AppendChild($xml.ImportNode($child_xml.Triggers, $true))
    $xml.Save($xml_path)

    $val = (Get-Content $xml_path -Raw) -Replace 'Triggers xmlns=""','Triggers'
    Set-Content -Path $xml_path -Value $val -Encoding Unicode

    Unregister-ScheduledTask -TaskName $task_name -Confirm:$false
    Register-ScheduledTask -Xml $(Get-Content $xml_path -Raw) -TaskName $task_name

    # Now we register a task for netctl-ui. This is started by vifconnect.ps1
    # whenever the mgmt vif comes online (if netctl-ui isn't already running).

    $task = Get-ScheduledTask -TaskName NetctlUi -ErrorAction SilentlyContinue
    if ($task -ne $null) {
        Unregister-ScheduledTask -TaskName NetctlUi -Confirm:$false
    }

    $A = New-ScheduledTaskAction -Execute "$PSScriptRoot\..\extras\netctl-ui\netctl-ui.exe"
    $T = New-ScheduledTaskTrigger -AtLogOn
    $I = New-ScheduledTask -Action $A -Settings $S -Trigger $T

    Register-ScheduledTask -TaskName NetctlUi -InputObject $I
}

if ($Unregister) {
    Unregister-ScheduledTask -TaskName NetctlUi `
                             -Confirm:$false `
                             -ErrorAction SilentlyContinue

    Unregister-ScheduledTask -TaskName $task_name `
                             -Confirm:$false `
                             -ErrorAction SilentlyContinue
}
