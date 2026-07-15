<#
.SYNOPSIS
Creates a basic SOC report from the local Windows Security log.

.NOTES
Run PowerShell as Administrator.
#>

[CmdletBinding()]
param(
    [ValidateRange(1,720)]
    [int]$Hours = 24,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "output")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord)

    [xml]$xml = $EventRecord.ToXml()
    $map = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $name = [string]$item.Name
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $map[$name] = [string]$item.'#text'
        }
    }

    $map
}

function Get-FirstValue {
    param(
        [hashtable]$Data,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Data.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($Data[$name])) {
            return $Data[$name]
        }
    }

    ""
}

if (-not (Test-IsAdministrator)) {
    Write-Error "Run PowerShell as Administrator, then run the script again."
}

$descriptions = @{
    4624 = "Successful Logon"
    4625 = "Failed Logon"
    4672 = "Special Privileges Assigned"
    4688 = "Process Created"
}

$startTime = (Get-Date).AddHours(-$Hours)
$eventIds = @(4624,4625,4672,4688)

New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = $eventIds
        StartTime = $startTime
    })
}
catch {
    Write-Error "Unable to read the Security log. Run PowerShell as Administrator. $($_.Exception.Message)"
}

$report = foreach ($event in $events) {
    $data = Get-EventDataMap -EventRecord $event

    [pscustomobject]@{
        TimeCreated = $event.TimeCreated
        EventId = $event.Id
        EventDescription = $descriptions[$event.Id]
        Computer = $event.MachineName
        Account = Get-FirstValue -Data $data -Names @("TargetUserName","SubjectUserName","AccountName")
        LogonType = Get-FirstValue -Data $data -Names @("LogonType")
        SourceAddress = Get-FirstValue -Data $data -Names @("IpAddress","SourceNetworkAddress","WorkstationName")
        FailureReason = Get-FirstValue -Data $data -Names @("FailureReason","Status","SubStatus")
        ProcessName = Get-FirstValue -Data $data -Names @("NewProcessName")
        ParentProcessName = Get-FirstValue -Data $data -Names @("ParentProcessName","CreatorProcessName")
        CommandLine = Get-FirstValue -Data $data -Names @("CommandLine","ProcessCommandLine")
    }
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$detailedPath = Join-Path $OutputDirectory "security-events-$stamp.csv"
$summaryPath = Join-Path $OutputDirectory "event-summary-$stamp.csv"

$report |
    Sort-Object TimeCreated -Descending |
    Export-Csv $detailedPath -NoTypeInformation -Encoding UTF8

$summary = $report |
    Group-Object EventId, EventDescription |
    ForEach-Object {
        [pscustomobject]@{
            EventId = $_.Group[0].EventId
            EventDescription = $_.Group[0].EventDescription
            Count = $_.Count
            FirstObserved = ($_.Group.TimeCreated | Measure-Object -Minimum).Minimum
            LastObserved = ($_.Group.TimeCreated | Measure-Object -Maximum).Maximum
        }
    } |
    Sort-Object Count -Descending

$summary | Export-Csv $summaryPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "SOC security report completed."
Write-Host "Detailed report: $detailedPath"
Write-Host "Summary report:  $summaryPath"
Write-Host ""
$summary | Format-Table -AutoSize
