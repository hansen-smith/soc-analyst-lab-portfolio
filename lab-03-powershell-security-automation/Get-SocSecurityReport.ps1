<#
.SYNOPSIS
    Creates a basic SOC report from the local Windows Security log.

.DESCRIPTION
    Collects Event IDs 4624, 4625, 4672, and 4688, extracts useful fields,
    exports detailed events to CSV, and creates a summary CSV.

.NOTES
    Run PowerShell as Administrator.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$Hours = 24,

    [string]$OutputDirectory = (Join-Path -Path $PSScriptRoot -ChildPath "output")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-EventDataMap {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord
    )

    [xml]$eventXml = $EventRecord.ToXml()
    $dataMap = @{}

    $dataNodes = @($eventXml.Event.EventData.Data)

    foreach ($dataNode in $dataNodes) {
        if ($null -eq $dataNode) {
            continue
        }

        $name = [string]$dataNode.Name

        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        # InnerText works reliably even when a #text property is not exposed.
        $value = [string]$dataNode.InnerText
        $dataMap[$name] = $value
    }

    return $dataMap
}

function Get-FirstValue {
    param(
        [hashtable]$Data,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if (
            $Data.ContainsKey($name) -and
            -not [string]::IsNullOrWhiteSpace([string]$Data[$name])
        ) {
            return [string]$Data[$name]
        }
    }

    return ""
}

if (-not (Test-IsAdministrator)) {
    Write-Error "Run PowerShell as Administrator, then run the script again."
}

$eventDescriptions = @{
    4624 = "Successful Logon"
    4625 = "Failed Logon"
    4672 = "Special Privileges Assigned"
    4688 = "Process Created"
}

$startTime = (Get-Date).AddHours(-$Hours)
$eventIds = @(4624, 4625, 4672, 4688)

New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

Write-Host "Collecting Windows Security events from the last $Hours hour(s)..."

try {
    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $eventIds
            StartTime = $startTime
        } -ErrorAction Stop
    )
}
catch {
    Write-Error (
        "Unable to read the Windows Security log. " +
        "Confirm that PowerShell is running as Administrator. " +
        "Details: $($_.Exception.Message)"
    )
}

if ($events.Count -eq 0) {
    Write-Warning "No matching events were found in the selected time range."
    return
}

$report = foreach ($event in $events) {
    $data = Get-EventDataMap -EventRecord $event

    $account = Get-FirstValue -Data $data -Names @(
        "TargetUserName",
        "SubjectUserName",
        "AccountName"
    )

    $sourceAddress = Get-FirstValue -Data $data -Names @(
        "IpAddress",
        "SourceNetworkAddress",
        "WorkstationName"
    )

    $failureReason = Get-FirstValue -Data $data -Names @(
        "FailureReason",
        "Status",
        "SubStatus"
    )

    [pscustomobject]@{
        TimeCreated       = $event.TimeCreated
        EventId           = $event.Id
        EventDescription  = $eventDescriptions[$event.Id]
        Computer          = $event.MachineName
        Account           = $account
        LogonType         = Get-FirstValue -Data $data -Names @("LogonType")
        SourceAddress     = $sourceAddress
        FailureReason     = $failureReason
        ProcessName       = Get-FirstValue -Data $data -Names @("NewProcessName")
        ParentProcessName = Get-FirstValue -Data $data -Names @(
            "ParentProcessName",
            "CreatorProcessName"
        )
        CommandLine       = Get-FirstValue -Data $data -Names @(
            "CommandLine",
            "ProcessCommandLine"
        )
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$detailedPath = Join-Path $OutputDirectory "security-events-$timestamp.csv"
$summaryPath = Join-Path $OutputDirectory "event-summary-$timestamp.csv"

$report |
    Sort-Object TimeCreated -Descending |
    Export-Csv -Path $detailedPath -NoTypeInformation -Encoding UTF8

$summary = $report |
    Group-Object EventId, EventDescription |
    ForEach-Object {
        [pscustomobject]@{
            EventId          = $_.Group[0].EventId
            EventDescription = $_.Group[0].EventDescription
            Count            = $_.Count
            FirstObserved    = (
                $_.Group.TimeCreated | Measure-Object -Minimum
            ).Minimum
            LastObserved     = (
                $_.Group.TimeCreated | Measure-Object -Maximum
            ).Maximum
        }
    } |
    Sort-Object Count -Descending

$summary |
    Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "SOC security report completed."
Write-Host "Detailed report: $detailedPath"
Write-Host "Summary report:  $summaryPath"
Write-Host ""
Write-Host "Event summary:"
$summary | Format-Table -AutoSize
