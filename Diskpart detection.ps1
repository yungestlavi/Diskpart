#Requires -RunAsAdministrator

function Check-PartitionChanges {
    [CmdletBinding()]
    param(
        [string]$BaselinePath = "$env:ProgramData\PartitionBaseline.json"
    )

    $ErrorActionPreference = 'SilentlyContinue'

    $logonTime = $null
    try {
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction SilentlyContinue |
            Where-Object { $_.LogonType -in @(2, 10, 11) -and $_.StartTime } |
            Sort-Object StartTime -Descending
        if ($sessions) { $logonTime = $sessions[0].StartTime }
    } catch { }

    if (-not $logonTime) {
        try {
            $logonEvent = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object {
                    $xml = [xml]$_.ToXml()
                    $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                    $logonType -in @('2','10','11')
                } | Select-Object -First 1
            if ($logonEvent) { $logonTime = $logonEvent.TimeCreated }
        } catch { }
    }

    if (-not $logonTime) {
        try { $logonTime = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime } catch { $logonTime = (Get-Date).AddHours(-24) }
    }

    $activePartitions = Get-Partition -ErrorAction SilentlyContinue
    $activeDriveLetters = @($activePartitions | Where-Object DriveLetter | Select-Object -ExpandProperty DriveLetter)

    $orphanedLetters = @()
    $mountedDevices = Get-ItemProperty -Path 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
    if ($mountedDevices) {
        $mountedDevices.PSObject.Properties | Where-Object { $_.Name -match '^\\DosDevices\\([A-Z]):$' } | ForEach-Object {
            $letter = $Matches[1]
            if ($letter -notin $activeDriveLetters) {
                $vol = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
                if (-not $vol) {
                    $orphanedLetters += $letter
                }
            }
        }
    }

    $createdList = @()
    $deletedList = @()

    if (Test-Path $BaselinePath) {
        try {
            $baseline = Get-Content -Path $BaselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $baseLetters = @($baseline.Partitions | Where-Object DriveLetter | Select-Object -ExpandProperty DriveLetter)

            foreach ($l in $activeDriveLetters) {
                if ($l -notin $baseLetters) { $createdList += $l }
            }

            foreach ($l in $baseLetters) {
                if ($l -notin $activeDriveLetters -and $l -notin $orphanedLetters) { $deletedList += $l }
            }
        } catch { }
    }

    try {
        $snapshot = @{
            Timestamp  = (Get-Date).ToString('o')
            Partitions = @($activePartitions | ForEach-Object {
                [PSCustomObject]@{
                    DiskNumber      = $_.DiskNumber
                    PartitionNumber = $_.PartitionNumber
                    DriveLetter     = [string]$_.DriveLetter
                }
            })
        }
        $snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path $BaselinePath -Encoding UTF8 -Force
    } catch { }

    $allDeletedCandidates = @($orphanedLetters + $deletedList | Select-Object -Unique)

    $timestamps = [System.Collections.Generic.List[DateTime]]::new()

    try {
        $diagEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Partition/Diagnostic'; StartTime = $logonTime } -ErrorAction SilentlyContinue
        if ($diagEvents) {
            foreach ($evt in $diagEvents) { $timestamps.Add($evt.TimeCreated) }
        }
    } catch { }

    try {
        $secEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $logonTime } -ErrorAction SilentlyContinue |
            Where-Object { $_.ToXml() -match 'diskpart\.exe' }
        if ($secEvents) {
            foreach ($evt in $secEvents) { $timestamps.Add($evt.TimeCreated) }
        }
    } catch { }

    try {
        $sysmonEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $logonTime } -ErrorAction SilentlyContinue |
            Where-Object { $_.ToXml() -match 'diskpart\.exe' }
        if ($sysmonEvents) {
            foreach ($evt in $sysmonEvents) { $timestamps.Add($evt.TimeCreated) }
        }
    } catch { }

    $prefetchPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchPath) {
        Get-ChildItem -Path $prefetchPath -Filter "DISKPART*" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.LastWriteTime -gt $logonTime) { $timestamps.Add($_.LastWriteTime) }
        }
    }

    try {
        $sysEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $logonTime } -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -in @('Ntfs', 'disk', 'partmgr', 'volmgr') }
        if ($sysEvents) {
            foreach ($evt in $sysEvents) { $timestamps.Add($evt.TimeCreated) }
        }
    } catch { }

    $mostRecentTime = $null
    if ($timestamps.Count -gt 0) {
        $mostRecentTime = ($timestamps | Sort-Object -Descending)[0]
    }

    $foundAny = $false

    foreach ($letter in $allDeletedCandidates) {
        if ($mostRecentTime) {
            $foundAny = $true
            $timeStr = $mostRecentTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "[DELETED] Partition ${letter}: - $timeStr" -ForegroundColor Red
        }
    }

    foreach ($letter in $createdList) {
        $eventTime = if ($mostRecentTime) { $mostRecentTime } else { Get-Date }
        $foundAny = $true
        $timeStr = $eventTime.ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "[CREATED] Partition ${letter}: - $timeStr" -ForegroundColor Green
    }

    if (-not $foundAny) {
        Write-Host "No partition changes detected since logon." -ForegroundColor Gray
    }
}

Check-PartitionChanges
