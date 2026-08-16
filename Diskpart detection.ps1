#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$BaselinePath = "$env:ProgramData\PartitionBaseline.json",
    [switch]$UpdateBaseline,
    [bool]$ShowReport = $true,
    [string]$ExportReport
)

$ErrorActionPreference = 'Stop'
$script:ReportLines = [System.Collections.Generic.List[string]]::new()
$script:AlertCount = 0
$script:WarningCount = 0

function Write-Report {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Alert','Header','Separator','Success')]
        [string]$Level = 'Info'
    )

    $script:ReportLines.Add($Message)
    if (-not $ShowReport) { return }

    switch ($Level) {
        'Header'    { Write-Host "`n$Message" -ForegroundColor Cyan }
        'Separator' { Write-Host $Message -ForegroundColor DarkGray }
        'Alert'     { Write-Host "  [!] $Message" -ForegroundColor Red; $script:AlertCount++ }
        'Warning'   { Write-Host "  [~] $Message" -ForegroundColor Yellow; $script:WarningCount++ }
        'Success'   { Write-Host "  [OK] $Message" -ForegroundColor Green }
        'Info'      { Write-Host "  $Message" -ForegroundColor White }
    }
}

function Get-CurrentLogonTime {
    try {
        $sessions = Get-CimInstance -ClassName Win32_LogonSession |
            Where-Object { $_.LogonType -in @(2, 10, 11) -and $_.StartTime } |
            Sort-Object StartTime -Descending
        if ($sessions) { return $sessions[0].StartTime }
    } catch { }

    try {
        $queryResult = query user 2>$null
        if ($queryResult) {
            foreach ($line in $queryResult) {
                if ($line -match $env:USERNAME) {
                    if ($line -match '(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\s+\d{1,2}[:.]\d{2})') {
                        return [DateTime]::Parse($Matches[1].Trim())
                    }
                }
            }
        }
    } catch { }

    try {
        $logonEvent = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4624
        } -MaxEvents 50 -ErrorAction SilentlyContinue |
            Where-Object {
                $xml = [xml]$_.ToXml()
                $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $logonType -in @('2','10','11') -and $targetUser -eq $env:USERNAME
            } | Select-Object -First 1
        if ($logonEvent) { return $logonEvent.TimeCreated }
    } catch { }

    try {
        return (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    } catch {
        return (Get-Date).AddHours(-24)
    }
}

function Get-PartitionSnapshot {
    $snapshot = @{
        Timestamp  = (Get-Date).ToString('o')
        Hostname   = $env:COMPUTERNAME
        Partitions = @()
    }

    try {
        $partitions = Get-Partition -ErrorAction SilentlyContinue
        foreach ($part in $partitions) {
            $volume = $null
            try { $volume = Get-Volume -Partition $part -ErrorAction SilentlyContinue } catch { }

            $snapshot.Partitions += [PSCustomObject]@{
                DiskNumber      = $part.DiskNumber
                PartitionNumber = $part.PartitionNumber
                DriveLetter     = if ($part.DriveLetter) { [string]$part.DriveLetter } else { '' }
                Size            = $part.Size
                Offset          = $part.Offset
                Type            = [string]$part.Type
                GptType         = if ($part.GptType) { [string]$part.GptType } else { '' }
                MbrType         = if ($part.MbrType) { [int]$part.MbrType } else { 0 }
                IsActive        = [bool]$part.IsActive
                IsBoot          = [bool]$part.IsBoot
                IsSystem        = [bool]$part.IsSystem
                IsHidden        = [bool]$part.IsHidden
                GuidID          = if ($part.Guid) { [string]$part.Guid } else { '' }
                AccessPaths     = @(if ($part.AccessPaths) { $part.AccessPaths | ForEach-Object { [string]$_ } } else { @() })
                FileSystem      = if ($volume) { [string]$volume.FileSystem } else { '' }
                VolumeLabel     = if ($volume) { [string]$volume.FileSystemLabel } else { '' }
            }
        }
    } catch {
        Write-Report "ERROR: Unable to enumerate partitions: $_" -Level Alert
    }

    return $snapshot
}

function Compare-Partitions {
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)]$Current
    )

    $changes = @{
        Created  = [System.Collections.Generic.List[object]]::new()
        Deleted  = [System.Collections.Generic.List[object]]::new()
        Modified = [System.Collections.Generic.List[object]]::new()
    }

    $baseKeys = @{}
    foreach ($p in $Baseline.Partitions) { $baseKeys["$($p.DiskNumber):$($p.PartitionNumber)"] = $p }

    $currKeys = @{}
    foreach ($p in $Current.Partitions) { $currKeys["$($p.DiskNumber):$($p.PartitionNumber)"] = $p }

    foreach ($key in $currKeys.Keys) {
        if (-not $baseKeys.ContainsKey($key)) {
            $changes.Created.Add(@{ Partition = $currKeys[$key]; Key = $key })
        }
    }

    foreach ($key in $baseKeys.Keys) {
        if (-not $currKeys.ContainsKey($key)) {
            $changes.Deleted.Add(@{ Partition = $baseKeys[$key]; Key = $key })
        }
    }

    foreach ($key in $currKeys.Keys) {
        if ($baseKeys.ContainsKey($key)) {
            $base = $baseKeys[$key]
            $curr = $currKeys[$key]
            $diffs = [System.Collections.Generic.List[string]]::new()

            foreach ($prop in @('Size', 'Offset', 'Type', 'DriveLetter', 'FileSystem', 'VolumeLabel', 'IsActive', 'IsBoot', 'IsSystem', 'IsHidden')) {
                if ([string]$base.$prop -ne [string]$curr.$prop) {
                    $diffs.Add("$prop`: '$($base.$prop)' -> '$($curr.$prop)'")
                }
            }

            if ($diffs.Count -gt 0) {
                $changes.Modified.Add(@{
                    Key          = $key
                    OldPartition = $base
                    NewPartition = $curr
                    Differences  = $diffs
                })
            }
        }
    }

    return $changes
}

function Get-OrphanedMountedDevices {
    param([string[]]$ActiveDriveLetters)

    $orphaned = [System.Collections.Generic.List[object]]::new()

    try {
        $mountedDevices = Get-ItemProperty -Path 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
        if (-not $mountedDevices) { return $orphaned }

        $regProperties = $mountedDevices.PSObject.Properties |
            Where-Object { $_.Name -match '^\\DosDevices\\([A-Z]):$' }

        foreach ($prop in $regProperties) {
            $letter = $null
            if ($prop.Name -match '\\DosDevices\\([A-Z]):') { $letter = $Matches[1] }
            if (-not $letter) { continue }

            $isActive = $letter -in $ActiveDriveLetters

            if (-not $isActive) {
                $volumeExists = $false
                try {
                    $vol = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
                    if ($vol) { $volumeExists = $true }
                } catch { }

                if (-not $volumeExists) {
                    $deviceData = $prop.Value
                    $deviceInfo = ""
                    try {
                        if ($deviceData.Length -gt 24) {
                            $deviceInfo = [System.Text.Encoding]::Unicode.GetString($deviceData).TrimEnd("`0")
                        } else {
                            $deviceInfo = "DiskSignature: 0x$([BitConverter]::ToString($deviceData[0..3]) -replace '-','')"
                            if ($deviceData.Length -ge 12) {
                                $offset = [BitConverter]::ToInt64($deviceData, 4)
                                $deviceInfo += ", Offset: $offset"
                            }
                        }
                    } catch {
                        $deviceInfo = "Binary data: $($deviceData.Length) bytes"
                    }

                    $orphaned.Add([PSCustomObject]@{
                        DriveLetter = $letter
                        RegistryKey = $prop.Name
                        DeviceInfo  = $deviceInfo
                        DataLength  = $deviceData.Length
                    })
                }
            }
        }
    } catch {
        Write-Report "Error accessing MountedDevices registry: $_" -Level Warning
    }

    return $orphaned
}

function Get-DiskpartExecutions {
    param([DateTime]$After)

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = 4688; StartTime = $After
        } -ErrorAction SilentlyContinue

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $processName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'
            $commandLine = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
            $creator = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'

            if ($processName -match 'diskpart\.exe') {
                $results.Add([PSCustomObject]@{
                    Time = $evt.TimeCreated; Process = $processName
                    CommandLine = $commandLine; User = $creator; Source = 'SecurityLog_4688'
                })
            }
        }
    } catch { }

    try {
        $sysmonEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $After
        } -ErrorAction SilentlyContinue

        foreach ($evt in $sysmonEvents) {
            $xml = [xml]$evt.ToXml()
            $image = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
            $cmdLine = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
            $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'User' }).'#text'

            if ($image -match 'diskpart\.exe') {
                $results.Add([PSCustomObject]@{
                    Time = $evt.TimeCreated; Process = $image
                    CommandLine = $cmdLine; User = $user; Source = 'Sysmon_1'
                })
            }
        }
    } catch { }

    return $results
}

function Get-PartitionDiagnosticEvents {
    param([DateTime]$After)

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Partition/Diagnostic'; StartTime = $After
        } -ErrorAction SilentlyContinue

        foreach ($evt in $events) {
            $results.Add([PSCustomObject]@{
                Time = $evt.TimeCreated; EventId = $evt.Id
                Message = $evt.Message; XmlData = $evt.ToXml(); Source = 'PartitionDiagnostic'
            })
        }
    } catch { }

    return $results
}

function Get-VolumeSystemEvents {
    param([DateTime]$After)

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($provider in @('Ntfs', 'disk', 'partmgr', 'volmgr', 'volsnap', 'Microsoft-Windows-Ntfs')) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'System'; ProviderName = $provider; StartTime = $After
            } -ErrorAction SilentlyContinue

            foreach ($evt in $events) {
                $results.Add([PSCustomObject]@{
                    Time = $evt.TimeCreated; EventId = $evt.Id
                    Provider = $provider; Message = $evt.Message; Source = 'SystemLog'
                })
            }
        } catch { }
    }

    return $results
}

function Get-PrefetchEvidence {
    $prefetchPath = "$env:SystemRoot\Prefetch"
    $results = [System.Collections.Generic.List[object]]::new()

    if (Test-Path $prefetchPath) {
        foreach ($pattern in @('DISKPART*', 'MMC.EXE*')) {
            Get-ChildItem -Path $prefetchPath -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
                $results.Add([PSCustomObject]@{
                    FileName = $_.Name; LastAccess = $_.LastAccessTime
                    LastWrite = $_.LastWriteTime; CreationTime = $_.CreationTime
                })
            }
        }
    }

    return $results
}

function Test-PostLogonEvidence {
    param(
        [DateTime]$LogonTime,
        [string]$DriveLetter = ''
    )

    $evidence = [System.Collections.Generic.List[string]]::new()

    $diskpartRuns = Get-DiskpartExecutions -After $LogonTime
    foreach ($run in $diskpartRuns) {
        $evidence.Add("diskpart.exe executed at $($run.Time.ToString('HH:mm:ss')) by $($run.User)")
    }

    $prefetch = Get-PrefetchEvidence
    foreach ($pf in $prefetch) {
        if ($pf.FileName -match 'DISKPART' -and $pf.LastWrite -gt $LogonTime) {
            $evidence.Add("DISKPART prefetch updated: $($pf.LastWrite.ToString('HH:mm:ss'))")
        }
        if ($pf.FileName -match 'MMC' -and $pf.LastWrite -gt $LogonTime) {
            $evidence.Add("MMC prefetch (possible Disk Management) updated: $($pf.LastWrite.ToString('HH:mm:ss'))")
        }
    }

    $diagEvents = Get-PartitionDiagnosticEvents -After $LogonTime
    if ($diagEvents.Count -gt 0) {
        $evidence.Add("$($diagEvents.Count) Partition/Diagnostic events after logon")
    }

    $sysEvents = Get-VolumeSystemEvents -After $LogonTime
    if ($sysEvents.Count -gt 0) {
        $significantEvents = $sysEvents | Where-Object {
            $_.EventId -in @(12, 55, 98, 7, 15, 51) -or
            ($DriveLetter -and $_.Message -match [regex]::Escape($DriveLetter))
        }
        if ($significantEvents) {
            $evidence.Add("$(@($significantEvents).Count) significant system events after logon")
        }
    }

    $suspiciousProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'diskpart' }
    if ($suspiciousProcs) { $evidence.Add("diskpart.exe currently running!") }

    return @{ HasEvidence = $evidence.Count -gt 0; Details = $evidence }
}

function Format-SizeHuman {
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

# ============================================================================
# MAIN
# ============================================================================

Write-Report "========================================================" -Level Separator
Write-Report " PARTITION CHANGE DETECTOR v2.0 (Forensic)" -Level Header
Write-Report " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info
Write-Report "========================================================" -Level Separator

$logonTime = Get-CurrentLogonTime
Write-Report ""
Write-Report "[SESSION]" -Level Header
Write-Report "User: $env:USERDOMAIN\$env:USERNAME" -Level Info
Write-Report "Computer: $env:COMPUTERNAME" -Level Info
Write-Report "Logon Time: $($logonTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
Write-Report "Current Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info

Write-Report ""
Write-Report "[CURRENT PARTITION SNAPSHOT]" -Level Header

$currentSnapshot = Get-PartitionSnapshot

if ($currentSnapshot.Partitions.Count -eq 0) {
    Write-Report "No partitions detected! Verify administrator permissions." -Level Alert
    exit 1
}

Write-Report "Detected $($currentSnapshot.Partitions.Count) partitions on $(($currentSnapshot.Partitions | Select-Object -ExpandProperty DiskNumber -Unique).Count) disk(s)" -Level Info

$activeDriveLetters = @()
foreach ($part in $currentSnapshot.Partitions) {
    $letter = if ($part.DriveLetter) { "$($part.DriveLetter):" } else { "N/A" }
    $label = if ($part.VolumeLabel) { " [$($part.VolumeLabel)]" } else { "" }
    $fs = if ($part.FileSystem) { " ($($part.FileSystem))" } else { "" }
    Write-Report "  Disk $($part.DiskNumber), Part $($part.PartitionNumber): $letter$label$fs - $(Format-SizeHuman $part.Size) - Type: $($part.Type)" -Level Info
    if ($part.DriveLetter) { $activeDriveLetters += $part.DriveLetter }
}

if ($UpdateBaseline) {
    Write-Report ""
    Write-Report "[BASELINE UPDATE]" -Level Header
    $currentSnapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $BaselinePath -Encoding UTF8 -Force
    Write-Report "Baseline saved to: $BaselinePath" -Level Success
    Write-Report "Timestamp: $($currentSnapshot.Timestamp)" -Level Info
    Write-Report "Partitions in baseline: $($currentSnapshot.Partitions.Count)" -Level Info
    Write-Report ""
    Write-Report "Run the script without -UpdateBaseline to compare." -Level Info

    if ($ExportReport -and $script:ReportLines.Count -gt 0) {
        $script:ReportLines | Out-File -FilePath $ExportReport -Encoding UTF8 -Force
        Write-Host "`nReport exported to: $ExportReport" -ForegroundColor Green
    }
    exit 0
}

# ============================================================================
# SECTION 1: FORENSIC DETECTION (works WITHOUT baseline)
# ============================================================================

Write-Report ""
Write-Report "================================================================" -Level Separator
Write-Report " SECTION 1: FORENSIC DETECTION (no baseline required)" -Level Header
Write-Report "================================================================" -Level Separator

Write-Report ""
Write-Report "[REGISTRY: Orphaned Drive Letters (MountedDevices)]" -Level Header
Write-Report "Scanning registry for drive letters assigned to partitions that no longer exist..." -Level Info

$orphanedDrives = Get-OrphanedMountedDevices -ActiveDriveLetters $activeDriveLetters

if ($orphanedDrives.Count -eq 0) {
    Write-Report "No orphaned drive letters found in the registry." -Level Success
} else {
    Write-Report "Found $($orphanedDrives.Count) orphaned drive letter(s) (possible deleted partitions):" -Level Warning
    Write-Report "" -Level Info

    foreach ($orphan in $orphanedDrives) {
        $evidenceResult = Test-PostLogonEvidence -LogonTime $logonTime -DriveLetter $orphan.DriveLetter

        if ($evidenceResult.HasEvidence) {
            Write-Report "PARTITION DELETED (POST-LOGON): Drive $($orphan.DriveLetter):" -Level Alert
            Write-Report "  Registry Key: $($orphan.RegistryKey)" -Level Alert
            Write-Report "  Device Info: $($orphan.DeviceInfo)" -Level Alert
            Write-Report "  Post-logon evidence:" -Level Alert
            foreach ($detail in $evidenceResult.Details) {
                Write-Report "    -> $detail" -Level Alert
            }
        } else {
            Write-Report "Orphaned drive letter (pre-logon / removable device): $($orphan.DriveLetter):" -Level Warning
            Write-Report "  Registry Key: $($orphan.RegistryKey)" -Level Info
            Write-Report "  Device Info: $($orphan.DeviceInfo)" -Level Info
            Write-Report "  -> No post-logon deletion evidence found. Not flagged as alert." -Level Info
        }
    }
}

Write-Report ""
Write-Report "[DISKPART.EXE EXECUTIONS (after logon: $($logonTime.ToString('HH:mm:ss')))]" -Level Header

$diskpartExecs = Get-DiskpartExecutions -After $logonTime

if ($diskpartExecs.Count -eq 0) {
    Write-Report "No diskpart.exe executions detected after logon." -Level Success
    Write-Report "  (Note: requires Audit Process Creation enabled or Sysmon installed)" -Level Info
} else {
    foreach ($exec in $diskpartExecs) {
        Write-Report "DISKPART.EXE EXECUTED: $($exec.Time.ToString('yyyy-MM-dd HH:mm:ss')) by $($exec.User)" -Level Alert
        if ($exec.CommandLine) {
            Write-Report "  Command line: $($exec.CommandLine)" -Level Alert
        }
        Write-Report "  Source: $($exec.Source)" -Level Info
    }
}

Write-Report ""
Write-Report "[PREFETCH: DISKPART / DISK MANAGEMENT]" -Level Header

$prefetchData = Get-PrefetchEvidence
$diskpartPrefetch = $prefetchData | Where-Object { $_.FileName -match 'DISKPART' }
$mmcPrefetch = $prefetchData | Where-Object { $_.FileName -match 'MMC' }

if ($diskpartPrefetch.Count -eq 0 -and $mmcPrefetch.Count -eq 0) {
    Write-Report "No prefetch files found for diskpart.exe or mmc.exe." -Level Success
} else {
    foreach ($pf in $diskpartPrefetch) {
        if ($pf.LastWrite -gt $logonTime) {
            Write-Report "DISKPART USED POST-LOGON: $($pf.FileName)" -Level Alert
            Write-Report "  Last execution: $($pf.LastWrite.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Alert
            Write-Report "  Prefetch created: $($pf.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
        } else {
            Write-Report "Diskpart prefetch (pre-logon): $($pf.FileName)" -Level Info
            Write-Report "  Last execution: $($pf.LastWrite.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
        }
    }
    foreach ($pf in $mmcPrefetch) {
        if ($pf.LastWrite -gt $logonTime) {
            Write-Report "MMC.EXE (possible Disk Management) POST-LOGON: $($pf.FileName)" -Level Warning
            Write-Report "  Last execution: $($pf.LastWrite.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Warning
        }
    }
}

Write-Report ""
Write-Report "[PARTITION/DIAGNOSTIC EVENTS (after logon)]" -Level Header

$diagEvents = Get-PartitionDiagnosticEvents -After $logonTime

if ($diagEvents.Count -eq 0) {
    Write-Report "No partition diagnostic events after logon." -Level Success
} else {
    Write-Report "Found $($diagEvents.Count) diagnostic events after logon:" -Level Warning
    foreach ($evt in ($diagEvents | Select-Object -First 10)) {
        $msgPreview = if ($evt.Message -and $evt.Message.Length -gt 120) { $evt.Message.Substring(0, 120) + "..." } else { $evt.Message }
        Write-Report "  [$($evt.Time.ToString('HH:mm:ss'))] EventID $($evt.EventId): $msgPreview" -Level Warning
    }
    if ($diagEvents.Count -gt 10) {
        Write-Report "  ... and $($diagEvents.Count - 10) more events." -Level Info
    }
}

Write-Report ""
Write-Report "[SYSTEM EVENTS - VOLUMES/DISKS (after logon)]" -Level Header

$sysEvents = Get-VolumeSystemEvents -After $logonTime

if ($sysEvents.Count -eq 0) {
    Write-Report "No relevant system events after logon." -Level Success
} else {
    Write-Report "Found $($sysEvents.Count) relevant system events:" -Level Warning
    foreach ($evt in ($sysEvents | Select-Object -First 10)) {
        $msgPreview = if ($evt.Message -and $evt.Message.Length -gt 100) { $evt.Message.Substring(0, 100) + "..." } else { $evt.Message }
        Write-Report "  [$($evt.Time.ToString('HH:mm:ss'))] $($evt.Provider) ID:$($evt.EventId) - $msgPreview" -Level Warning
    }
    if ($sysEvents.Count -gt 10) {
        Write-Report "  ... and $($sysEvents.Count - 10) more events." -Level Info
    }
}

Write-Report ""
Write-Report "[ACTIVE PROCESSES - DISK MANAGEMENT TOOLS]" -Level Header

$suspiciousFound = $false
$suspiciousProcesses = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'diskpart|mmc' }

if ($suspiciousProcesses) {
    foreach ($proc in $suspiciousProcesses) {
        if ($proc.Name -eq 'diskpart') {
            Write-Report "DISKPART.EXE CURRENTLY RUNNING! PID: $($proc.Id)" -Level Alert
            $suspiciousFound = $true
        }
        if ($proc.Name -eq 'mmc') {
            try {
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine -match 'diskmgmt') {
                    Write-Report "DISK MANAGEMENT CURRENTLY RUNNING! PID: $($proc.Id)" -Level Alert
                    $suspiciousFound = $true
                }
            } catch { }
        }
    }
}

if (-not $suspiciousFound) {
    Write-Report "No disk management tools currently running." -Level Success
}

# ============================================================================
# SECTION 2: BASELINE COMPARISON (if available)
# ============================================================================

Write-Report ""
Write-Report "================================================================" -Level Separator
Write-Report " SECTION 2: BASELINE COMPARISON" -Level Header
Write-Report "================================================================" -Level Separator

if (-not (Test-Path $BaselinePath)) {
    Write-Report ""
    Write-Report "No baseline found at: $BaselinePath" -Level Warning
    Write-Report "Forensic detection (Section 1) is still active." -Level Info
    Write-Report "For more precise comparisons, create a baseline:" -Level Info
    Write-Report "  .\Detect-PartitionChanges.ps1 -UpdateBaseline" -Level Info
} else {
    $baselineRaw = Get-Content -Path $BaselinePath -Raw -Encoding UTF8
    $baseline = $baselineRaw | ConvertFrom-Json

    Write-Report ""
    Write-Report "Baseline loaded: $($baseline.Timestamp)" -Level Info
    Write-Report "Partitions in baseline: $($baseline.Partitions.Count)" -Level Info

    $baselineTime = [DateTime]::Parse($baseline.Timestamp)
    $changes = Compare-Partitions -Baseline $baseline -Current $currentSnapshot

    Write-Report ""
    Write-Report "[CREATED PARTITIONS (vs baseline)]" -Level Header

    if ($changes.Created.Count -eq 0) {
        Write-Report "No new partitions detected." -Level Success
    } else {
        foreach ($item in $changes.Created) {
            $p = $item.Partition
            $letter = if ($p.DriveLetter) { "$($p.DriveLetter):" } else { "N/A" }
            Write-Report "NEW PARTITION: Disk $($p.DiskNumber), Part $($p.PartitionNumber) ($letter) - $(Format-SizeHuman $p.Size) - $($p.Type)" -Level Alert
        }
    }

    Write-Report ""
    Write-Report "[DELETED PARTITIONS (vs baseline)]" -Level Header

    if ($changes.Deleted.Count -eq 0) {
        Write-Report "No deleted partitions detected." -Level Success
    } else {
        foreach ($item in $changes.Deleted) {
            $p = $item.Partition
            $letter = if ($p.DriveLetter) { "$($p.DriveLetter):" } else { "N/A" }
            $fs = if ($p.FileSystem) { " ($($p.FileSystem))" } else { "" }

            if ($baselineTime -gt $logonTime) {
                Write-Report "PARTITION DELETED (POST-LOGON): Disk $($p.DiskNumber), Part $($p.PartitionNumber) ($letter)$fs - $(Format-SizeHuman $p.Size) - $($p.Type)" -Level Alert
                Write-Report "  -> Baseline was created AFTER current logon: deletion occurred in THIS session." -Level Alert
            } else {
                $letterForSearch = if ($p.DriveLetter) { $p.DriveLetter } else { '' }
                $evidenceResult = Test-PostLogonEvidence -LogonTime $logonTime -DriveLetter $letterForSearch

                if ($evidenceResult.HasEvidence) {
                    Write-Report "PARTITION DELETED (POST-LOGON EVIDENCE): Disk $($p.DiskNumber), Part $($p.PartitionNumber) ($letter)$fs - $(Format-SizeHuman $p.Size) - $($p.Type)" -Level Alert
                    foreach ($detail in $evidenceResult.Details) {
                        Write-Report "  -> $detail" -Level Alert
                    }
                } else {
                    Write-Report "Partition missing (PRE-LOGON, NOT FLAGGED): Disk $($p.DiskNumber), Part $($p.PartitionNumber) ($letter)$fs - $(Format-SizeHuman $p.Size) - $($p.Type)" -Level Warning
                    Write-Report "  -> Baseline is pre-logon, no post-logon evidence. Deleted BEFORE reboot?" -Level Warning
                }
            }
        }
    }

    Write-Report ""
    Write-Report "[MODIFIED PARTITIONS (vs baseline)]" -Level Header

    if ($changes.Modified.Count -eq 0) {
        Write-Report "No modifications detected." -Level Success
    } else {
        foreach ($item in $changes.Modified) {
            $key = $item.Key
            $letter = if ($item.NewPartition.DriveLetter) { "$($item.NewPartition.DriveLetter):" } else { "N/A" }
            Write-Report "PARTITION MODIFIED: Disk $($key.Split(':')[0]), Part $($key.Split(':')[1]) ($letter)" -Level Alert
            foreach ($diff in $item.Differences) {
                Write-Report "  Change: $diff" -Level Alert
            }
        }
    }

    $currentSnapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $BaselinePath -Encoding UTF8 -Force
    Write-Report ""
    Write-Report "Baseline automatically updated." -Level Info
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Report ""
Write-Report "========================================================" -Level Separator
Write-Report "[FINAL SUMMARY]" -Level Header
Write-Report "========================================================" -Level Separator

Write-Report ""
if ($script:AlertCount -eq 0 -and $script:WarningCount -eq 0) {
    Write-Report "NO ANOMALIES DETECTED" -Level Success
} elseif ($script:AlertCount -gt 0) {
    Write-Report "DETECTED $($script:AlertCount) PARTITION ANOMALIES!" -Level Alert
    Write-Report "Warnings: $($script:WarningCount)" -Level Warning
} else {
    Write-Report "No critical alerts. Warnings: $($script:WarningCount)" -Level Warning
}

Write-Report "Orphaned drive letters detected: $($orphanedDrives.Count)" -Level Info
Write-Report "Reference logon time: $($logonTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info

if ($ExportReport -and $script:ReportLines.Count -gt 0) {
    $script:ReportLines | Out-File -FilePath $ExportReport -Encoding UTF8 -Force
    Write-Host "`nReport exported to: $ExportReport" -ForegroundColor Green
}
