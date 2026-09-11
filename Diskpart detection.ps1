#Requires -RunAsAdministrator

function Check-PartitionStatus {
    [CmdletBinding()]
    param(
        [string]$BaselinePath = "$env:ProgramData\PartitionBaseline.json"
    )

    $ErrorActionPreference = 'SilentlyContinue'

    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
    if (-not $bootTime) { $bootTime = (Get-Date).AddHours(-24) }

    $logonTime = $null
    try {
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction SilentlyContinue |
            Where-Object { $_.LogonType -in @(2, 10, 11) -and $_.StartTime } |
            Sort-Object StartTime -Descending
        if ($sessions) { $logonTime = $sessions[0].StartTime }
    } catch { }

    if (-not $logonTime) { $logonTime = $bootTime }
    if ($logonTime -lt $bootTime) { $logonTime = $bootTime }

    function Format-Size {
        param([long]$Bytes)
        if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
        if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
        if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
        if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
        return "$Bytes B"
    }

    function Get-LastKnownDriveLetter {
        param(
            [int]$DiskNumber,
            [int]$PartitionNumber,
            [long]$PartitionOffset,
            [string]$PartitionGuid
        )

        try {
            $part = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -ErrorAction SilentlyContinue
            if ($part) {
                $vol = Get-Volume -Partition $part -ErrorAction SilentlyContinue
                if ($vol -and $vol.UniqueId) {
                    $cache = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache' -ErrorAction SilentlyContinue
                    foreach ($key in $cache) {
                        $val = Get-ItemProperty -Path $key.PSPath -Name VolumeLabel -ErrorAction SilentlyContinue
                        if ($val.VolumeLabel -eq $vol.UniqueId) {
                            $letter = $key.PSChildName
                            if ($letter -match '^[A-Z]:$') {
                                return $letter.Substring(0, 1)
                            }
                        }
                    }
                }
            }
        } catch { }

        try {
            $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
            $diskSig = if ($disk -and $disk.Signature) { $disk.Signature } else { 0 }
            
            $mountedDevices = Get-ItemProperty -Path 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
            if (-not $mountedDevices) { return $null }

            $regProps = $mountedDevices.PSObject.Properties | Where-Object { $_.Name -match '^\\DosDevices\\([A-Z]):$' }

            foreach ($prop in $regProps) {
                $letter = $Matches[1]
                $data = $prop.Value
                if (-not $data) { continue }

                if ($PartitionGuid -and $data.Length -ge 24) {
                    try {
                        $guidByteString = [BitConverter]::ToString($data, 8, 16) -replace '-'
                        $partGuidClean = $PartitionGuid -replace '[\{\}-]', ''
                        if ($guidByteString -ieq $partGuidClean) {
                            return "$letter"
                        }
                    } catch { }
                }

                if ($diskSig -and $data.Length -ge 12) {
                    try {
                        $regSig = [BitConverter]::ToUInt32($data, 0)
                        $regOffset = [BitConverter]::ToInt64($data, 4)

                        if ($regSig -eq $diskSig -and [Math]::Abs($regOffset - $PartitionOffset) -lt 1048576) {
                            return "$letter"
                        }
                    } catch { }
                }
            }
        } catch { }

        return $null
    }

    $usedLetters = (Get-Partition -ErrorAction SilentlyContinue | Where-Object DriveLetter | Select-Object -ExpandProperty DriveLetter)
    $allLetters = 65..90 | ForEach-Object { [char]$_ }
    $availableLetters = $allLetters | Where-Object { $_ -notin $usedLetters -and $_ -notin @('A','B') }

    $allPartitions = Get-Partition -ErrorAction SilentlyContinue
    $activeDriveLetters = @($allPartitions | Where-Object DriveLetter | Select-Object -ExpandProperty DriveLetter)

    $visibleList = @()
    $hiddenList = @()

    foreach ($part in $allPartitions) {
        $vol = $null
        try { $vol = Get-Volume -Partition $part -ErrorAction SilentlyContinue } catch { }

        $hasLetter = [bool]($part.DriveLetter)
        $isHidden = [bool]($part.IsHidden)
        
        $isSystemPartition = $part.Type -in @('System', 'Reserved', 'Recovery', 'EFI', 'MSR') -or $part.IsSystem -or $part.IsBoot

        if ($hasLetter -and -not $isHidden -and $vol -and $vol.FileSystem) {
            $labelStr = if ($vol.FileSystemLabel) { " [$($vol.FileSystemLabel)]" } else { "" }
            $sizeStr = Format-Size $part.Size
            $letterStr = $part.DriveLetter
            $visibleList += "[VISIBLE] Drive ${letterStr}:$labelStr ($($vol.FileSystem) - $sizeStr) - Disk $($part.DiskNumber), Partition $($part.PartitionNumber)"
        } elseif (-not $isSystemPartition) {
            $lastLetter = Get-LastKnownDriveLetter -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -PartitionOffset $part.Offset -PartitionGuid $part.Guid
            
            $assignedDisplay = if ($part.DriveLetter) { "$($part.DriveLetter):" } else { "None" }
            $previousDisplay = if ($lastLetter) { "$lastLetter`:" } else { "Unknown" }

            $hiddenList += [PSCustomObject]@{
                DiskNumber      = $part.DiskNumber
                PartitionNumber = $part.PartitionNumber
                DriveLetter     = $assignedDisplay
                PreviousLetter  = $previousDisplay
                SuggestedLetter = if ($lastLetter) { $lastLetter } else { if ($availableLetters) { $availableLetters[0] } else { 'X' } }
                Size            = Format-Size $part.Size
                Type            = $part.Type
                IsHidden        = $part.IsHidden
                FileSystem      = if ($vol) { $vol.FileSystem } else { "Unknown/None" }
            }
        }
    }

    $orphanedLetters = @()
    $mountedDevices = Get-ItemProperty -Path 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
    if ($mountedDevices) {
        $mountedDevices.PSObject.Properties | Where-Object { $_.Name -match '^\\DosDevices\\([A-Z]):$' } | ForEach-Object {
            $letter = $Matches[1]
            if ($letter -notin $activeDriveLetters) {
                $v = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
                if (-not $v) { $orphanedLetters += $letter }
            }
        }
    }

    function Get-DeletionEvidenceForDrive {
        param(
            [string]$TargetDriveLetter,
            [DateTime]$AfterTime
        )

        $evidenceTimes = [System.Collections.Generic.List[DateTime]]::new()

        try {
            $secEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $AfterTime } -ErrorAction SilentlyContinue |
                Where-Object { $_.ToXml() -match 'diskpart\.exe' }
            foreach ($evt in $secEvents) { $evidenceTimes.Add($evt.TimeCreated) }
        } catch { }

        try {
            $sysmonEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $AfterTime } -ErrorAction SilentlyContinue |
                Where-Object { $_.ToXml() -match 'diskpart\.exe' }
            foreach ($evt in $sysmonEvents) { $evidenceTimes.Add($evt.TimeCreated) }
        } catch { }

        $prefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchPath) {
            Get-ChildItem -Path $prefetchPath -Filter "DISKPART*" -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.LastWriteTime -gt $AfterTime) {
                    $evidenceTimes.Add($_.LastWriteTime)
                }
            }
        }

        try {
            $diagEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Partition/Diagnostic'; StartTime = $AfterTime } -ErrorAction SilentlyContinue |
                Where-Object {
                    $xml = $_.ToXml()
                    $xml -match [regex]::Escape($TargetDriveLetter) -or $xml -match 'Delete' -or $xml -match 'Remove'
                }
            foreach ($evt in $diagEvents) { $evidenceTimes.Add($evt.TimeCreated) }
        } catch { }

        try {
            $pattern1 = "\b" + [regex]::Escape($TargetDriveLetter) + ":\b"
            $pattern2 = "\\DosDevices\\" + [regex]::Escape($TargetDriveLetter) + ":"
            $sysEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $AfterTime } -ErrorAction SilentlyContinue |
                Where-Object {
                    $msg = $_.Message
                    $msg -and ($msg -match $pattern1 -or $msg -match $pattern2)
                }
            foreach ($evt in $sysEvents) { $evidenceTimes.Add($evt.TimeCreated) }
        } catch { }

        if ($evidenceTimes.Count -gt 0) {
            return ($evidenceTimes | Sort-Object -Descending)[0]
        }
        return $null
    }

    $headerAscii = @"
  ____  _     _                     _     ____       _           _             
 |  _ \(_)___| | ___ __   __ _ _ __| |_  |  _ \  ___| |_ ___  ___| |_ ___  _ __ 
 | | | | / __| |/ / '_ \ / _` | '__| __| | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 | |_| | \__ \   <| |_) | (_| | |  | |_  | |_| |  __/ ||  __/ (__| || (_) | |   
 |____/|_|___/_|\_\ .__/ \__,_|_|   \__| |____/ \___|\__\___|\___|\__\___/|_|   
                  |_|                                                          
"@
    Write-Host $headerAscii -ForegroundColor Cyan
    Write-Host " Made by yungestlavi 💜" -ForegroundColor Magenta
    Write-Host "================================================================" -ForegroundColor Cyan

    Write-Host "`n[1/3] VISIBLE & ACCESSIBLE PARTITIONS" -ForegroundColor Cyan
    if ($visibleList.Count -gt 0) {
        foreach ($item in $visibleList) {
            Write-Host "  $item" -ForegroundColor Green
        }
    } else {
        Write-Host "  No visible partitions found." -ForegroundColor Gray
    }

    Write-Host "`n[2/3] REMOVED PARTITIONS (POST-LOGON)" -ForegroundColor Cyan
    $foundDeleted = $false
    if ($orphanedLetters.Count -gt 0) {
        foreach ($letter in $orphanedLetters) {
            $deletedTime = Get-DeletionEvidenceForDrive -TargetDriveLetter $letter -AfterTime $logonTime
            if ($deletedTime) {
                $foundDeleted = $true
                $timeStr = $deletedTime.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "  [DELETED] Drive ${letter}: - Timestamp: $timeStr" -ForegroundColor Red
            }
        }
    }
    
    if (-not $foundDeleted) {
        Write-Host "  No partition deletions detected since logon." -ForegroundColor Gray
    }

    Write-Host "`n[3/3] HIDDEN / INACCESSIBLE USER PARTITIONS" -ForegroundColor Cyan
    if ($hiddenList.Count -gt 0) {
        foreach ($h in $hiddenList) {
            $targetLetter = $h.SuggestedLetter

            Write-Host "  [HIDDEN/INACCESSIBLE] Disk $($h.DiskNumber), Partition $($h.PartitionNumber) | Original Letter: $($h.PreviousLetter) | Assigned Letter: $($h.DriveLetter) | Size: $($h.Size) | Type: $($h.Type) | FileSystem: $($h.FileSystem)" -ForegroundColor Yellow
            Write-Host "    -> Step-by-step commands to reveal this partition in File Explorer:" -ForegroundColor Yellow
            Write-Host "       [Method 1: PowerShell (Run as Administrator)]" -ForegroundColor White
            Write-Host "         Get-Partition -DiskNumber $($h.DiskNumber) -PartitionNumber $($h.PartitionNumber) | Set-Partition -NewDriveLetter ${targetLetter}" -ForegroundColor DarkYellow
            Write-Host "         Get-Partition -DiskNumber $($h.DiskNumber) -PartitionNumber $($h.PartitionNumber) | Set-Partition -IsHidden `$false" -ForegroundColor DarkYellow
            Write-Host "       [Method 2: Diskpart CLI (Run as Administrator)]" -ForegroundColor White
            Write-Host "         diskpart" -ForegroundColor DarkYellow
            Write-Host "         select disk $($h.DiskNumber)" -ForegroundColor DarkYellow
            Write-Host "         select partition $($h.PartitionNumber)" -ForegroundColor DarkYellow
            Write-Host "         assign letter=${targetLetter}" -ForegroundColor DarkYellow
            Write-Host "         gpt attributes=0x0000000000000000" -ForegroundColor DarkYellow
            Write-Host ""
        }
    } else {
        Write-Host "  No hidden or inaccessible user partitions found." -ForegroundColor Gray
    }

    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host " my social" -ForegroundColor White
    Write-Host " github -> github.com/yungestlavi" -ForegroundColor Gray
    Write-Host " discord -> yungestlavi" -ForegroundColor Gray
    Write-Host " youtube -> yungestlavi" -ForegroundColor Gray
    Write-Host "================================================================`n" -ForegroundColor Cyan
}

Check-PartitionStatus
