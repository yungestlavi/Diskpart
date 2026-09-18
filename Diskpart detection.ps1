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

    # ========================
    # BASELINE MANAGEMENT
    # ========================

    function Get-PartitionSnapshot {
        $snapshot = @()
        $allParts = Get-Partition -ErrorAction SilentlyContinue

        $allVolumes = Get-PnpDevice -Class Volume -ErrorAction SilentlyContinue
        $volRelations = @{}
        foreach ($v in $allVolumes) {
            $rels = Get-PnpDeviceProperty -InstanceId $v.InstanceId -KeyName 'DEVPKEY_Device_PowerRelations' -ErrorAction SilentlyContinue
            if ($rels.Data) {
                $volRelations[$v.InstanceId] = $rels.Data -join ';'
            }
        }

        foreach ($p in $allParts) {
            $vol = $null
            try { $vol = Get-Volume -Partition $p -ErrorAction SilentlyContinue } catch { }

            $isSystem = $p.Type -in @('System', 'Reserved', 'Recovery', 'EFI', 'MSR') -or $p.IsSystem -or $p.IsBoot

            $volumeId = ""
            if ($vol -and $vol.UniqueId) { $volumeId = $vol.UniqueId }

            $storageDeviceId = ""
            $diskRegId = ""
            
            try {
                $disk = Get-Disk -Number $p.DiskNumber -ErrorAction SilentlyContinue
                if ($disk) {
                    $wmiDisk = Get-WmiObject Win32_DiskDrive -Filter "Index=$($disk.Number)" -ErrorAction SilentlyContinue
                    if ($wmiDisk -and $wmiDisk.PNPDeviceID) {
                        $pnpId = $wmiDisk.PNPDeviceID
                        $hexOffSearch = "#" + $p.Offset.ToString("X16")
                        
                        foreach ($key in $volRelations.Keys) {
                            if ($volRelations[$key] -match [regex]::Escape($pnpId) -and $key -match $hexOffSearch) {
                                $storageDeviceId = $key
                                if ($key -match '^STORAGE\\VOLUME\\(\{[^}]+\})#') {
                                    $diskRegId = $Matches[1]
                                }
                                break
                            }
                        }
                    }
                    
                    if (-not $storageDeviceId) {
                        $entries = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\STORAGE\VOLUME' -ErrorAction SilentlyContinue
                        foreach ($e in $entries) {
                            $name = $e.PSChildName
                            if ($name -match '^(\{[^}]+\})#([0-9A-Fa-f]+)$') {
                                $regGuid = $Matches[1]
                                $hexOff = $Matches[2]
                                $decOff = [Convert]::ToInt64($hexOff, 16)
                                if ([Math]::Abs($decOff - $p.Offset) -lt 65536) {
                                    $diskRegId = $regGuid
                                    $storageDeviceId = "STORAGE\VOLUME\$diskRegId#$hexOff"
                                    break
                                }
                            }
                        }
                    }
                }
            } catch { }

            $encryption = "None"
            try {
                if ($p.DriveLetter -and $p.DriveLetter -ne [char]0) {
                    $bl = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$($p.DriveLetter):'" -ErrorAction SilentlyContinue
                    if ($bl -and $bl.ProtectionStatus -ne 0) {
                        $encryption = "BitLocker"
                    }
                }
            } catch { }

            if ($encryption -eq "None" -and -not $isSystem -and -not $vol.FileSystem) {
                $encryption = "RAW (Possible Encrypted Container)"
            }

            $snapshot += [PSCustomObject]@{
                DiskNumber      = $p.DiskNumber
                PartitionNumber = $p.PartitionNumber
                DriveLetter     = if ($p.DriveLetter -and $p.DriveLetter -ne [char]0) { [string]$p.DriveLetter } else { "" }
                Size            = $p.Size
                Offset          = $p.Offset
                Type            = [string]$p.Type
                Guid            = [string]$p.Guid
                VolumeId        = $volumeId
                FileSystem      = if ($vol) { [string]$vol.FileSystem } else { "" }
                Label           = if ($vol -and $vol.FileSystemLabel) { [string]$vol.FileSystemLabel } else { "" }
                IsSystem        = $isSystem
                IsHidden        = [bool]$p.IsHidden
                StorageDeviceId = $storageDeviceId
                DiskRegId       = $diskRegId
                Encryption      = $encryption
            }
        }
        return $snapshot
    }

    function Save-Baseline {
        param($Snapshot, $BootTime, $Path)
        $baseline = @{
            BootTime     = $BootTime.ToString("o")
            ScanTime     = (Get-Date).ToString("o")
            Partitions   = @($Snapshot | ForEach-Object {
                @{
                    DiskNumber      = $_.DiskNumber
                    PartitionNumber = $_.PartitionNumber
                    DriveLetter     = $_.DriveLetter
                    Size            = $_.Size
                    Offset          = $_.Offset
                    Type            = $_.Type
                    Guid            = $_.Guid
                    VolumeId        = $_.VolumeId
                    FileSystem      = $_.FileSystem
                    Label           = $_.Label
                    IsSystem        = $_.IsSystem
                    IsHidden        = $_.IsHidden
                    StorageDeviceId = $_.StorageDeviceId
                    DiskRegId       = $_.DiskRegId
                    Encryption      = $_.Encryption
                }
            })
        }
        $baseline | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8 -Force
    }

    function Load-Baseline {
        param($Path)
        if (-not (Test-Path $Path)) { return $null }
        try {
            $raw = Get-Content -Path $Path -Raw -Encoding UTF8
            $parsed = ($raw | ConvertFrom-Json)
            if (-not $parsed.BootTime) { return $null }
            return $parsed
        } catch { return $null }
    }

    $currentSnapshot = Get-PartitionSnapshot
    $baseline = Load-Baseline -Path $BaselinePath
    $isNewSession = $false

    $baselineBoot = $null
    if ($baseline -and $baseline.BootTime) {
        $baselineBoot = if ($baseline.BootTime -is [DateTime]) { $baseline.BootTime } else { [DateTime]::Parse($baseline.BootTime) }
    }

    if (-not $baseline -or $baselineBoot -ne $bootTime) {
        $isNewSession = $true
        Save-Baseline -Snapshot $currentSnapshot -BootTime $bootTime -Path $BaselinePath
        $baseline = Load-Baseline -Path $BaselinePath
    } else {
        $mergedPartitions = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($bp in $baseline.Partitions) { $mergedPartitions.Add($bp) }
        
        foreach ($cp in $currentSnapshot) {
            $exists = $mergedPartitions | Where-Object { 
                ($_.DiskNumber -eq $cp.DiskNumber -and $_.PartitionNumber -eq $cp.PartitionNumber -and $_.Offset -eq $cp.Offset) -or
                ($_.VolumeId -and $_.VolumeId -eq $cp.VolumeId) -or
                ($_.Guid -and $_.Guid -eq $cp.Guid -and $cp.Guid -ne "")
            }
            if (-not $exists) {
                $mergedPartitions.Add($cp)
            } else {
                $exists[0].DriveLetter = $cp.DriveLetter
                $exists[0].IsHidden = $cp.IsHidden
                $exists[0].StorageDeviceId = $cp.StorageDeviceId
                $exists[0].DiskRegId = $cp.DiskRegId
                $exists[0].Encryption = $cp.Encryption
            }
        }
        
        # Format dates explicitly so they don't break when saving back
        $btStr = if ($baseline.BootTime -is [DateTime]) { $baseline.BootTime.ToString("o") } else { $baseline.BootTime }
        $stStr = (Get-Date).ToString("o")

        $updatedBaseline = @{
            BootTime = $btStr
            ScanTime = $stStr
            Partitions = $mergedPartitions.ToArray()
        }
        $updatedBaseline | ConvertTo-Json -Depth 5 | Out-File -FilePath $BaselinePath -Encoding UTF8 -Force
        $baseline = Load-Baseline -Path $BaselinePath
    }

    # ========================
    # FORENSIC TIMESTAMP FUNCTIONS
    # ========================

    function Get-PnPVolumeDeleteTime {
        param(
            [string]$StorageDeviceId,
            [string]$DiskRegId,
            [long]$Offset,
            [DateTime]$AfterTime
        )

        if (-not $StorageDeviceId -and $DiskRegId) {
            $hexOff = $Offset.ToString("X16")
            $StorageDeviceId = "STORAGE\VOLUME\$DiskRegId#$hexOff"
        }

        if (-not $StorageDeviceId) { return $null }

        try {
            $pnpEvents = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Id -eq 420 -and
                    $_.TimeCreated -gt $AfterTime -and
                    $_.Message -match [regex]::Escape($StorageDeviceId)
                }

            if (-not $pnpEvents -and $DiskRegId) {
                $pnpEvents = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Id -eq 420 -and
                        $_.TimeCreated -gt $AfterTime -and
                        $_.Message -match 'VOLUME' -and
                        $_.Message -match [regex]::Escape($DiskRegId)
                    }
            }

            if ($pnpEvents) {
                $sorted = @($pnpEvents | Sort-Object TimeCreated -Descending)
                return $sorted[0].TimeCreated
            }
        } catch { }

        return $null
    }

    function Get-VolumeHiddenTime {
        param(
            [string]$StorageDeviceId,
            [string]$DiskRegId,
            [long]$Offset,
            [string]$DriveLetter,
            [DateTime]$AfterTime
        )

        $bestTime = $null

        $pnpTime = Get-PnPVolumeDeleteTime -StorageDeviceId $StorageDeviceId -DiskRegId $DiskRegId -Offset $Offset -AfterTime $AfterTime
        if ($pnpTime) { $bestTime = $pnpTime }

        if (-not $bestTime -and $DriveLetter) {
            try {
                $pattern1 = "\b" + [regex]::Escape($DriveLetter) + ":\b"
                $pattern2 = "\\DosDevices\\" + [regex]::Escape($DriveLetter) + ":"
                $sysEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $AfterTime } -ErrorAction SilentlyContinue |
                    Where-Object {
                        $msg = $_.Message
                        $msg -and ($msg -match $pattern1 -or $msg -match $pattern2)
                    }
                if ($sysEvents) {
                    $sorted = @($sysEvents | Sort-Object TimeCreated -Descending)
                    $bestTime = $sorted[0].TimeCreated
                }
            } catch { }
        }

        return $bestTime
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

    # ========================
    # PARTITION ANALYSIS
    # ========================

    $usedLetters = @(Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne [char]0 } | Select-Object -ExpandProperty DriveLetter)
    $allLetters = 65..90 | ForEach-Object { [char]$_ }
    $availableLetters = $allLetters | Where-Object { $_ -notin $usedLetters -and $_ -notin @('A','B') }

    $visibleList = @()
    $hiddenList = @()

    foreach ($snap in $currentSnapshot) {
        if ($snap.DriveLetter -and -not $snap.IsHidden -and $snap.FileSystem) {
            $labelStr = if ($snap.Label) { " [$($snap.Label)]" } else { "" }
            $sizeStr = Format-Size $snap.Size
            $encStr = if ($snap.Encryption -and $snap.Encryption -ne "None") { " [ENCRYPTED: $($snap.Encryption)]" } else { "" }
            
            $visibleList += "[VISIBLE] Drive $($snap.DriveLetter):$labelStr ($($snap.FileSystem) - $sizeStr) - Disk $($snap.DiskNumber), Partition $($snap.PartitionNumber)$encStr"
        } elseif (-not $snap.IsSystem) {
            $lastLetter = Get-LastKnownDriveLetter -DiskNumber $snap.DiskNumber -PartitionNumber $snap.PartitionNumber -PartitionOffset $snap.Offset -PartitionGuid $snap.Guid

            if (-not $lastLetter -and $baseline) {
                $baseMatch = $baseline.Partitions | Where-Object {
                    $_.DiskNumber -eq $snap.DiskNumber -and
                    $_.PartitionNumber -eq $snap.PartitionNumber -and
                    $_.DriveLetter
                }
                if ($baseMatch) { $lastLetter = $baseMatch.DriveLetter }
            }

            $assignedDisplay = if ($snap.DriveLetter) { "$($snap.DriveLetter):" } else { "None" }
            $previousDisplay = if ($lastLetter) { "$lastLetter`:" } else { "Unknown" }
            $suggestedLetter = if ($lastLetter) { $lastLetter } else { if ($availableLetters) { [string]$availableLetters[0] } else { 'X' } }

            $hiddenTime = Get-VolumeHiddenTime -StorageDeviceId $snap.StorageDeviceId -DiskRegId $snap.DiskRegId -Offset $snap.Offset -DriveLetter $lastLetter -AfterTime $logonTime
            $hiddenTimeDisplay = if ($hiddenTime) { $hiddenTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }

            $vol = $null
            try {
                $p = Get-Partition -DiskNumber $snap.DiskNumber -PartitionNumber $snap.PartitionNumber -ErrorAction SilentlyContinue
                if ($p) { $vol = Get-Volume -Partition $p -ErrorAction SilentlyContinue }
            } catch { }

            $fsDisplay = if ($vol) { $vol.FileSystem } else { if ($snap.FileSystem) { $snap.FileSystem } else { "Unknown/None" } }
            $encStr = if ($snap.Encryption -and $snap.Encryption -ne "None") { " | Encryption: $($snap.Encryption)" } else { "" }

            $hiddenList += [PSCustomObject]@{
                DiskNumber      = $snap.DiskNumber
                PartitionNumber = $snap.PartitionNumber
                DriveLetter     = $assignedDisplay
                PreviousLetter  = $previousDisplay
                SuggestedLetter = $suggestedLetter
                Size            = Format-Size $snap.Size
                Type            = $snap.Type
                IsHidden        = $snap.IsHidden
                FileSystem      = $fsDisplay
                EncryptionStr   = $encStr
                HiddenTime      = $hiddenTimeDisplay
            }
        }
    }

    # ========================
    # DELETED PARTITIONS (BASELINE COMPARISON + ORPHANED LETTERS)
    # ========================

    $deletedList = @()

    if ($baseline -and -not $isNewSession) {
        foreach ($bp in $baseline.Partitions) {
            if ($bp.IsSystem) { continue }
            if (-not $bp.DriveLetter) { continue }

            $stillExists = $currentSnapshot | Where-Object {
                ($_.DiskNumber -eq $bp.DiskNumber -and $_.PartitionNumber -eq $bp.PartitionNumber -and $_.Offset -eq $bp.Offset) -or
                ($_.VolumeId -and $_.VolumeId -eq $bp.VolumeId) -or
                ($_.Guid -and $_.Guid -eq $bp.Guid -and $_.Guid -ne "")
            }

            $stillHasLetter = $currentSnapshot | Where-Object {
                $_.DriveLetter -eq $bp.DriveLetter
            }

            if (-not $stillHasLetter) {
                $deleteTime = Get-PnPVolumeDeleteTime -StorageDeviceId $bp.StorageDeviceId -DiskRegId $bp.DiskRegId -Offset $bp.Offset -AfterTime $logonTime

                if (-not $deleteTime) {
                    $deleteTime = Get-VolumeHiddenTime -StorageDeviceId $bp.StorageDeviceId -DiskRegId $bp.DiskRegId -Offset $bp.Offset -DriveLetter $bp.DriveLetter -AfterTime $logonTime
                }

                if ($stillExists) { continue }

                $timeStr = if ($deleteTime) { $deleteTime.ToString("yyyy-MM-dd HH:mm:ss") } else {
                    $st = if ($baseline.ScanTime -is [DateTime]) { $baseline.ScanTime } else { [DateTime]::Parse($baseline.ScanTime) }
                    "Between $($st.ToString('HH:mm:ss')) and $((Get-Date).ToString('HH:mm:ss'))"
                }
                $sizeStr = Format-Size $bp.Size

                $deletedList += [PSCustomObject]@{
                    Letter    = $bp.DriveLetter
                    Timestamp = $timeStr
                    Size      = $sizeStr
                    Type      = $bp.Type
                    SortTime  = if ($deleteTime) { $deleteTime } else { Get-Date }
                }
            }
        }
    }

    $activeDriveLetters = @($currentSnapshot | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter)
    $mountedDevices = Get-ItemProperty -Path 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
    if ($mountedDevices) {
        $mountedDevices.PSObject.Properties | Where-Object { $_.Name -match '^\\DosDevices\\([A-Z]):$' } | ForEach-Object {
            $letter = $Matches[1]
            if ($letter -notin $activeDriveLetters) {
                $v = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
                if (-not $v) {
                    $alreadyTracked = $deletedList | Where-Object { $_.Letter -eq $letter }
                    if (-not $alreadyTracked) {
                        $regData = $_.Value
                        $diskRegId = ""
                        $offset = [long]0

                        if ($regData -and $regData.Length -eq 12) {
                            $offset = [BitConverter]::ToInt64($regData, 4)
                        }

                        $deleteTime = Get-VolumeHiddenTime -StorageDeviceId "" -DiskRegId $diskRegId -Offset $offset -DriveLetter $letter -AfterTime $logonTime
                        
                        # MODIFICA: Se deleteTime è nullo, significa che è un residuo vecchio (es. USB staccata giorni fa).
                        # Non inseriamo nella lista deletedList se non abbiamo un evento specifico post-logon.
                        if ($deleteTime) {
                            $timeStr = $deleteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            $deletedList += [PSCustomObject]@{
                                Letter    = $letter
                                Timestamp = $timeStr
                                Size      = "Unknown"
                                Type      = "Unknown"
                                SortTime  = $deleteTime
                            }
                        }
                    }
                }
            }
        }
    }

    # ========================
    # OUTPUT
    # ========================

    $headerAscii = @"
  ____  _     _                     _     ____       _           _             
 |  _ \(_)___| | ___ __   __ _ _ __| |_  |  _ \  ___| |_ ___  ___| |_ ___  _ __ 
 | | | | / __| |/ / '_ \ / _`` | '__| __| | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 | |_| | \__ \   <| |_) | (_| | |  | |_  | |_| |  __/ ||  __/ (__| || (_) | |   
 |____/|_|___/_|\_\ .__/ \__,_|_|   \__| |____/ \___|\__\___|\___|\__\___/|_|   
                  |_|                                                          
"@
    Write-Host $headerAscii -ForegroundColor Cyan
    Write-Host " Made by yungestlavi $([char]::ConvertFromUtf32(0x1F49C))" -ForegroundColor Magenta
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
    if ($deletedList.Count -gt 0) {
        $deletedList | Sort-Object SortTime -Descending | ForEach-Object {
            Write-Host "  [DELETED] Drive $($_.Letter): - Timestamp: $($_.Timestamp) - Size: $($_.Size)" -ForegroundColor Red
        }
    } else {
        Write-Host "  No partition deletions detected since logon." -ForegroundColor Gray
    }

    Write-Host "`n[3/3] HIDDEN / INACCESSIBLE USER PARTITIONS" -ForegroundColor Cyan
    if ($hiddenList.Count -gt 0) {
        foreach ($h in $hiddenList) {
            $targetLetter = $h.SuggestedLetter

            Write-Host "  [HIDDEN/INACCESSIBLE] Disk $($h.DiskNumber), Partition $($h.PartitionNumber) | Original Letter: $($h.PreviousLetter) | Assigned Letter: $($h.DriveLetter) | Size: $($h.Size) | Type: $($h.Type) | FileSystem: $($h.FileSystem)$($h.EncryptionStr) | Hidden at: $($h.HiddenTime)" -ForegroundColor Yellow
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
