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
        $sessions = @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction SilentlyContinue |
            Where-Object { $_.LogonType -in @(2, 10, 11) -and $_.StartTime } |
            Sort-Object StartTime)
        if ($sessions.Count -gt 0) {
            $sinceBoot = @($sessions | Where-Object { $_.StartTime -ge $bootTime })
            if ($sinceBoot.Count -gt 0) { $logonTime = $sinceBoot[0].StartTime }
            else { $logonTime = $sessions[0].StartTime }
        }
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
    # DELETED PARTITION FORENSICS (LOW LEVEL HELPERS)
    # ========================

    function Convert-HexStringToBytes {
        param([string]$Hex)
        if (-not $Hex) { return $null }
        $clean = ($Hex -replace '[^0-9A-Fa-f]', '')
        if ($clean.Length -lt 2) { return $null }
        $len = [int]($clean.Length / 2)
        $bytes = New-Object byte[] $len
        try {
            for ($i = 0; $i -lt $len; $i++) {
                $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
            }
        } catch { return $null }
        return $bytes
    }

    function Get-GuidFromBytes {
        param([byte[]]$Bytes, [int]$Offset)
        if (-not $Bytes -or ($Offset + 16) -gt $Bytes.Length) { return "" }
        try {
            $slice = New-Object byte[] 16
            [Array]::Copy($Bytes, $Offset, $slice, 0, 16)
            return (New-Object System.Guid (,$slice)).ToString()
        } catch { return "" }
    }

    # Decodes a DRIVE_LAYOUT_INFORMATION_EX blob (the PartitionTable field of
    # Microsoft-Windows-Partition/Diagnostic event 1006).
    # Header = 48 bytes, each PARTITION_INFORMATION_EX entry = 144 bytes.
    function ConvertFrom-DriveLayoutBlob {
        param([byte[]]$Blob)

        $layout = [PSCustomObject]@{
            Style      = "Unknown"
            Signature  = [uint32]0
            DiskId     = ""
            Partitions = @()
        }
        if (-not $Blob -or $Blob.Length -lt 48) { return $layout }

        try {
            $style = [BitConverter]::ToUInt32($Blob, 0)
            $count = [int][BitConverter]::ToUInt32($Blob, 4)

            if ($style -eq 0) {
                $layout.Style = "MBR"
                $layout.Signature = [BitConverter]::ToUInt32($Blob, 8)
            } elseif ($style -eq 1) {
                $layout.Style = "GPT"
                $layout.DiskId = Get-GuidFromBytes -Bytes $Blob -Offset 8
            } else {
                $layout.Style = "RAW"
            }

            $entrySize = 144
            $base = 48
            $maxEntries = [int][Math]::Floor(($Blob.Length - $base) / $entrySize)
            if ($count -lt 0 -or $count -gt $maxEntries) { $count = $maxEntries }

            $parts = @()
            for ($i = 0; $i -lt $count; $i++) {
                $o = $base + ($i * $entrySize)
                if (($o + $entrySize) -gt $Blob.Length) { break }

                $pStyle = [BitConverter]::ToUInt32($Blob, $o)
                $start  = [BitConverter]::ToInt64($Blob, $o + 8)
                $length = [BitConverter]::ToInt64($Blob, $o + 16)
                $number = [int][BitConverter]::ToUInt32($Blob, $o + 24)
                if ($length -le 0) { continue }

                $partId  = ""
                $typeStr = "Unknown"

                if ($pStyle -eq 1) {
                    $typeGuid = (Get-GuidFromBytes -Bytes $Blob -Offset ($o + 32)) -replace '[{}]', ''
                    $partId   = Get-GuidFromBytes -Bytes $Blob -Offset ($o + 48)
                    switch ($typeGuid.ToLower()) {
                        'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' { $typeStr = "Basic" }
                        'de94bba4-06d1-4d40-a16a-bfd50179d6ac' { $typeStr = "Recovery" }
                        'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' { $typeStr = "System (EFI)" }
                        'e3c9e316-0b5c-4db8-817d-f92df00215ae' { $typeStr = "Reserved (MSR)" }
                        default                                { $typeStr = "GPT" }
                    }
                } else {
                    $mbrType = $Blob[$o + 32]
                    $partId  = Get-GuidFromBytes -Bytes $Blob -Offset ($o + 40)
                    switch ($mbrType) {
                        0x07    { $typeStr = "Basic (NTFS/exFAT)" }
                        0x0B    { $typeStr = "Basic (FAT32)" }
                        0x0C    { $typeStr = "Basic (FAT32 LBA)" }
                        0x27    { $typeStr = "Recovery" }
                        0xEE    { $typeStr = "GPT Protective" }
                        default { $typeStr = ("MBR 0x{0:X2}" -f $mbrType) }
                    }
                }

                $parts += [PSCustomObject]@{
                    Number      = $number
                    Offset      = $start
                    Size        = $length
                    PartitionId = $partId
                    TypeName    = $typeStr
                }
            }
            $layout.Partitions = $parts
        } catch { }

        return $layout
    }

    # Reads the disk layout history recorded by Windows itself.
    # Every time a partition table changes (create / delete / clean) Windows
    # writes a new 1006 event containing the FULL partition table at that moment.
    function Get-DiskLayoutHistory {
        param([int]$MaxEvents = 600)

        $history = @()
        $events = $null
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Partition/Diagnostic'; Id = 1006 } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        } catch { $events = $null }
        if (-not $events -or $events.Count -eq 0) { return $history }

        foreach ($e in $events) {
            try {
                $xml = [xml]$e.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) {
                    if ($d -is [System.Xml.XmlElement]) {
                        $fieldName = $d.GetAttribute('Name')
                        if ($fieldName) { $data[[string]$fieldName] = [string]$d.InnerText }
                    }
                }

                $blob = $null
                if ($data.ContainsKey('PartitionTable')) {
                    $blob = Convert-HexStringToBytes -Hex $data['PartitionTable']
                }

                if ($blob) {
                    $layout = ConvertFrom-DriveLayoutBlob -Blob $blob
                    if ($layout.Style -ne "Unknown") {
                        $diskNumber = -1
                        if ($data.ContainsKey('DiskNumber') -and $data['DiskNumber'] -match '^\d+$') { $diskNumber = [int]$data['DiskNumber'] }

                        $serial = ""
                        if ($data.ContainsKey('SerialNumber') -and $data['SerialNumber']) { $serial = ([string]$data['SerialNumber']).Trim() }

                        # identity taken from the partition table itself: it stays stable
                        # even when an event does not carry the serial number
                        $key = "DISK:$diskNumber"
                        if ($layout.DiskId) { $key = "ID:$($layout.DiskId)" }
                        elseif ($layout.Signature -ne 0) { $key = "SIG:$($layout.Signature)" }
                        elseif ($serial) { $key = "SN:$serial" }

                        $history += [PSCustomObject]@{
                            Time       = $e.TimeCreated
                            DiskNumber = $diskNumber
                            Serial     = $serial
                            Key        = $key
                            Layout     = $layout
                        }
                    }
                }
            } catch { }
        }

        return $history
    }

    # Kernel-PnP "device deleted" records for volume devices: gives the exact
    # second the volume object was torn down, plus the byte offset in the
    # device instance id.
    function Get-PnpVolumeDeletionRecords {
        param([DateTime]$AfterTime)

        $records = @()
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; Id = 420; StartTime = $AfterTime } -ErrorAction SilentlyContinue)
        } catch { $events = @() }

        foreach ($e in $events) {
            $instance = ""
            try {
                $xml = [xml]$e.ToXml()
                foreach ($d in $xml.Event.EventData.Data) {
                    if ($d -is [System.Xml.XmlElement]) { $instance = "$instance $($d.InnerText)" }
                    else { $instance = "$instance $d" }
                }
            } catch { }

            $msg = ""
            try { $msg = [string]$e.Message } catch { }

            $text = "$instance $msg"
            if ($text -notmatch 'VOLUME') { continue }

            $offset = [long]-1
            $signature = [uint32]0

            $m = [regex]::Match($text, 'Signature([0-9A-Fa-f]+)Offset([0-9A-Fa-f]+)')
            if ($m.Success) {
                try { $signature = [Convert]::ToUInt32($m.Groups[1].Value, 16) } catch { }
                try { $offset = [Convert]::ToInt64($m.Groups[2].Value, 16) } catch { }
            } else {
                $m2 = [regex]::Match($text, '#([0-9A-Fa-f]{8,16})')
                if ($m2.Success) {
                    try { $offset = [Convert]::ToInt64($m2.Groups[1].Value, 16) } catch { }
                }
            }

            $records += [PSCustomObject]@{
                Time      = $e.TimeCreated
                Offset    = $offset
                Signature = $signature
                Instance  = $text
            }
        }

        return $records
    }

    # Rebuilds the drive letter of a partition that no longer exists:
    #  1) HKLM\SYSTEM\MountedDevices  (MBR = signature + offset, GPT = DMIO:ID: + partition GUID)
    #  2) the saved baseline of this session
    # Reads HKLM\SYSTEM\MountedDevices once.
    #   \DosDevices\X:      -> drive letter
    #   \??\Volume{GUID}    -> volume GUID
    # Both point at the same binary value, so a letter can be linked to its volume GUID.
    # Binary value: 12 bytes = MBR (disk signature + byte offset)
    #               24 bytes = GPT ("DMIO:ID:" + partition GUID)
    function Get-MountedDeviceEntries {
        $entries = @()
        $md = $null
        try { $md = Get-ItemProperty -Path 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue } catch { }
        if (-not $md) { return $entries }

        foreach ($prop in $md.PSObject.Properties) {
            $data = $prop.Value
            if ($data -isnot [byte[]]) { continue }

            $name = [string]$prop.Name
            $kind = ""
            $letter = ""
            $volumeGuid = ""

            $mL = [regex]::Match($name, '^\\DosDevices\\([A-Za-z]):$')
            $mV = [regex]::Match($name, '^\\\?\?\\Volume\{([0-9A-Fa-f\-]+)\}$')

            if ($mL.Success) {
                $kind = "Letter"
                $letter = $mL.Groups[1].Value.ToUpper()
            } elseif ($mV.Success) {
                $kind = "Volume"
                $volumeGuid = $mV.Groups[1].Value.ToLower()
            } else {
                continue
            }

            $offset    = [long]-1
            $signature = [uint32]0
            $partGuid  = ""

            if ($data.Length -eq 12) {
                try {
                    $signature = [BitConverter]::ToUInt32($data, 0)
                    $offset    = [BitConverter]::ToInt64($data, 4)
                } catch { }
            } elseif ($data.Length -ge 24) {
                $prefix = ""
                try { $prefix = [Text.Encoding]::ASCII.GetString($data, 0, 8) } catch { }
                if ($prefix -eq 'DMIO:ID:') {
                    $partGuid = ((Get-GuidFromBytes -Bytes $data -Offset 8) -replace '[{}]', '').ToLower()
                }
            }

            $hex = ""
            try { $hex = [BitConverter]::ToString($data) } catch { }

            $entries += [PSCustomObject]@{
                Kind          = $kind
                Letter        = $letter
                VolumeGuid    = $volumeGuid
                Hex           = $hex
                Offset        = $offset
                Signature     = $signature
                PartitionGuid = $partGuid
            }
        }

        return $entries
    }

    function Find-LetterEntryForPartition {
        param($MdLetters, [long]$Offset, [uint32]$Signature, [string]$PartitionGuid)

        $wanted = (([string]$PartitionGuid) -replace '[{}]', '').ToLower()
        if ($wanted -eq '00000000-0000-0000-0000-000000000000') { $wanted = "" }

        $hit = $null
        foreach ($e in $MdLetters) {
            if ($hit) { break }
            if ($wanted -and $e.PartitionGuid -and $e.PartitionGuid -eq $wanted) { $hit = $e }
            elseif ($Signature -ne 0 -and $e.Signature -eq $Signature -and $e.Offset -ge 0 -and $e.Offset -eq $Offset) { $hit = $e }
        }
        return $hit
    }

    function Find-LetterInBaseline {
        param($Baseline, [long]$Offset, [string]$PartitionGuid)

        if (-not $Baseline -or -not $Baseline.Partitions) { return "" }

        $wanted = (([string]$PartitionGuid) -replace '[{}]', '').ToLower()
        if ($wanted -eq '00000000-0000-0000-0000-000000000000') { $wanted = "" }

        $found = ""
        foreach ($bp in $Baseline.Partitions) {
            if ($found) { break }
            if (-not $bp.DriveLetter) { continue }

            $bg = (([string]$bp.Guid) -replace '[{}]', '').ToLower()
            if ($wanted -and $bg -and $bg -eq $wanted) {
                $found = ([string]$bp.DriveLetter).ToUpper()
            } else {
                $bo = [long]-1
                try { $bo = [long]$bp.Offset } catch { }
                if ($bo -ge 0 -and $bo -eq $Offset) { $found = ([string]$bp.DriveLetter).ToUpper() }
            }
        }
        return $found
    }

    # Exact teardown time of ONE volume device: matched either on its own volume GUID
    # or on its byte offset, never on a generic text search in the System log.
    function Get-PnpTimeForVolume {
        param($PnpRecords, $VolumeGuids, [long]$Offset)

        # the volume GUID is unique, the byte offset is not (two disks can share it),
        # so the GUID always wins and the offset is only a second choice
        $guidHits = @()
        if ($VolumeGuids) {
            foreach ($r in $PnpRecords) {
                $instLower = ([string]$r.Instance).ToLower()
                foreach ($g in $VolumeGuids) {
                    if ($g -and $instLower.Contains([string]$g)) { $guidHits += $r; break }
                }
            }
        }
        if ($guidHits.Count -gt 0) { return (@($guidHits | Sort-Object Time))[0].Time }

        if ($Offset -ge 0) {
            $offsetHits = @($PnpRecords | Where-Object { $_.Offset -ge 0 -and $_.Offset -eq $Offset })
            if ($offsetHits.Count -gt 0) { return (@($offsetHits | Sort-Object Time))[0].Time }
        }

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
    # DELETED PARTITIONS (EVENT LOG DIFF + BASELINE COMPARISON + ORPHANED LETTERS)
    # ========================

    $deletedList     = @()
    $deletedKeys     = @{}
    $reportedLetters = @{}

    # --- what is alive right now ---
    $presentSerials     = @{}
    $presentDiskNumbers = @{}
    try {
        foreach ($d in @(Get-Disk -ErrorAction SilentlyContinue)) {
            $presentDiskNumbers[[int]$d.Number] = $true
            if ($d.SerialNumber) { $presentSerials[([string]$d.SerialNumber).Trim()] = $true }
        }
    } catch { }

    $liveOffsets = @{}
    $liveGuids   = @{}
    foreach ($cp in $currentSnapshot) {
        $liveOffsets["$($cp.Offset)"] = $true
        if ($cp.Guid) { $liveGuids[(([string]$cp.Guid) -replace '[{}]', '').ToLower()] = $true }
    }

    $mdEntries     = @(Get-MountedDeviceEntries)
    $mdLetters     = @($mdEntries | Where-Object { $_.Kind -eq 'Letter' })
    $pnpDeletions  = @(Get-PnpVolumeDeletionRecords -AfterTime $logonTime)
    $layoutHistory = @(Get-DiskLayoutHistory)

    # --- 1) partition table diff: every single change has its own 1006 event,
    #        so every deletion gets its own exact timestamp ---
    $layoutDeletions = @()
    if ($layoutHistory.Count -gt 0) {
        foreach ($group in ($layoutHistory | Group-Object -Property Key)) {
            $seq = @($group.Group | Sort-Object Time)
            for ($i = 1; $i -lt $seq.Count; $i++) {
                $prev = $seq[$i - 1]
                $cur  = $seq[$i]
                if ($cur.Time -le $logonTime) { continue }

                $prevParts = @($prev.Layout.Partitions)
                $curParts  = @($cur.Layout.Partitions)
                if ($prevParts.Count -eq 0) { continue }

                # a disk that vanished completely was unplugged, not wiped
                # (if the disk is still attached, an empty table means "diskpart clean")
                if ($curParts.Count -eq 0) {
                    $diskStillAttached = $false
                    if ($cur.Serial -and $presentSerials.ContainsKey($cur.Serial)) { $diskStillAttached = $true }
                    if ($cur.DiskNumber -ge 0 -and $presentDiskNumbers.ContainsKey($cur.DiskNumber)) { $diskStillAttached = $true }
                    if (-not $diskStillAttached) { continue }
                }

                foreach ($pp in $prevParts) {
                    $ppId = (([string]$pp.PartitionId) -replace '[{}]', '').ToLower()
                    if ($ppId -eq '00000000-0000-0000-0000-000000000000') { $ppId = "" }

                    $stillThere = $curParts | Where-Object {
                        ($_.Offset -eq $pp.Offset) -or
                        ($ppId -and ((([string]$_.PartitionId) -replace '[{}]', '').ToLower()) -eq $ppId)
                    }
                    if ($stillThere) { continue }

                    # the timestamp IS the event that no longer contains the partition:
                    # one event per diskpart operation, so no two deletions share a time
                    $layoutDeletions += [PSCustomObject]@{
                        Time        = $cur.Time
                        Offset      = $pp.Offset
                        Size        = $pp.Size
                        PartitionId = $pp.PartitionId
                        TypeName    = $pp.TypeName
                        Signature   = $prev.Layout.Signature
                        DiskNumber  = $prev.DiskNumber
                    }
                }
            }
        }
    }

    foreach ($rec in @($layoutDeletions | Sort-Object Time)) {
        $key = "$($rec.Offset)|$($rec.PartitionId)|$($rec.Time.ToString('yyyyMMddHHmmssfff'))"
        if ($deletedKeys.ContainsKey($key)) { continue }
        $deletedKeys[$key] = $true

        $letter = ""
        $mdHit = Find-LetterEntryForPartition -MdLetters $mdLetters -Offset $rec.Offset -Signature $rec.Signature -PartitionGuid $rec.PartitionId
        if ($mdHit) { $letter = $mdHit.Letter }
        if (-not $letter) { $letter = Find-LetterInBaseline -Baseline $baseline -Offset $rec.Offset -PartitionGuid $rec.PartitionId }
        if ($letter) { $reportedLetters[$letter] = $true } else { $letter = "Unknown" }

        $deletedList += [PSCustomObject]@{
            Letter    = $letter
            Timestamp = $rec.Time.ToString("yyyy-MM-dd HH:mm:ss")
            Size      = Format-Size $rec.Size
            Type      = $rec.TypeName
            SortTime  = $rec.Time
            Offset    = $rec.Offset
        }
    }

    # --- 2) fallback: baseline saved earlier in this same session ---
    if ($baseline -and -not $isNewSession) {
        foreach ($bp in $baseline.Partitions) {
            if ($bp.IsSystem) { continue }

            $stillExists = $currentSnapshot | Where-Object {
                ($_.DiskNumber -eq $bp.DiskNumber -and $_.Offset -eq $bp.Offset) -or
                ($_.VolumeId -and $_.VolumeId -eq $bp.VolumeId) -or
                ($_.Guid -and $bp.Guid -and $_.Guid -eq $bp.Guid)
            }
            if ($stillExists) { continue }

            $bpLetter = ""
            if ($bp.DriveLetter) { $bpLetter = ([string]$bp.DriveLetter).ToUpper() }

            $already = $deletedList | Where-Object {
                ($_.Offset -eq $bp.Offset) -or ($bpLetter -and $_.Letter -eq $bpLetter)
            }
            if ($already) { continue }

            # exact time for this specific volume only
            $bpGuid = (([string]$bp.Guid) -replace '[{}]', '').ToLower()
            $volGuids = @()
            $mdHit = Find-LetterEntryForPartition -MdLetters $mdLetters -Offset ([long]$bp.Offset) -Signature ([uint32]0) -PartitionGuid $bpGuid
            if ($mdHit) { $volGuids = @($mdEntries | Where-Object { $_.Kind -eq 'Volume' -and $_.Hex -eq $mdHit.Hex } | ForEach-Object { $_.VolumeGuid }) }

            $deleteTime = Get-PnpTimeForVolume -PnpRecords $pnpDeletions -VolumeGuids $volGuids -Offset ([long]$bp.Offset)

            $scanTime = Get-Date
            try {
                if ($baseline.ScanTime -is [DateTime]) { $scanTime = $baseline.ScanTime }
                elseif ($baseline.ScanTime) { $scanTime = [DateTime]::Parse($baseline.ScanTime) }
            } catch { $scanTime = Get-Date }

            $timeStr = if ($deleteTime) { $deleteTime.ToString("yyyy-MM-dd HH:mm:ss") } else {
                "Unknown (Between $($scanTime.ToString('HH:mm:ss')) and $((Get-Date).ToString('HH:mm:ss')))"
            }

            $letter = $bpLetter
            if (-not $letter -and $mdHit) { $letter = $mdHit.Letter }
            if ($letter) { $reportedLetters[$letter] = $true } else { $letter = "Unknown" }

            $deletedList += [PSCustomObject]@{
                Letter    = $letter
                Timestamp = $timeStr
                Size      = Format-Size $bp.Size
                Type      = $bp.Type
                SortTime  = if ($deleteTime) { $deleteTime } else { $scanTime }
                Offset    = [long]$bp.Offset
            }
        }
    }

    # --- 3) fallback: drive letters still registered in MountedDevices whose volume is gone.
    #        The time comes from the Kernel-PnP teardown of THAT volume (matched by its own
    #        volume GUID / byte offset). No evidence for this specific volume = not reported,
    #        so an old unplugged drive never borrows someone else's timestamp. ---
    foreach ($e in $mdLetters) {
        if ($reportedLetters.ContainsKey($e.Letter)) { continue }

        if ($e.PartitionGuid) {
            if ($liveGuids.ContainsKey($e.PartitionGuid)) { continue }
        } elseif ($e.Offset -ge 0) {
            if ($liveOffsets.ContainsKey("$($e.Offset)")) { continue }
        } else {
            continue
        }

        if (Get-Volume -DriveLetter $e.Letter -ErrorAction SilentlyContinue) { continue }

        $volGuids = @($mdEntries | Where-Object { $_.Kind -eq 'Volume' -and $_.Hex -eq $e.Hex } | ForEach-Object { $_.VolumeGuid })
        $deleteTime = Get-PnpTimeForVolume -PnpRecords $pnpDeletions -VolumeGuids $volGuids -Offset $e.Offset
        if (-not $deleteTime) { continue }

        $reportedLetters[$e.Letter] = $true

        $deletedList += [PSCustomObject]@{
            Letter    = $e.Letter
            Timestamp = $deleteTime.ToString("yyyy-MM-dd HH:mm:ss")
            Size      = "Unknown"
            Type      = "Unknown"
            SortTime  = $deleteTime
            Offset    = $e.Offset
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
