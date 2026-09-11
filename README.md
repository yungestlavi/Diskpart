# Diskpart Detector

Diskpart Detector is an advanced forensic PowerShell script designed to monitor, detect, and reveal partition changes on Windows systems. It tracks visible partitions, detects partitions deleted post-logon, and uncovers hidden or inaccessible user partitions, extracting their original drive letters even if they were intentionally removed using tools like diskpart.

## Quick Start

You can run the script directly from an elevated PowerShell session without downloading the file:

```
irm https://raw.githubusercontent.com/yungestlavi/Diskpart/main/Diskpart%20detection.ps1 | iex
```

*(Note: Ensure the URL matches your actual GitHub repository name and path)*

## Features

- **Visible Partitions**: Lists all currently accessible partitions along with their drive letter, label, filesystem, and size.
- **Forensic Deletion Tracking**: Identifies partitions that were deleted during the current user session by analyzing Windows Event Logs (Security, Sysmon, Partition Diagnostics, and System).
- **Hidden Partition Recovery**: Detects existing partitions that are inaccessible to the user (e.g., hidden via diskpart). It queries the registry (including the Windows Search VolumeInfoCache) to accurately recover the original drive letter assigned before the partition was hidden.
- **Recovery Instructions**: Provides step-by-step PowerShell and Diskpart commands to easily restore access to any detected hidden partition.

## Requirements

- Windows 10 or later.
- PowerShell 5.1 or later.
- The script must be executed with Administrator privileges.

## Usage

If you prefer to download and run the script locally:

1. Open PowerShell as Administrator.
2. Navigate to the directory containing the script.
3. Execute the script:
   `powershell
   .\Diskpart detection.ps1
   `

## Output Categories

1. **VISIBLE & ACCESSIBLE PARTITIONS**: Standard partitions currently in use by the OS.
2. **REMOVED PARTITIONS (POST-LOGON)**: Drives that have been deleted or removed since the system booted, complete with timestamps of the deletion events.
3. **HIDDEN / INACCESSIBLE USER PARTITIONS**: Partitions that exist on the disk but have no drive letter or are explicitly hidden. Standard OS partitions (Recovery, EFI, Reserved) are safely excluded.

## Author

Made by yungestlavi

- GitHub: github.com/yungestlavi
- Discord: yungestlavi
- YouTube: yungestlavi
