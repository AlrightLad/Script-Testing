<#
.SYNOPSIS
    Server Storage Usage Growth Tracking Script for Ninja RMM

.DESCRIPTION
    Collects daily storage metrics from servers, maintains a 60-day rolling history,
    calculates growth trends using linear regression, and updates Ninja RMM custom fields.
    Critical trends trigger Ninja event log entries for automated alerting.

.PARAMETER Verbose
    Enable detailed diagnostic output for troubleshooting

.NOTES
    Version: 1.0
    Ticket: 1123004 - DTC Internal
    Requires: PowerShell 5.1+
    Run As: SYSTEM
    Schedule: Daily at 10:00 PM

.EXAMPLE
    .\Storage-Growth-Monitor.ps1
    Standard execution in Ninja context

.EXAMPLE
    .\Storage-Growth-Monitor.ps1 -Verbose
    Execution with detailed diagnostic output
#>

[CmdletBinding()]
param()

#region Configuration
$script:Config = @{
    Version = "1.0"
    StoragePath = "C:\ProgramData\NinjaRMM\StorageMetrics"
    HistoryFile = "storage_history.json"
    BackupFile = "storage_history.json.bak"
    LogFile = "storage_monitor.log"
    HistoryRetentionDays = 65
    LogRetentionDays = 90
    OfflineRemovalDays = 30
    MinDataPoints = 7
    FullConfidencePoints = 30
    MaxDataDrives = 3
    MinDriveSizeGB = 1
    MaxDaysUntilFull = 1825
    CriticalDaysThreshold = 30
    AttentionDaysThreshold = 90
    CriticalUsagePercent = 95
    MinGrowthRateGBPerDay = 0.1
    EventLogSource = "StorageGrowthMonitor"
    ExcludedLabels = @("Recovery", "EFI", "System Reserved", "SYSTEM", "Windows RE")
    ExcludedFileSystems = @("FAT", "FAT32", "RAW")
}
#endregion

#region Logging Functions
function Get-FormattedTimestamp {
    $now = Get-Date
    $tz = [System.TimeZoneInfo]::Local.Id
    $tzAbbr = if ($now.IsDaylightSavingTime()) {
        [System.TimeZoneInfo]::Local.DaylightName -replace '[^A-Z]', ''
    } else {
        [System.TimeZoneInfo]::Local.StandardName -replace '[^A-Z]', ''
    }
    if ([string]::IsNullOrEmpty($tzAbbr)) { $tzAbbr = "UTC" }
    return "[{0:yyyy-MM-dd HH:mm:ss} $tzAbbr]" -f $now
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [switch]$VerboseOnly
    )

    if ($VerboseOnly -and -not $VerbosePreference -eq 'Continue') {
        return
    }

    $timestamp = Get-FormattedTimestamp
    $prefix = if ($VerboseOnly) { "[VERBOSE] " } else { "" }
    $logEntry = "$timestamp $prefix$Message"

    # Output to console
    Write-Host $logEntry

    # Append to log buffer for later file write
    $script:LogBuffer += $logEntry
}

function Initialize-LogBuffer {
    $script:LogBuffer = @()
}

function Save-LogFile {
    $logPath = Join-Path $script:Config.StoragePath $script:Config.LogFile

    try {
        # Read existing log and prune old entries
        $cutoffDate = (Get-Date).AddDays(-$script:Config.LogRetentionDays)
        $existingEntries = @()
        $prunedCount = 0

        if (Test-Path $logPath) {
            $existingContent = Get-Content $logPath -ErrorAction SilentlyContinue
            foreach ($line in $existingContent) {
                # Try to parse timestamp from line
                if ($line -match '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
                    $lineDate = [DateTime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss", $null)
                    if ($lineDate -ge $cutoffDate) {
                        $existingEntries += $line
                    } else {
                        $prunedCount++
                    }
                } else {
                    # Keep lines with unparseable timestamps
                    $existingEntries += $line
                }
            }
        }

        if ($prunedCount -gt 0) {
            Write-Log "Log file pruning: $prunedCount entries removed (older than $($script:Config.LogRetentionDays) days)" -VerboseOnly
        }

        # Combine existing and new entries
        $allEntries = $existingEntries + $script:LogBuffer

        # Write to file
        $allEntries | Set-Content -Path $logPath -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Host "$(Get-FormattedTimestamp) Warning: Could not write to log file: $_"
    }
}
#endregion

#region Event Log Functions
function Initialize-EventLogSource {
    $source = $script:Config.EventLogSource

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            Write-Log "Registering event log source: $source" -VerboseOnly
            New-EventLog -LogName Application -Source $source -ErrorAction Stop
            Write-Log "Event log source registered successfully" -VerboseOnly
        }
        return $true
    }
    catch {
        Write-Log "Warning: Could not register event log source: $_"
        return $false
    }
}

function Write-StorageEvent {
    param(
        [int]$EventId,
        [string]$Message,
        [System.Diagnostics.EventLogEntryType]$EntryType = [System.Diagnostics.EventLogEntryType]::Warning
    )

    try {
        Write-EventLog -LogName Application -Source $script:Config.EventLogSource -EventId $EventId -EntryType $EntryType -Message $Message
        return $true
    }
    catch {
        Write-Log "Warning: Could not write to event log: $_"
        return $false
    }
}
#endregion

#region Storage Path Functions
function Initialize-StoragePath {
    $path = $script:Config.StoragePath

    if (-not (Test-Path $path)) {
        try {
            Write-Log "Creating storage folder: $path" -VerboseOnly
            New-Item -Path $path -ItemType Directory -Force -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            Write-Log "CRITICAL: Could not create storage folder: $_"
            return $false
        }
    }
    return $true
}
#endregion

#region JSON History Functions
function Get-HistoryFilePath {
    return Join-Path $script:Config.StoragePath $script:Config.HistoryFile
}

function Get-BackupFilePath {
    return Join-Path $script:Config.StoragePath $script:Config.BackupFile
}

function Initialize-HistoryData {
    return @{
        version = $script:Config.Version
        deviceId = $env:COMPUTERNAME
        lastUpdated = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
        excessDriveAlertSent = $false
        drives = @{}
    }
}

function Load-HistoryData {
    $historyPath = Get-HistoryFilePath

    if (-not (Test-Path $historyPath)) {
        Write-Log "No existing history file, creating new" -VerboseOnly
        return Initialize-HistoryData
    }

    try {
        $fileInfo = Get-Item $historyPath
        Write-Log "Existing JSON: Yes ($([math]::Round($fileInfo.Length / 1KB, 1)) KB)" -VerboseOnly

        $content = Get-Content $historyPath -Raw -Encoding UTF8
        $data = $content | ConvertFrom-Json

        # Convert PSCustomObject to hashtable for easier manipulation
        $hashtable = Initialize-HistoryData
        $hashtable.version = $data.version
        $hashtable.deviceId = $data.deviceId
        $hashtable.lastUpdated = $data.lastUpdated
        $hashtable.excessDriveAlertSent = if ($null -ne $data.excessDriveAlertSent) { $data.excessDriveAlertSent } else { $false }

        # Convert drives
        if ($data.drives) {
            foreach ($prop in $data.drives.PSObject.Properties) {
                $driveLetter = $prop.Name
                $driveData = $prop.Value

                $hashtable.drives[$driveLetter] = @{
                    volumeLabel = $driveData.volumeLabel
                    totalSizeGB = $driveData.totalSizeGB
                    driveType = $driveData.driveType
                    alertSent = if ($null -ne $driveData.alertSent) { $driveData.alertSent } else { $false }
                    status = $driveData.status
                    lastSeen = $driveData.lastSeen
                    history = @()
                }

                # Convert history array
                if ($driveData.history) {
                    foreach ($entry in $driveData.history) {
                        $hashtable.drives[$driveLetter].history += @{
                            timestamp = $entry.timestamp
                            usedGB = $entry.usedGB
                            freeGB = $entry.freeGB
                            usagePercent = $entry.usagePercent
                        }
                    }
                }
            }
        }

        return $hashtable
    }
    catch {
        Write-Log "Warning: History file corrupted, renaming and starting fresh"
        $corruptedPath = $historyPath + ".corrupted"
        try {
            Move-Item -Path $historyPath -Destination $corruptedPath -Force
        }
        catch {
            Write-Log "Warning: Could not rename corrupted file: $_"
        }
        return Initialize-HistoryData
    }
}

function Save-HistoryData {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Data
    )

    $historyPath = Get-HistoryFilePath
    $backupPath = Get-BackupFilePath

    # Backup existing file
    if (Test-Path $historyPath) {
        try {
            Copy-Item -Path $historyPath -Destination $backupPath -Force
        }
        catch {
            Write-Log "Warning: Could not create backup file: $_"
        }
    }

    # Convert hashtable to proper structure for JSON
    $jsonObject = @{
        version = $Data.version
        deviceId = $Data.deviceId
        lastUpdated = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
        excessDriveAlertSent = $Data.excessDriveAlertSent
        drives = @{}
    }

    foreach ($driveLetter in $Data.drives.Keys) {
        $drive = $Data.drives[$driveLetter]
        $jsonObject.drives[$driveLetter] = @{
            volumeLabel = $drive.volumeLabel
            totalSizeGB = $drive.totalSizeGB
            driveType = $drive.driveType
            alertSent = $drive.alertSent
            status = $drive.status
            lastSeen = $drive.lastSeen
            history = $drive.history
        }
    }

    # Retry logic for locked file
    $maxRetries = 3
    $retryDelay = 5

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $jsonObject | ConvertTo-Json -Depth 10 | Set-Content -Path $historyPath -Encoding UTF8 -ErrorAction Stop
            return $true
        }
        catch {
            if ($i -lt $maxRetries - 1) {
                Write-Log "Warning: History file locked, retrying in $retryDelay seconds..."
                Start-Sleep -Seconds $retryDelay
            }
            else {
                Write-Log "Error: Could not save history file after $maxRetries attempts: $_"
                return $false
            }
        }
    }
    return $false
}
#endregion

#region Drive Discovery Functions
function Get-OSDriveLetter {
    try {
        $osDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
        Write-Log "OS drive auto-detected: $osDrive" -VerboseOnly
        return $osDrive
    }
    catch {
        Write-Log "Warning: Could not detect OS drive, falling back to C:"
        return "C:"
    }
}

function Get-VolumeMetadata {
    try {
        $volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop
        Write-Log "Win32_Volume query: Success" -VerboseOnly
        return $volumes
    }
    catch {
        Write-Log "Warning: Win32_Volume query failed, continuing with LogicalDisk only"
        return $null
    }
}

function Get-DiscoveredDrives {
    param(
        [string]$OSDriveLetter
    )

    $drives = @()

    # Primary source - Win32_LogicalDisk
    $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"

    # Secondary source - Win32_Volume for filtering metadata
    $volumes = Get-VolumeMetadata
    $volumeMap = @{}
    if ($volumes) {
        foreach ($vol in $volumes) {
            if ($vol.DriveLetter) {
                $volumeMap[$vol.DriveLetter] = $vol
            }
        }
    }

    Write-Log "Drive Discovery: $($logicalDisks.Count) drives found" -VerboseOnly

    foreach ($disk in $logicalDisks) {
        $driveLetter = $disk.DeviceID
        $sizeGB = [math]::Round($disk.Size / 1GB, 3)
        $volumeLabel = $disk.VolumeName
        $fileSystem = $null

        # Get additional metadata from Win32_Volume
        if ($volumeMap.ContainsKey($driveLetter)) {
            $vol = $volumeMap[$driveLetter]
            $fileSystem = $vol.FileSystem
            if ([string]::IsNullOrEmpty($volumeLabel)) {
                $volumeLabel = $vol.Label
            }
        }

        # Check exclusion criteria
        $excluded = $false
        $exclusionReason = ""

        # Size check
        if ($sizeGB -lt $script:Config.MinDriveSizeGB) {
            $excluded = $true
            $exclusionReason = "Size < $($script:Config.MinDriveSizeGB)GB"
        }

        # Label check
        if (-not $excluded -and -not [string]::IsNullOrEmpty($volumeLabel)) {
            foreach ($label in $script:Config.ExcludedLabels) {
                if ($volumeLabel -ieq $label) {
                    $excluded = $true
                    $exclusionReason = "Volume label '$volumeLabel'"
                    break
                }
            }
        }

        # File system check
        if (-not $excluded -and -not [string]::IsNullOrEmpty($fileSystem)) {
            if ($script:Config.ExcludedFileSystems -contains $fileSystem) {
                $excluded = $true
                $exclusionReason = "File system '$fileSystem'"
            }
        }

        # Determine drive type
        $driveType = if ($driveLetter -eq $OSDriveLetter) { "OS" } else { "Data" }

        if ($excluded) {
            Write-Log "  $driveLetter DriveType=3 Size=${sizeGB}GB Label='$volumeLabel' - EXCLUDED ($exclusionReason)" -VerboseOnly
        }
        else {
            Write-Log "  $driveLetter DriveType=3 Size=${sizeGB}GB - INCLUDED ($driveType)" -VerboseOnly

            $usedBytes = $disk.Size - $disk.FreeSpace
            $usedGB = [math]::Round($usedBytes / 1GB, 3)
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 3)
            $usagePercent = if ($disk.Size -gt 0) { [math]::Round(($usedBytes / $disk.Size) * 100, 2) } else { 0 }

            Write-Log "Drive $driveLetter Raw values - Total: $sizeGB Used: $usedGB Free: $freeGB Percent: $usagePercent%" -VerboseOnly

            $drives += @{
                driveLetter = $driveLetter
                volumeLabel = $volumeLabel
                totalSizeGB = $sizeGB
                usedGB = $usedGB
                freeGB = $freeGB
                usagePercent = $usagePercent
                driveType = $driveType
                timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            }
        }
    }

    return $drives
}
#endregion

#region History Management Functions
function Update-DriveHistory {
    param(
        [hashtable]$HistoryData,
        [array]$DiscoveredDrives,
        [string]$OSDriveLetter
    )

    $currentTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    $cutoffDate = (Get-Date).AddDays(-$script:Config.HistoryRetentionDays)
    $offlineCutoffDate = (Get-Date).AddDays(-$script:Config.OfflineRemovalDays)

    # Track which drives are currently visible
    $visibleDrives = @{}
    foreach ($drive in $DiscoveredDrives) {
        $visibleDrives[$drive.driveLetter] = $true
    }

    # Update existing drives and mark offline
    $drivesToRemove = @()
    foreach ($driveLetter in $HistoryData.drives.Keys) {
        $driveData = $HistoryData.drives[$driveLetter]

        if ($visibleDrives.ContainsKey($driveLetter)) {
            # Drive is online
            $driveData.status = "Online"
            $driveData.lastSeen = $currentTime
        }
        else {
            # Drive is offline
            if ($driveData.status -ne "Offline") {
                Write-Log "Drive $driveLetter went offline" -VerboseOnly
            }
            $driveData.status = "Offline"

            # Check if should be removed (offline > 30 days)
            if (-not [string]::IsNullOrEmpty($driveData.lastSeen)) {
                $lastSeenDate = [DateTime]::Parse($driveData.lastSeen)
                if ($lastSeenDate -lt $offlineCutoffDate) {
                    Write-Log "Drive $driveLetter offline > $($script:Config.OfflineRemovalDays) days, removing from history" -VerboseOnly
                    $drivesToRemove += $driveLetter
                }
            }
        }

        # Prune old history entries
        $prunedHistory = @()
        foreach ($entry in $driveData.history) {
            $entryDate = [DateTime]::Parse($entry.timestamp)
            if ($entryDate -ge $cutoffDate) {
                $prunedHistory += $entry
            }
        }
        $originalCount = $driveData.history.Count
        $driveData.history = $prunedHistory
        if ($originalCount -ne $prunedHistory.Count) {
            Write-Log "Drive $driveLetter History - $originalCount points loaded, $($prunedHistory.Count) after pruning" -VerboseOnly
        }
    }

    # Remove offline drives past threshold
    foreach ($driveLetter in $drivesToRemove) {
        $HistoryData.drives.Remove($driveLetter)
    }

    # Add/update discovered drives
    foreach ($drive in $DiscoveredDrives) {
        $driveLetter = $drive.driveLetter

        if (-not $HistoryData.drives.ContainsKey($driveLetter)) {
            # New drive
            Write-Log "New drive discovered: $driveLetter" -VerboseOnly
            $HistoryData.drives[$driveLetter] = @{
                volumeLabel = $drive.volumeLabel
                totalSizeGB = $drive.totalSizeGB
                driveType = $drive.driveType
                alertSent = $false
                status = "Online"
                lastSeen = $currentTime
                history = @()
            }
        }
        else {
            # Existing drive - check for size changes
            $existingDrive = $HistoryData.drives[$driveLetter]
            if ([math]::Abs($existingDrive.totalSizeGB - $drive.totalSizeGB) -gt 0.1) {
                Write-Log "Drive $driveLetter disk size changed from $($existingDrive.totalSizeGB) GB to $($drive.totalSizeGB) GB"
                $existingDrive.totalSizeGB = $drive.totalSizeGB
            }

            # Update label and type if changed
            $existingDrive.volumeLabel = $drive.volumeLabel
            $existingDrive.driveType = $drive.driveType
        }

        # Add new history entry
        $HistoryData.drives[$driveLetter].history += @{
            timestamp = $drive.timestamp
            usedGB = $drive.usedGB
            freeGB = $drive.freeGB
            usagePercent = $drive.usagePercent
        }
    }

    return $HistoryData
}
#endregion

#region Growth Calculation Functions
function Calculate-LinearRegression {
    param(
        [array]$History
    )

    if ($History.Count -lt 2) {
        return @{
            slope = 0
            intercept = 0
            rSquared = 0
        }
    }

    # Convert timestamps to days from first measurement
    $firstDate = [DateTime]::Parse($History[0].timestamp)
    $xValues = @()
    $yValues = @()

    foreach ($entry in $History) {
        $entryDate = [DateTime]::Parse($entry.timestamp)
        $daysSinceFirst = ($entryDate - $firstDate).TotalDays
        $xValues += $daysSinceFirst
        $yValues += $entry.usedGB
    }

    $n = $History.Count
    $sumX = ($xValues | Measure-Object -Sum).Sum
    $sumY = ($yValues | Measure-Object -Sum).Sum
    $sumXY = 0
    $sumX2 = 0
    $sumY2 = 0

    for ($i = 0; $i -lt $n; $i++) {
        $sumXY += $xValues[$i] * $yValues[$i]
        $sumX2 += $xValues[$i] * $xValues[$i]
        $sumY2 += $yValues[$i] * $yValues[$i]
    }

    # Calculate slope
    $denominator = ($n * $sumX2) - ($sumX * $sumX)
    if ($denominator -eq 0) {
        return @{
            slope = 0
            intercept = $sumY / $n
            rSquared = 0
        }
    }

    $slope = (($n * $sumXY) - ($sumX * $sumY)) / $denominator
    $intercept = ($sumY - ($slope * $sumX)) / $n

    # Calculate R-squared
    $meanY = $sumY / $n
    $ssTot = 0
    $ssRes = 0
    for ($i = 0; $i -lt $n; $i++) {
        $predicted = $slope * $xValues[$i] + $intercept
        $ssTot += ($yValues[$i] - $meanY) * ($yValues[$i] - $meanY)
        $ssRes += ($yValues[$i] - $predicted) * ($yValues[$i] - $predicted)
    }

    $rSquared = if ($ssTot -gt 0) { 1 - ($ssRes / $ssTot) } else { 0 }

    return @{
        slope = $slope
        intercept = $intercept
        rSquared = [math]::Max(0, $rSquared)
    }
}

function Get-DriveMetrics {
    param(
        [hashtable]$DriveData
    )

    $metrics = @{
        status = "Insufficient Data"
        gbPerMonth = "Insufficient Data"
        daysUntilFull = "Insufficient Data"
        isLimited = $false
        rawDaysUntilFull = $null
    }

    # Check if offline
    if ($DriveData.status -eq "Offline") {
        $metrics.status = "Offline"
        $metrics.gbPerMonth = "OFFLINE"
        $metrics.daysUntilFull = "OFFLINE"
        return $metrics
    }

    # Check minimum data points
    $historyCount = $DriveData.history.Count
    if ($historyCount -lt $script:Config.MinDataPoints) {
        return $metrics
    }

    # Calculate regression
    $regression = Calculate-LinearRegression -History $DriveData.history
    $dailyGrowthRate = $regression.slope
    $monthlyGrowthRate = $dailyGrowthRate * 30

    Write-Log "Regression - slope=$([math]::Round($dailyGrowthRate, 4)) GB/day, R²=$([math]::Round($regression.rSquared, 2))" -VerboseOnly

    # Get current free space from latest history entry
    $latestEntry = $DriveData.history | Select-Object -Last 1
    $currentFreeGB = $latestEntry.freeGB
    $currentUsagePercent = $latestEntry.usagePercent

    # Calculate days until full
    $daysUntilFull = $null
    $daysUntilFullDisplay = ""

    if ($dailyGrowthRate -le 0) {
        if ($dailyGrowthRate -lt 0) {
            $daysUntilFullDisplay = "Declining"
        }
        else {
            $daysUntilFullDisplay = "No Growth"
        }
    }
    else {
        $daysUntilFull = $currentFreeGB / $dailyGrowthRate
        if ($daysUntilFull -gt $script:Config.MaxDaysUntilFull) {
            $daysUntilFull = $script:Config.MaxDaysUntilFull
            $daysUntilFullDisplay = "{0:F2}" -f $daysUntilFull
        }
        else {
            $daysUntilFullDisplay = "{0:F2}" -f $daysUntilFull
        }
    }

    # Format GB per month
    $gbPerMonthDisplay = "{0:F3}" -f $monthlyGrowthRate

    # Determine status (in priority order)
    $status = "Stable"

    # Critical: days-until-full < 30 OR usage > 95%
    if (($null -ne $daysUntilFull -and $daysUntilFull -lt $script:Config.CriticalDaysThreshold) -or
        $currentUsagePercent -gt $script:Config.CriticalUsagePercent) {
        $status = "Critical"
    }
    # Attention: days-until-full between 30-90
    elseif ($null -ne $daysUntilFull -and $daysUntilFull -ge $script:Config.CriticalDaysThreshold -and
            $daysUntilFull -le $script:Config.AttentionDaysThreshold) {
        $status = "Attention"
    }
    # Declining: negative growth
    elseif ($dailyGrowthRate -lt 0) {
        $status = "Declining"
    }
    # Growing: growth >= 0.1 GB/day AND days-until-full > 90
    elseif ($dailyGrowthRate -ge $script:Config.MinGrowthRateGBPerDay -and
            ($null -eq $daysUntilFull -or $daysUntilFull -gt $script:Config.AttentionDaysThreshold)) {
        $status = "Growing"
    }
    # Stable: growth < 0.1 GB/day OR zero growth
    else {
        $status = "Stable"
    }

    # Check for limited history indicator
    $isLimited = $historyCount -ge $script:Config.MinDataPoints -and $historyCount -lt $script:Config.FullConfidencePoints
    if ($isLimited) {
        $status = "$status (Limited)"
    }

    $metrics.status = $status
    $metrics.gbPerMonth = $gbPerMonthDisplay
    $metrics.daysUntilFull = $daysUntilFullDisplay
    $metrics.isLimited = $isLimited
    $metrics.rawDaysUntilFull = $daysUntilFull

    return $metrics
}
#endregion

#region Drive Ranking Functions
function Get-StatusPriority {
    param([string]$Status)

    # Remove (Limited) suffix for comparison
    $baseStatus = $Status -replace '\s*\(Limited\)$', ''

    switch ($baseStatus) {
        "Critical" { return 1 }
        "Attention" { return 2 }
        "Growing" { return 3 }
        "Stable" { return 4 }
        "Declining" { return 5 }
        "Insufficient Data" { return 6 }
        "Offline" { return 7 }
        default { return 99 }
    }
}

function Get-ServerStatusPriority {
    param([string]$Status)

    # For server status, we want Critical > Attention > Growing > Stable > Declining > Insufficient Data
    $baseStatus = $Status -replace '\s*\(Limited\)$', ''

    switch ($baseStatus) {
        "Critical" { return 1 }
        "Attention" { return 2 }
        "Growing" { return 3 }
        "Stable" { return 4 }
        "Declining" { return 5 }
        "Insufficient Data" { return 6 }
        default { return 99 }
    }
}

function Get-RankedDataDrives {
    param(
        [hashtable]$AllDrives,
        [string]$OSDriveLetter
    )

    $onlineDrives = @()
    $offlineDrives = @()

    foreach ($driveLetter in $AllDrives.Keys) {
        if ($driveLetter -eq $OSDriveLetter) { continue }

        $drive = $AllDrives[$driveLetter]
        $metrics = Get-DriveMetrics -DriveData $drive

        $driveInfo = @{
            driveLetter = $driveLetter
            volumeLabel = $drive.volumeLabel
            totalSizeGB = $drive.totalSizeGB
            status = $metrics.status
            gbPerMonth = $metrics.gbPerMonth
            daysUntilFull = $metrics.daysUntilFull
            rawDaysUntilFull = $metrics.rawDaysUntilFull
            alertSent = $drive.alertSent
            history = $drive.history
        }

        if ($drive.status -eq "Offline") {
            $offlineDrives += $driveInfo
        }
        else {
            $onlineDrives += $driveInfo
        }
    }

    # Sort online drives by criticality
    $sortedOnline = $onlineDrives | Sort-Object {
        Get-StatusPriority $_.status
    }, {
        # Secondary sort: days until full (numeric first, then alphabetic)
        if ($null -ne $_.rawDaysUntilFull) {
            $_.rawDaysUntilFull
        }
        else {
            [double]::MaxValue
        }
    }, {
        # Tie-breaker: drive letter
        $_.driveLetter
    }

    # Sort offline drives alphabetically
    $sortedOffline = $offlineDrives | Sort-Object { $_.driveLetter }

    # Combine: online first, then offline
    return @($sortedOnline) + @($sortedOffline)
}
#endregion

#region Alert Functions
function Process-CriticalAlerts {
    param(
        [hashtable]$HistoryData,
        [string]$OSDriveLetter
    )

    $criticalDrives = @()
    $hostname = $env:COMPUTERNAME

    foreach ($driveLetter in $HistoryData.drives.Keys) {
        $drive = $HistoryData.drives[$driveLetter]

        if ($drive.status -eq "Offline") { continue }

        $metrics = Get-DriveMetrics -DriveData $drive
        $baseStatus = $metrics.status -replace '\s*\(Limited\)$', ''

        $wasAlertSent = $drive.alertSent

        if ($baseStatus -eq "Critical") {
            if (-not $wasAlertSent) {
                Write-Log "Drive $driveLetter alertSent was FALSE, setting to TRUE, writing Event 5001" -VerboseOnly
                $criticalDrives += @{
                    driveLetter = $driveLetter
                    daysUntilFull = $metrics.daysUntilFull
                    gbPerMonth = $metrics.gbPerMonth
                }
                $drive.alertSent = $true
            }
            else {
                Write-Log "Drive $driveLetter alertSent was TRUE, skipping Event 5001" -VerboseOnly
            }
        }
        else {
            # Reset alert flag when no longer critical
            if ($wasAlertSent) {
                Write-Log "Drive $driveLetter no longer Critical, resetting alertSent to FALSE" -VerboseOnly
                $drive.alertSent = $false
            }
        }
    }

    # Write combined event if any drives transitioned to critical
    if ($criticalDrives.Count -gt 0) {
        if ($criticalDrives.Count -eq 1) {
            $d = $criticalDrives[0]
            $message = "STORAGE CRITICAL: Server $hostname - Drive $($d.driveLetter) has $($d.daysUntilFull) days until full ($($d.gbPerMonth) GB/month growth rate). Immediate attention required."
        }
        else {
            $driveList = ($criticalDrives | ForEach-Object {
                "- Drive $($_.driveLetter): $($_.daysUntilFull) days until full ($($_.gbPerMonth) GB/month)"
            }) -join "`n"
            $message = "STORAGE CRITICAL: Server $hostname - Multiple drives require attention:`n$driveList`nImmediate attention required."
        }

        Write-StorageEvent -EventId 5001 -Message $message
        Write-Log "! Critical alert written to Event Log (ID 5001)"
        return $true
    }

    return $false
}

function Process-ExcessDriveAlert {
    param(
        [hashtable]$HistoryData,
        [array]$DataDrives
    )

    $onlineDataDriveCount = ($DataDrives | Where-Object { $_.status -ne "Offline" }).Count
    $hostname = $env:COMPUTERNAME

    if ($onlineDataDriveCount -gt $script:Config.MaxDataDrives) {
        if (-not $HistoryData.excessDriveAlertSent) {
            $excludedDrives = ($DataDrives | Select-Object -Skip $script:Config.MaxDataDrives | ForEach-Object { $_.driveLetter }) -join ", "
            $message = "STORAGE MONITORING: Server $hostname has $onlineDataDriveCount data drives but only $($script:Config.MaxDataDrives) can be reported. Excluded drives: $excludedDrives. Script update may be required."

            Write-StorageEvent -EventId 5002 -Message $message
            Write-Log "! Excess drives alert written to Event Log (ID 5002)"
            $HistoryData.excessDriveAlertSent = $true
        }
    }
    else {
        # Reset flag when drive count is within limits
        if ($HistoryData.excessDriveAlertSent) {
            Write-Log "Drive count now within limits, resetting excessDriveAlertSent" -VerboseOnly
            $HistoryData.excessDriveAlertSent = $false
        }
    }
}
#endregion

#region Ninja RMM Functions
function Test-NinjaContext {
    return $null -ne (Get-Command "Ninja-Property-Set" -ErrorAction SilentlyContinue)
}

function Set-NinjaProperty {
    param(
        [string]$Name,
        [string]$Value
    )

    if ($script:RunningInNinja) {
        try {
            Ninja-Property-Set $Name $Value
        }
        catch {
            Write-Log "Warning: Could not set Ninja property '$Name': $_"
        }
    }
}

function Update-NinjaFields {
    param(
        [hashtable]$OSDriveMetrics,
        [array]$RankedDataDrives,
        [string]$ServerStatus,
        [string]$OSDriveLetter
    )

    # Overall status
    Set-NinjaProperty "Server Storage Status" $ServerStatus

    # OS Drive
    Set-NinjaProperty "OS Drive Status" $OSDriveMetrics.status
    Set-NinjaProperty "OS Drive GB per Month" $OSDriveMetrics.gbPerMonth
    Set-NinjaProperty "OS Drive Days Until Full" $OSDriveMetrics.daysUntilFull

    # Data Drives (1-3)
    for ($i = 1; $i -le $script:Config.MaxDataDrives; $i++) {
        $driveIndex = $i - 1

        if ($driveIndex -lt $RankedDataDrives.Count) {
            $drive = $RankedDataDrives[$driveIndex]
            $letterDisplay = if ($drive.status -eq "Offline") { "$($drive.driveLetter) (OFFLINE)" } else { $drive.driveLetter -replace ':$', '' }

            Set-NinjaProperty "Data Drive $i Letter" $letterDisplay
            Set-NinjaProperty "Data Drive $i Status" $drive.status
            Set-NinjaProperty "Data Drive $i GB per Month" $drive.gbPerMonth
            Set-NinjaProperty "Data Drive $i Days Until Full" $drive.daysUntilFull
        }
        else {
            Set-NinjaProperty "Data Drive $i Letter" "NO DRIVE"
            Set-NinjaProperty "Data Drive $i Status" "NO DRIVE"
            Set-NinjaProperty "Data Drive $i GB per Month" "NO DRIVE"
            Set-NinjaProperty "Data Drive $i Days Until Full" "NO DRIVE"
        }
    }
}
#endregion

#region Output Functions
function Write-ConsoleReport {
    param(
        [hashtable]$HistoryData,
        [hashtable]$OSDriveMetrics,
        [array]$RankedDataDrives,
        [string]$ServerStatus,
        [string]$OSDriveLetter,
        [bool]$CriticalAlertWritten
    )

    $hostname = $env:COMPUTERNAME

    Write-Log "Storage Growth Analysis - $hostname"
    Write-Log "═══════════════════════════════════════════════════════════════"
    Write-Log ""

    # OS Drive
    Write-Log "OS DRIVE (Auto-detected: $OSDriveLetter)"
    $osDrive = $HistoryData.drives[$OSDriveLetter]
    $osLabel = if ([string]::IsNullOrEmpty($osDrive.volumeLabel)) { $OSDriveLetter } else { $osDrive.volumeLabel }
    Write-Log "  Drive $OSDriveLetter ($osLabel)"

    if ($osDrive.history.Count -gt 0) {
        $latest = $osDrive.history | Select-Object -Last 1
        Write-Log "  Current: $("{0:F3}" -f $latest.usedGB) GB / $("{0:F3}" -f $osDrive.totalSizeGB) GB ($("{0:F2}" -f $latest.usagePercent)%)"
    }

    Write-Log "  Growth:  $($OSDriveMetrics.gbPerMonth) GB/month"

    $statusDisplay = $OSDriveMetrics.status
    if ($OSDriveMetrics.daysUntilFull -eq $("{0:F2}" -f $script:Config.MaxDaysUntilFull)) {
        Write-Log "  Status:  $statusDisplay ($($OSDriveMetrics.daysUntilFull) days until full - capped)"
    }
    else {
        Write-Log "  Status:  $statusDisplay ($($OSDriveMetrics.daysUntilFull) days until full)"
    }

    Write-Log ""
    Write-Log "DATA DRIVES (Ranked by Criticality)"
    Write-Log "───────────────────────────────────────────────────────────────"

    for ($i = 0; $i -lt $script:Config.MaxDataDrives; $i++) {
        $slotNum = $i + 1

        if ($i -lt $RankedDataDrives.Count) {
            $drive = $RankedDataDrives[$i]
            $label = if ([string]::IsNullOrEmpty($drive.volumeLabel)) { $drive.driveLetter } else { $drive.volumeLabel }

            if ($drive.status -eq "Offline") {
                Write-Log "  [$slotNum] Drive $($drive.driveLetter) ($label) - OFFLINE"
            }
            else {
                Write-Log "  [$slotNum] Drive $($drive.driveLetter) ($label)"

                # Get current values from history
                $driveData = $HistoryData.drives[$drive.driveLetter]
                if ($driveData.history.Count -gt 0) {
                    $latest = $driveData.history | Select-Object -Last 1
                    Write-Log "      Current: $("{0:F3}" -f $latest.usedGB) GB / $("{0:F3}" -f $driveData.totalSizeGB) GB ($("{0:F2}" -f $latest.usagePercent)%)"
                }

                Write-Log "      Growth:  $($drive.gbPerMonth) GB/month"

                $baseStatus = $drive.status -replace '\s*\(Limited\)$', ''
                if ($baseStatus -eq "Critical") {
                    Write-Log "      Status:  $($drive.status.ToUpper()) ($($drive.daysUntilFull) days until full)"
                }
                else {
                    Write-Log "      Status:  $($drive.status) ($($drive.daysUntilFull) days until full)"
                }
            }
        }
        else {
            Write-Log "  [$slotNum] NO DRIVE"
        }

        Write-Log ""
    }

    Write-Log "═══════════════════════════════════════════════════════════════"
    Write-Log "SERVER STATUS: $($ServerStatus.ToUpper())"
    Write-Log ""
}

function Write-FieldsSummary {
    param(
        [string]$OSDriveLetter,
        [array]$RankedDataDrives
    )

    if ($script:RunningInNinja) {
        Write-Log "✓ CUSTOM FIELDS FILLED"
    }
    else {
        Write-Log "*** TEST MODE - Ninja fields not updated ***"
    }

    Write-Log "  - OS Drive: $($OSDriveLetter -replace ':$', '')"

    for ($i = 0; $i -lt $script:Config.MaxDataDrives; $i++) {
        $slotNum = $i + 1
        if ($i -lt $RankedDataDrives.Count) {
            $drive = $RankedDataDrives[$i]
            $letterDisplay = if ($drive.status -eq "Offline") { "$($drive.driveLetter -replace ':$', '') (OFFLINE)" } else { $drive.driveLetter -replace ':$', '' }
            Write-Log "  - Data Drive ${slotNum}: $letterDisplay"
        }
        else {
            Write-Log "  - Data Drive ${slotNum}: NO DRIVE"
        }
    }
}
#endregion

#region Main Execution
function Main {
    # Initialize
    Initialize-LogBuffer

    # Check Ninja context
    $script:RunningInNinja = Test-NinjaContext

    if (-not $script:RunningInNinja) {
        Write-Log "*** TEST MODE - Not running in Ninja context ***"
        Write-Log "Ninja custom field updates will be skipped."
        Write-Log ""
    }

    # Verbose initialization info
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" -VerboseOnly
    Write-Log "Script Version: $($script:Config.Version)" -VerboseOnly
    Write-Log "Storage Path: $($script:Config.StoragePath)" -VerboseOnly
    Write-Log "" -VerboseOnly

    # Initialize event log source
    $eventLogReady = Initialize-EventLogSource

    # Initialize storage path
    if (-not (Initialize-StoragePath)) {
        Write-Log "CRITICAL: Cannot create storage folder. Exiting."
        Save-LogFile
        exit 1
    }

    # Load history data
    $historyData = Load-HistoryData

    # Detect OS drive
    $osDriveLetter = Get-OSDriveLetter

    # Discover drives
    Write-Log "" -VerboseOnly
    $discoveredDrives = Get-DiscoveredDrives -OSDriveLetter $osDriveLetter
    Write-Log "" -VerboseOnly

    # Update history
    $historyData = Update-DriveHistory -HistoryData $historyData -DiscoveredDrives $discoveredDrives -OSDriveLetter $osDriveLetter

    # Get OS drive metrics
    $osDriveMetrics = @{
        status = "Insufficient Data"
        gbPerMonth = "Insufficient Data"
        daysUntilFull = "Insufficient Data"
    }

    if ($historyData.drives.ContainsKey($osDriveLetter)) {
        $osDriveMetrics = Get-DriveMetrics -DriveData $historyData.drives[$osDriveLetter]
        Write-Log "Drive $osDriveLetter Status: $($osDriveMetrics.status)" -VerboseOnly
    }

    # Get ranked data drives
    $rankedDataDrives = Get-RankedDataDrives -AllDrives $historyData.drives -OSDriveLetter $osDriveLetter

    # Process excess drive alert
    Process-ExcessDriveAlert -HistoryData $historyData -DataDrives $rankedDataDrives

    # Limit to max data drives for reporting
    $reportedDataDrives = $rankedDataDrives | Select-Object -First $script:Config.MaxDataDrives

    # Determine server status (worst case among online drives)
    $worstStatus = "Insufficient Data"
    $worstPriority = 99

    # Check OS drive
    $osStatusPriority = Get-ServerStatusPriority $osDriveMetrics.status
    if ($osStatusPriority -lt $worstPriority) {
        $worstPriority = $osStatusPriority
        $worstStatus = $osDriveMetrics.status -replace '\s*\(Limited\)$', ''
    }

    # Check data drives (online only)
    foreach ($drive in $rankedDataDrives) {
        if ($drive.status -eq "Offline") { continue }
        $statusPriority = Get-ServerStatusPriority $drive.status
        if ($statusPriority -lt $worstPriority) {
            $worstPriority = $statusPriority
            $worstStatus = $drive.status -replace '\s*\(Limited\)$', ''
        }
    }

    $serverStatus = $worstStatus

    # Process critical alerts
    $criticalAlertWritten = $false
    if ($eventLogReady) {
        $criticalAlertWritten = Process-CriticalAlerts -HistoryData $historyData -OSDriveLetter $osDriveLetter
    }

    # Write console report
    Write-ConsoleReport -HistoryData $historyData -OSDriveMetrics $osDriveMetrics -RankedDataDrives $reportedDataDrives -ServerStatus $serverStatus -OSDriveLetter $osDriveLetter -CriticalAlertWritten $criticalAlertWritten

    # Update Ninja fields
    if ($script:RunningInNinja) {
        Update-NinjaFields -OSDriveMetrics $osDriveMetrics -RankedDataDrives $reportedDataDrives -ServerStatus $serverStatus -OSDriveLetter $osDriveLetter
    }

    # Write fields summary
    Write-FieldsSummary -OSDriveLetter $osDriveLetter -RankedDataDrives $reportedDataDrives

    # Save history
    $totalDataPoints = 0
    foreach ($driveLetter in $historyData.drives.Keys) {
        $totalDataPoints += $historyData.drives[$driveLetter].history.Count
    }

    if (Save-HistoryData -Data $historyData) {
        Write-Log "✓ History file saved ($($historyData.drives.Count) drives, $totalDataPoints data points)"
    }

    # Save log file
    Save-LogFile

    exit 0
}

# Execute main function
Main
#endregion
