function Get-ServerInfo {
    <#
    .SYNOPSIS
        Collects server hardware, OS, disk, RAM, and CPU information.
    .DESCRIPTION
        Gathers comprehensive server infrastructure data including hardware specs,
        OS version, disk utilization, Windows Installer folder size, recent hotfixes,
        and uptime. Compares OS version against DTC standards for EOL/supported status.
    .PARAMETER Standards
        The DTC standards object loaded from DTC-Standards.json, used for OS version comparison.
    .EXAMPLE
        $serverData = Get-ServerInfo -Standards $standards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Standards
    )

    Write-Verbose "Get-ServerInfo: Starting server information collection"

    $result = @{}

    # Computer name
    $result.ComputerName = $env:COMPUTERNAME
    Write-Verbose "Get-ServerInfo: Computer name = $($result.ComputerName)"

    # Domain or workgroup
    try {
        $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
        $result.Domain = $cs.Domain
        $result.IsDomainJoined = $cs.PartOfDomain
        Write-Verbose "Get-ServerInfo: Domain = $($result.Domain), DomainJoined = $($result.IsDomainJoined)"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to get domain info — $($_.Exception.Message)"
        $result.Domain = "Unknown"
        $result.IsDomainJoined = $false
    }

    # OS information
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $lastBoot = $os.ConvertToDateTime($os.LastBootUpTime)
        $installDate = $os.ConvertToDateTime($os.InstallDate)
        $result.OS = @{
            Caption     = $os.Caption
            Version     = $os.Version
            BuildNumber = $os.BuildNumber
            InstallDate = $installDate.ToString("yyyy-MM-dd")
            LastBoot    = $lastBoot.ToString("yyyy-MM-dd HH:mm:ss")
        }
        # Calculate uptime
        $result.UptimeDays = [math]::Floor(((Get-Date) - $lastBoot).TotalDays)
        Write-Verbose "Get-ServerInfo: OS = $($os.Caption), Uptime = $($result.UptimeDays) days"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to get OS info — $($_.Exception.Message)"
        $result.OS = @{ Caption = "Unknown"; Version = "Unknown"; BuildNumber = "Unknown"; InstallDate = "Unknown"; LastBoot = "Unknown" }
        $result.UptimeDays = -1
    }

    # CPU information
    try {
        $cpu = Get-WmiObject Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $result.CPU = @{
            Name              = $cpu.Name.Trim()
            Cores             = $cpu.NumberOfCores
            LogicalProcessors = $cpu.NumberOfLogicalProcessors
            MaxClockMHz       = $cpu.MaxClockSpeed
        }
        Write-Verbose "Get-ServerInfo: CPU = $($result.CPU.Name)"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to get CPU info — $($_.Exception.Message)"
        $result.CPU = @{ Name = "Unknown"; Cores = 0; LogicalProcessors = 0; MaxClockMHz = 0 }
    }

    # RAM
    try {
        $totalRam = (Get-WmiObject Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
        $result.RAMTotalGB = [math]::Round($totalRam / 1GB, 2)
        Write-Verbose "Get-ServerInfo: RAM = $($result.RAMTotalGB) GB"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to get RAM info — $($_.Exception.Message)"
        $result.RAMTotalGB = 0
    }

    # Logical disks
    try {
        $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        $result.Disks = @()
        foreach ($disk in $disks) {
            $sizeGB = [math]::Round($disk.Size / 1GB, 2)
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $usedPercent = if ($disk.Size -gt 0) { [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1) } else { 0 }

            $status = "Healthy"
            if ($usedPercent -ge $Standards.disk_health.critical_threshold_percent) {
                $status = "Critical"
            }
            elseif ($usedPercent -ge $Standards.disk_health.warning_threshold_percent) {
                $status = "Warning"
            }

            $result.Disks += @{
                Drive       = $disk.DeviceID
                SizeGB      = $sizeGB
                FreeGB      = $freeGB
                UsedPercent = $usedPercent
                Status      = $status
            }
            Write-Verbose "Get-ServerInfo: Disk $($disk.DeviceID) — $usedPercent% used ($status)"
        }
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to get disk info — $($_.Exception.Message)"
        $result.Disks = @()
    }

    # Physical disks (Get-PhysicalDisk may not be available on all systems)
    try {
        $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
        $result.PhysicalDisks = @()
        foreach ($pd in $physicalDisks) {
            $result.PhysicalDisks += @{
                MediaType    = $pd.MediaType
                SizeGB       = [math]::Round($pd.Size / 1GB, 2)
                HealthStatus = $pd.HealthStatus
            }
        }
        Write-Verbose "Get-ServerInfo: Found $($result.PhysicalDisks.Count) physical disk(s)"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Get-PhysicalDisk not available — $($_.Exception.Message)"
        $result.PhysicalDisks = @()
    }

    # RAID controller info (best-effort)
    try {
        $raidInfo = Get-WmiObject Win32_DiskDrive -ErrorAction Stop | Select-Object Model, InterfaceType, MediaType, Size
        $result.RAIDInfo = @()
        foreach ($drive in $raidInfo) {
            $result.RAIDInfo += @{
                Model         = $drive.Model
                InterfaceType = $drive.InterfaceType
                MediaType     = $drive.MediaType
                SizeGB        = if ($drive.Size) { [math]::Round($drive.Size / 1GB, 2) } else { 0 }
            }
        }
        Write-Verbose "Get-ServerInfo: Found $($result.RAIDInfo.Count) disk drive(s) via WMI"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to get RAID info — $($_.Exception.Message)"
        $result.RAIDInfo = @()
    }

    # Windows Installer folder size
    try {
        $installerPath = "C:\Windows\Installer"
        if (Test-Path $installerPath) {
            $measureResult = (Get-ChildItem $installerPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum)
            $installerSize = if ($measureResult.Sum) { $measureResult.Sum } else { 0 }
            $result.InstallerFolderGB = [math]::Round($installerSize / 1GB, 2)
        }
        else {
            $result.InstallerFolderGB = 0
        }
        Write-Verbose "Get-ServerInfo: Windows Installer folder = $($result.InstallerFolderGB) GB"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to measure Installer folder — $($_.Exception.Message)"
        $result.InstallerFolderGB = 0
    }

    # Recent hotfixes
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop |
            Sort-Object @{Expression = { if ($_.InstalledOn) { $_.InstalledOn } else { [datetime]::MinValue } }; Descending = $true} |
            Select-Object -First 5
        $result.RecentHotfixes = @()
        foreach ($hf in $hotfixes) {
            $result.RecentHotfixes += @{
                HotFixID    = $hf.HotFixID
                InstalledOn = if ($hf.InstalledOn) { $hf.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                Description = $hf.Description
            }
        }
        Write-Verbose "Get-ServerInfo: Found $($result.RecentHotfixes.Count) recent hotfix(es)"
    }
    catch {
        Write-Verbose "Get-ServerInfo: Failed to get hotfix info — $($_.Exception.Message)"
        $result.RecentHotfixes = @()
    }

    # OS version status check against standards
    $result.OSVersionStatus = "Unknown"
    if ($result.OS.Caption) {
        $osCaption = $result.OS.Caption
        $isSupported = $false
        $isEOL = $false

        foreach ($supported in $Standards.os_versions.server_supported) {
            if ($osCaption -match [regex]::Escape($supported)) {
                $isSupported = $true
                break
            }
        }

        if (-not $isSupported) {
            foreach ($eol in $Standards.os_versions.server_eol) {
                if ($osCaption -match [regex]::Escape($eol)) {
                    $isEOL = $true
                    break
                }
            }
        }

        if ($isSupported) {
            $result.OSVersionStatus = "Supported"
        }
        elseif ($isEOL) {
            $result.OSVersionStatus = "EOL"
        }
        else {
            $result.OSVersionStatus = "Unknown"
        }
        Write-Verbose "Get-ServerInfo: OS version status = $($result.OSVersionStatus)"
    }

    return $result
}
