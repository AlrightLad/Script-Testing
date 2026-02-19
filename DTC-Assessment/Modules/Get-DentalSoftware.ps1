function Get-DentalSoftware {
    <#
    .SYNOPSIS
        Detects dental and related software via registry scrape.
    .DESCRIPTION
        Scrapes the Windows registry for installed software and matches against known
        dental software patterns including practice management systems, imaging platforms,
        imaging drivers, VoIP, backup, RMM/security, and dental utilities. Also queries
        Windows Defender status separately.
    .EXAMPLE
        $dentalData = Get-DentalSoftware
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Get-DentalSoftware: Starting dental software detection"

    # Detection patterns — all patterns defined here for easy maintenance
    $DetectionPatterns = [ordered]@{
        # PRACTICE MANAGEMENT SYSTEMS
        PMS = [ordered]@{
            "Dentrix"       = "Dentrix"
            "Eaglesoft"     = "Eaglesoft"
            "Open Dental"   = "Open Dental"
            "SoftDent"      = "SoftDent"
            "PracticeWorks" = "PracticeWorks"
            "PBS Endo"      = "PBS Endo"
            "TDO"           = "TDO|The Dental Office"
            "Curve Dental"  = "Curve"
        }

        # IMAGING PLATFORMS
        Imaging = [ordered]@{
            "DEXIS"         = "DEXIS"
            "CS Imaging"    = "CS Imaging|Carestream.*Imaging|CS 3D"
            "Schick"        = "Schick|CDR DICOM|IOSS"
            "Apteryx"       = "Apteryx|XVWeb|XrayVision"
            "Romexis"       = "Romexis"
            "Sidexis"       = "Sidexis"
            "DTX Studio"    = "DTX Studio"
            "Dolphin"       = "Dolphin.*Imaging"
            "i-CAT"         = "i-CAT"
            "Vatech"        = "EzDent"
            "Planmeca"      = "Planmeca"
        }

        # IMAGING DRIVERS AND SERVICES
        ImagingDrivers = [ordered]@{
            "TWAIN"         = "TWAIN"
            "DEXIS Service" = "DEXIS.*Service"
            "Schick CDR"    = "CDR"
            "IOSS"          = "IOSS|Integrated Open Sensor"
        }

        # VOIP SOFTWARE
        VoIP = [ordered]@{
            "Weave"           = "Weave"
            "RingCentral"     = "RingCentral"
            "8x8"             = "8x8"
            "Zoom"            = "Zoom"
            "Microsoft Teams" = "Teams"
            "Vonage"          = "Vonage"
            "Dialpad"         = "Dialpad"
            "Freedom Voice"   = "Freedom.*Voice|FreedomVoice"
            "Mango Voice"     = "Mango"
        }

        # BACKUP SOFTWARE
        Backup = [ordered]@{
            "Veeam"        = "Veeam"
            "MSP360"       = "MSP360|CloudBerry"
            "Acronis"      = "Acronis"
            "StorageCraft" = "StorageCraft|Arcserve|ShadowProtect"
            "Datto"        = "Datto"
        }

        # RMM AND SECURITY
        RMMSecurity = [ordered]@{
            "NinjaOne"     = "NinjaRMM|NinjaOne|ninjarmm-agent"
            "ConnectWise"  = "ConnectWise|LabTech|Automate"
            "Datto RMM"   = "Datto RMM|Autotask"
            "SentinelOne"  = "SentinelOne|Sentinel Agent"
            "Webroot"      = "Webroot"
            "Sophos"       = "Sophos"
            "Norton"       = "Norton"
            "McAfee"       = "McAfee"
            "AVG"          = "AVG"
            "Avast"        = "Avast"
            "Kaspersky"    = "Kaspersky"
            "Bitdefender"  = "Bitdefender"
            "Malwarebytes" = "Malwarebytes"
        }

        # DENTAL UTILITIES
        Utilities = [ordered]@{
            "DemandForce"                = "DemandForce"
            "RevenueWell"                = "RevenueWell"
            "Dentrix Ascend Connector"   = "Dentrix.*Ascend.*Connector|Ascend.*Connect"
            "eClinicalWorks"             = "eClinicalWorks"
        }
    }

    $result = @{
        DetectedSoftware     = @{}
        WindowsDefender      = @{}
        AllInstalledSoftware = @()
    }

    # Scrape registry
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $allSoftware = @()
    foreach ($regPath in $regPaths) {
        try {
            $items = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($items) {
                $allSoftware += $items
            }
        }
        catch {
            Write-Verbose "Get-DentalSoftware: Failed to read $regPath — $($_.Exception.Message)"
        }
    }

    $allSoftware = @($allSoftware | Where-Object { $_.DisplayName })
    Write-Verbose "Get-DentalSoftware: Found $($allSoftware.Count) installed software entries"

    # Build full software list for appendix
    $result.AllInstalledSoftware = @($allSoftware | ForEach-Object {
        @{
            DisplayName     = $_.DisplayName
            DisplayVersion  = $_.DisplayVersion
            Publisher       = $_.Publisher
            InstallDate     = $_.InstallDate
            InstallLocation = $_.InstallLocation
        }
    } | Sort-Object { $_.DisplayName })

    # Match against detection patterns
    foreach ($category in $DetectionPatterns.Keys) {
        $result.DetectedSoftware[$category] = @()

        foreach ($appName in $DetectionPatterns[$category].Keys) {
            $pattern = $DetectionPatterns[$category][$appName]
            $matched = @($allSoftware | Where-Object { $_.DisplayName -match $pattern })

            foreach ($match in $matched) {
                $result.DetectedSoftware[$category] += @{
                    AppName         = $appName
                    DisplayName     = $match.DisplayName
                    Version         = $match.DisplayVersion
                    InstallDate     = $match.InstallDate
                    Publisher       = $match.Publisher
                    InstallLocation = $match.InstallLocation
                }
            }
        }

        Write-Verbose "Get-DentalSoftware: $category — $($result.DetectedSoftware[$category].Count) match(es)"
    }

    # Windows Defender status (not in registry — query separately)
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $result.WindowsDefender = @{
            Enabled                = $defender.AntivirusEnabled
            RealTimeProtection     = $defender.RealTimeProtectionEnabled
            SignatureDate          = if ($defender.AntivirusSignatureLastUpdated) { $defender.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
            AMRunningMode          = $defender.AMRunningMode
        }
        Write-Verbose "Get-DentalSoftware: Defender — Enabled: $($result.WindowsDefender.Enabled), RealTime: $($result.WindowsDefender.RealTimeProtection)"
    }
    catch {
        Write-Verbose "Get-DentalSoftware: Windows Defender status unavailable — $($_.Exception.Message)"
        $result.WindowsDefender = @{
            Enabled            = "Unknown"
            RealTimeProtection = "Unknown"
            SignatureDate      = "Unknown"
            AMRunningMode      = "Unknown"
        }
    }

    return $result
}
