function Get-WorkstationSample {
    <#
    .SYNOPSIS
        Performs remote spot-check of specified workstations via WMI or WinRM.
    .DESCRIPTION
        For each specified workstation IP, checks reachability and then collects OS version,
        disk utilization, dental software, AV status, local admin accounts, and Windows
        Installer folder size. Tries WinRM (Invoke-Command) first, falls back to WMI (DCOM).
        Unreachable or access-denied workstations are logged and skipped.
    .PARAMETER WorkstationIPs
        Array of IP addresses to scan.
    .PARAMETER Standards
        The DTC standards object loaded from DTC-Standards.json.
    .EXAMPLE
        $wsData = Get-WorkstationSample -WorkstationIPs @("10.0.1.50","10.0.1.51") -Standards $standards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$WorkstationIPs,

        [Parameter(Mandatory = $true)]
        [PSObject]$Standards
    )

    Write-Verbose "Get-WorkstationSample: Starting workstation scan for $($WorkstationIPs.Count) workstation(s)"

    $results = @()

    foreach ($ip in $WorkstationIPs) {
        Write-Verbose "Get-WorkstationSample: Scanning $ip"

        $wsResult = @{
            IPAddress   = $ip
            Reachable   = $false
            Method      = "None"
            Data        = @{}
            Error       = $null
        }

        # Test reachability
        $pingOK = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $pingOK) {
            $wsResult.Error = "Workstation $ip is not reachable"
            Write-Verbose "Get-WorkstationSample: $ip is not reachable"
            $results += $wsResult
            continue
        }

        $wsResult.Reachable = $true

        # Try WinRM first, fall back to WMI
        $dataCollected = $false

        # --- WinRM Attempt ---
        try {
            Write-Verbose "Get-WorkstationSample: Trying WinRM for $ip"
            $sessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 30000
            $wsData = Invoke-Command -ComputerName $ip -SessionOption $sessionOption -ErrorAction Stop -ScriptBlock {
                $data = @{}

                # OS version
                try {
                    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
                    $data.OS = @{
                        Caption     = $os.Caption
                        Version     = $os.Version
                        BuildNumber = $os.BuildNumber
                    }
                }
                catch {
                    $data.OS = @{ Caption = "Unknown"; Version = "Unknown"; BuildNumber = "Unknown" }
                }

                # Disk utilization
                try {
                    $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
                    $data.Disks = @()
                    foreach ($disk in $disks) {
                        $sizeGB = [math]::Round($disk.Size / 1GB, 2)
                        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                        $usedPercent = if ($disk.Size -gt 0) { [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1) } else { 0 }
                        $data.Disks += @{
                            Drive       = $disk.DeviceID
                            SizeGB      = $sizeGB
                            FreeGB      = $freeGB
                            UsedPercent = $usedPercent
                        }
                    }
                }
                catch {
                    $data.Disks = @()
                }

                # Dental software registry scrape
                try {
                    $regPaths = @(
                        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                    )
                    $allSoftware = @()
                    foreach ($rp in $regPaths) {
                        $items = Get-ItemProperty $rp -ErrorAction SilentlyContinue
                        if ($items) { $allSoftware += $items }
                    }
                    $allSoftware = @($allSoftware | Where-Object { $_.DisplayName })
                    $data.InstalledSoftware = @($allSoftware | ForEach-Object {
                        @{
                            DisplayName    = $_.DisplayName
                            DisplayVersion = $_.DisplayVersion
                            Publisher      = $_.Publisher
                        }
                    })
                }
                catch {
                    $data.InstalledSoftware = @()
                }

                # AV status
                try {
                    $defender = Get-MpComputerStatus -ErrorAction Stop
                    $data.AVStatus = @{
                        DefenderEnabled        = $defender.AntivirusEnabled
                        RealTimeProtection     = $defender.RealTimeProtectionEnabled
                        SignatureDate          = if ($defender.AntivirusSignatureLastUpdated) { $defender.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd") } else { "Unknown" }
                    }
                }
                catch {
                    # Try WMI SecurityCenter2
                    try {
                        $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction Stop
                        $data.AVStatus = @{
                            Products = @($avProducts | ForEach-Object { $_.displayName })
                        }
                    }
                    catch {
                        $data.AVStatus = @{ DefenderEnabled = "Unknown"; RealTimeProtection = "Unknown" }
                    }
                }

                # Local admin accounts
                try {
                    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
                    $data.LocalAdmins = @($admins | ForEach-Object { $_.Name })
                }
                catch {
                    $data.LocalAdmins = @()
                }

                # Windows Installer folder size
                try {
                    $measureResult = (Get-ChildItem "C:\Windows\Installer" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum)
                    $installerSize = if ($measureResult.Sum) { $measureResult.Sum } else { 0 }
                    $data.InstallerFolderGB = [math]::Round($installerSize / 1GB, 2)
                }
                catch {
                    $data.InstallerFolderGB = 0
                }

                return $data
            }

            $wsResult.Method = "WinRM"
            $wsResult.Data = $wsData
            $dataCollected = $true
            Write-Verbose "Get-WorkstationSample: WinRM succeeded for $ip"
        }
        catch {
            Write-Verbose "Get-WorkstationSample: WinRM failed for $ip — $($_.Exception.Message). Trying WMI..."
        }

        # --- WMI (DCOM) Fallback ---
        if (-not $dataCollected) {
            try {
                Write-Verbose "Get-WorkstationSample: Trying WMI/DCOM for $ip"
                $wmiData = @{}

                # OS version
                try {
                    $os = Get-WmiObject Win32_OperatingSystem -ComputerName $ip -ErrorAction Stop
                    $wmiData.OS = @{
                        Caption     = $os.Caption
                        Version     = $os.Version
                        BuildNumber = $os.BuildNumber
                    }
                }
                catch {
                    $wmiData.OS = @{ Caption = "Unknown"; Version = "Unknown"; BuildNumber = "Unknown" }
                }

                # Disk utilization
                try {
                    $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $ip -ErrorAction Stop
                    $wmiData.Disks = @()
                    foreach ($disk in $disks) {
                        $sizeGB = [math]::Round($disk.Size / 1GB, 2)
                        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                        $usedPercent = if ($disk.Size -gt 0) { [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1) } else { 0 }
                        $wmiData.Disks += @{
                            Drive       = $disk.DeviceID
                            SizeGB      = $sizeGB
                            FreeGB      = $freeGB
                            UsedPercent = $usedPercent
                        }
                    }
                }
                catch {
                    $wmiData.Disks = @()
                }

                # Software list via WMI registry provider
                try {
                    $software = Get-WmiObject Win32_Product -ComputerName $ip -ErrorAction Stop
                    $wmiData.InstalledSoftware = @($software | ForEach-Object {
                        @{
                            DisplayName    = $_.Name
                            DisplayVersion = $_.Version
                            Publisher      = $_.Vendor
                        }
                    })
                }
                catch {
                    $wmiData.InstalledSoftware = @()
                }

                # AV status via SecurityCenter2
                try {
                    $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ComputerName $ip -ErrorAction Stop
                    $wmiData.AVStatus = @{
                        Products = @($avProducts | ForEach-Object { $_.displayName })
                    }
                }
                catch {
                    $wmiData.AVStatus = @{ DefenderEnabled = "Unknown"; RealTimeProtection = "Unknown" }
                }

                # Local admins via WMI
                try {
                    $adminGroup = Get-WmiObject Win32_GroupUser -ComputerName $ip -ErrorAction Stop |
                        Where-Object { $_.GroupComponent -match 'Name="Administrators"' }
                    $wmiData.LocalAdmins = @($adminGroup | ForEach-Object {
                        if ($_.PartComponent -match 'Name="(.+?)"') { $Matches[1] }
                    })
                }
                catch {
                    $wmiData.LocalAdmins = @()
                }

                $wmiData.InstallerFolderGB = 0  # Cannot easily measure remotely via WMI

                $wsResult.Method = "WMI"
                $wsResult.Data = $wmiData
                $dataCollected = $true
                Write-Verbose "Get-WorkstationSample: WMI succeeded for $ip"
            }
            catch {
                $wsResult.Error = "Both WinRM and WMI failed for $ip — $($_.Exception.Message)"
                Write-Verbose "Get-WorkstationSample: All methods failed for $ip"
            }
        }

        # OS version status check
        if ($dataCollected -and $wsResult.Data.OS -and $wsResult.Data.OS.Caption) {
            $osCaption = $wsResult.Data.OS.Caption
            $wsResult.Data.OSVersionStatus = "Unknown"

            foreach ($supported in $Standards.os_versions.workstation_supported) {
                if ($osCaption -match [regex]::Escape($supported)) {
                    $wsResult.Data.OSVersionStatus = "Supported"
                    break
                }
            }
            if ($wsResult.Data.OSVersionStatus -eq "Unknown") {
                foreach ($eol in $Standards.os_versions.workstation_eol) {
                    if ($osCaption -match [regex]::Escape($eol)) {
                        $wsResult.Data.OSVersionStatus = "EOL"
                        break
                    }
                }
            }
        }

        $results += $wsResult
    }

    Write-Verbose "Get-WorkstationSample: Completed scanning $($results.Count) workstation(s)"

    return $results
}
