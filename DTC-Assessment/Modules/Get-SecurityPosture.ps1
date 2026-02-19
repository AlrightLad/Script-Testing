function Get-SecurityPosture {
    <#
    .SYNOPSIS
        Collects security posture information including AV, firewall, RMM, shares, and local admins.
    .DESCRIPTION
        Gathers Windows Defender status, third-party AV from dental software detection,
        Windows Firewall profile status, RMM agent presence, open file shares,
        local administrator group members, and DTCADMIN account existence check.
    .PARAMETER DentalSoftwareData
        The output from Get-DentalSoftware, used to cross-reference RMM and AV detections.
    .PARAMETER Standards
        The DTC standards object loaded from DTC-Standards.json.
    .EXAMPLE
        $securityData = Get-SecurityPosture -DentalSoftwareData $dentalData -Standards $standards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$DentalSoftwareData,

        [Parameter(Mandatory = $true)]
        [PSObject]$Standards
    )

    Write-Verbose "Get-SecurityPosture: Starting security posture collection"

    $result = @{}

    # --- Antivirus Status ---
    # Windows Defender (from dental software data or fresh query)
    $result.WindowsDefender = $DentalSoftwareData.WindowsDefender

    # Third-party AV (from dental software RMMSecurity category)
    $avProducts = @()
    $rmmSecurityApps = $DentalSoftwareData.DetectedSoftware.RMMSecurity
    if ($rmmSecurityApps) {
        $avKeywords = @("Norton", "McAfee", "AVG", "Avast", "Kaspersky", "Bitdefender",
                        "Malwarebytes", "SentinelOne", "Webroot", "Sophos")
        foreach ($app in $rmmSecurityApps) {
            foreach ($keyword in $avKeywords) {
                if ($app.AppName -match $keyword) {
                    $avProducts += $app
                    break
                }
            }
        }
    }
    $result.ThirdPartyAV = $avProducts
    Write-Verbose "Get-SecurityPosture: Found $($avProducts.Count) third-party AV product(s)"

    # Check for consumer AV (gap flags from standards)
    $consumerAVDetected = @()
    foreach ($flag in $Standards.antivirus.gap_flags) {
        foreach ($app in $rmmSecurityApps) {
            if ($app.AppName -match $flag -or $app.DisplayName -match $flag) {
                $consumerAVDetected += $app
            }
        }
    }
    $result.ConsumerAVDetected = $consumerAVDetected

    # --- Windows Firewall ---
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled
        $result.WindowsFirewall = @($firewallProfiles | ForEach-Object {
            @{
                Name    = $_.Name
                Enabled = $_.Enabled
            }
        })
        Write-Verbose "Get-SecurityPosture: Firewall profiles collected"
    }
    catch {
        Write-Verbose "Get-SecurityPosture: Failed to get firewall profiles — $($_.Exception.Message)"
        $result.WindowsFirewall = @()
    }

    # --- RMM Agents ---
    $rmmAgents = @()
    $rmmKeywords = @("NinjaOne", "ConnectWise", "Datto RMM")
    if ($rmmSecurityApps) {
        foreach ($app in $rmmSecurityApps) {
            foreach ($keyword in $rmmKeywords) {
                if ($app.AppName -match $keyword) {
                    $rmmAgents += $app
                    break
                }
            }
        }
    }
    $result.RMMAgents = $rmmAgents

    # Check for NinjaOne specifically
    $result.NinjaOneInstalled = ($rmmAgents | Where-Object { $_.AppName -eq "NinjaOne" }).Count -gt 0
    Write-Verbose "Get-SecurityPosture: NinjaOne installed = $($result.NinjaOneInstalled)"

    # Check for competing RMM agents
    $result.CompetingRMM = @($rmmAgents | Where-Object { $_.AppName -ne "NinjaOne" })

    # --- Open File Shares ---
    try {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^\$|^IPC\$|^ADMIN\$' }
        $result.OpenShares = @($shares | ForEach-Object {
            @{
                Name        = $_.Name
                Path        = $_.Path
                Description = $_.Description
            }
        })
        Write-Verbose "Get-SecurityPosture: Found $($result.OpenShares.Count) non-default share(s)"
    }
    catch {
        Write-Verbose "Get-SecurityPosture: Failed to get SMB shares — $($_.Exception.Message)"
        $result.OpenShares = @()
    }

    # --- Local Administrators ---
    try {
        $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $result.LocalAdmins = @($localAdmins | ForEach-Object {
            @{
                Name        = $_.Name
                ObjectClass = $_.ObjectClass
                PrincipalSource = if ($_.PrincipalSource) { $_.PrincipalSource.ToString() } else { "Unknown" }
            }
        })
        Write-Verbose "Get-SecurityPosture: Found $($result.LocalAdmins.Count) local admin(s)"
    }
    catch {
        Write-Verbose "Get-SecurityPosture: Failed to get local admins — $($_.Exception.Message)"
        # Fallback using net localgroup
        try {
            $netOutput = & net localgroup Administrators 2>$null
            $result.LocalAdmins = @()
            $capturing = $false
            foreach ($line in $netOutput) {
                if ($line -match '^-+$') { $capturing = $true; continue }
                if ($line -match 'The command completed') { break }
                if ($capturing -and $line.Trim()) {
                    $result.LocalAdmins += @{
                        Name        = $line.Trim()
                        ObjectClass = "Unknown"
                        PrincipalSource = "Unknown"
                    }
                }
            }
        }
        catch {
            $result.LocalAdmins = @()
        }
    }

    # --- DTCADMIN Check ---
    try {
        $dtcAdmin = Get-LocalUser -Name "DTCADMIN" -ErrorAction SilentlyContinue
        $result.DTCADMINExists = $null -ne $dtcAdmin
        if ($dtcAdmin) {
            $result.DTCADMINEnabled = $dtcAdmin.Enabled
        }
        else {
            $result.DTCADMINEnabled = $false
        }
        Write-Verbose "Get-SecurityPosture: DTCADMIN exists = $($result.DTCADMINExists)"
    }
    catch {
        Write-Verbose "Get-SecurityPosture: DTCADMIN check failed — $($_.Exception.Message)"
        $result.DTCADMINExists = $false
        $result.DTCADMINEnabled = $false
    }

    return $result
}
