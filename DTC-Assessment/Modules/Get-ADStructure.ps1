function Get-ADStructure {
    <#
    .SYNOPSIS
        Collects Active Directory structure and health data.
    .DESCRIPTION
        Gathers domain information, OU structure, user statistics, stale accounts,
        Domain Admins membership, password policy, and GPO list. Gracefully handles
        workgroup machines and systems without the ActiveDirectory module.
    .PARAMETER Standards
        The DTC standards object loaded from DTC-Standards.json, used for stale account
        and Domain Admin thresholds.
    .EXAMPLE
        $adData = Get-ADStructure -Standards $standards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Standards
    )

    Write-Verbose "Get-ADStructure: Starting Active Directory data collection"

    # First check: Is this machine domain-joined?
    $cs = Get-WmiObject Win32_ComputerSystem
    if (-not $cs.PartOfDomain) {
        Write-Verbose "Get-ADStructure: Machine is not domain-joined"
        return @{
            Status  = "Workgroup"
            Message = "This machine is not domain-joined — no AD data available"
        }
    }

    # Second check: Is the ActiveDirectory PowerShell module available?
    if (-not (Get-Module -ListAvailable ActiveDirectory)) {
        Write-Verbose "Get-ADStructure: ActiveDirectory module not available"
        return @{
            Status  = "ModuleUnavailable"
            Message = "ActiveDirectory PowerShell module not installed on this server"
        }
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to import ActiveDirectory module — $($_.Exception.Message)"
        return @{
            Status  = "ModuleLoadFailed"
            Message = "Failed to load ActiveDirectory module: $($_.Exception.Message)"
        }
    }

    $result = @{
        Status = "DomainJoined"
    }

    # Domain info
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $result.DomainName = $domain.DNSRoot
        $result.DomainFunctionalLevel = $domain.DomainMode.ToString()
        $result.NetBIOSName = $domain.NetBIOSName
        Write-Verbose "Get-ADStructure: Domain = $($result.DomainName), Level = $($result.DomainFunctionalLevel)"
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to get domain info — $($_.Exception.Message)"
        $result.DomainName = "Unknown"
        $result.DomainFunctionalLevel = "Unknown"
        $result.NetBIOSName = "Unknown"
    }

    # Forest info
    try {
        $forest = Get-ADForest -ErrorAction Stop
        $result.ForestFunctionalLevel = $forest.ForestMode.ToString()
        Write-Verbose "Get-ADStructure: Forest level = $($result.ForestFunctionalLevel)"
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to get forest info — $($_.Exception.Message)"
        $result.ForestFunctionalLevel = "Unknown"
    }

    # OU structure
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName -ErrorAction Stop
        $result.OUTree = @()
        foreach ($ou in $ous) {
            # Calculate depth by counting commas minus the domain components
            $dnParts = $ou.DistinguishedName.Split(',')
            $dcCount = ($dnParts | Where-Object { $_ -match '^DC=' }).Count
            $depth = $dnParts.Count - $dcCount - 1  # subtract DCs and OU itself

            $result.OUTree += @{
                Name              = $ou.Name
                DistinguishedName = $ou.DistinguishedName
                Depth             = [math]::Max(0, $depth)
            }
        }
        $result.OUTree = @($result.OUTree | Sort-Object { $_.DistinguishedName })
        Write-Verbose "Get-ADStructure: Found $($result.OUTree.Count) OU(s)"
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to get OU structure — $($_.Exception.Message)"
        $result.OUTree = @()
    }

    # User statistics
    try {
        $enabledUsers = @(Get-ADUser -Filter { Enabled -eq $true } -ErrorAction Stop)
        $disabledUsers = @(Get-ADUser -Filter { Enabled -eq $false } -ErrorAction Stop)

        $staleThresholdDays = $Standards.stale_accounts.days_inactive
        $staleCutoff = (Get-Date).AddDays(-$staleThresholdDays)

        $staleUsers = @(Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate -ErrorAction Stop |
            Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $staleCutoff })

        $result.Users = @{
            EnabledCount  = $enabledUsers.Count
            DisabledCount = $disabledUsers.Count
            StaleCount    = $staleUsers.Count
            StaleAccounts = @($staleUsers | ForEach-Object {
                @{
                    Name          = $_.Name
                    SamAccountName = $_.SamAccountName
                    LastLogonDate = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
                }
            })
        }
        Write-Verbose "Get-ADStructure: Users — Enabled: $($result.Users.EnabledCount), Disabled: $($result.Users.DisabledCount), Stale: $($result.Users.StaleCount)"
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to get user stats — $($_.Exception.Message)"
        $result.Users = @{
            EnabledCount  = 0
            DisabledCount = 0
            StaleCount    = 0
            StaleAccounts = @()
        }
    }

    # Domain Admins
    try {
        $domainAdmins = Get-ADGroupMember "Domain Admins" -ErrorAction Stop
        $result.DomainAdmins = @($domainAdmins | ForEach-Object {
            @{
                Name           = $_.Name
                SamAccountName = $_.SamAccountName
            }
        })
        $result.DomainAdminCount = $result.DomainAdmins.Count
        Write-Verbose "Get-ADStructure: Domain Admins count = $($result.DomainAdminCount)"
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to get Domain Admins — $($_.Exception.Message)"
        $result.DomainAdmins = @()
        $result.DomainAdminCount = 0
    }

    # Password policy
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $result.PasswordPolicy = @{
            MinLength         = $policy.MinPasswordLength
            MaxAgeDays        = $policy.MaxPasswordAge.Days
            HistoryCount      = $policy.PasswordHistoryCount
            ComplexityEnabled = $policy.ComplexityEnabled
            LockoutThreshold  = $policy.LockoutThreshold
        }
        Write-Verbose "Get-ADStructure: Password policy — MinLength: $($result.PasswordPolicy.MinLength), Complexity: $($result.PasswordPolicy.ComplexityEnabled)"
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to get password policy — $($_.Exception.Message)"
        $result.PasswordPolicy = @{
            MinLength         = 0
            MaxAgeDays        = 0
            HistoryCount      = 0
            ComplexityEnabled = $false
            LockoutThreshold  = 0
        }
    }

    # GPOs
    try {
        if (Get-Module -ListAvailable GroupPolicy) {
            Import-Module GroupPolicy -ErrorAction Stop
            $gpos = Get-GPO -All -ErrorAction Stop
            $result.GPOs = @($gpos | ForEach-Object {
                @{
                    Name         = $_.DisplayName
                    Status       = $_.GpoStatus.ToString()
                    LastModified = $_.ModificationTime.ToString("yyyy-MM-dd HH:mm:ss")
                }
            })
            Write-Verbose "Get-ADStructure: Found $($result.GPOs.Count) GPO(s)"
        }
        else {
            $result.GPOs = @()
            Write-Verbose "Get-ADStructure: GroupPolicy module not available"
        }
    }
    catch {
        Write-Verbose "Get-ADStructure: Failed to get GPOs — $($_.Exception.Message)"
        $result.GPOs = @()
    }

    return $result
}
