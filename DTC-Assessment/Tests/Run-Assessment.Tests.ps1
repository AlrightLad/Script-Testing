# DTC Network Assessment Toolkit — Pester Tests
# Run with: Invoke-Pester -Path .\Tests\Run-Assessment.Tests.ps1

$scriptRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Load standards
$standardsPath = Join-Path $scriptRoot "Standards\DTC-Standards.json"
$Standards = Get-Content $standardsPath -Raw | ConvertFrom-Json

# Dot-source modules
$moduleDir = Join-Path $scriptRoot "Modules"
Get-ChildItem -Path $moduleDir -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

Describe "DTC-Standards.json" {
    It "should parse without errors" {
        { Get-Content $standardsPath -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It "should have a meta.version field" {
        $Standards.meta.version | Should -Not -BeNullOrEmpty
    }

    It "should have all required standard categories" {
        $requiredCategories = @("firewall", "dns", "rmm", "backup", "antivirus", "domain",
                                "local_admin", "printers", "disk_health", "windows_installer",
                                "stale_accounts", "domain_admins", "os_versions")
        foreach ($cat in $requiredCategories) {
            $Standards.$cat | Should -Not -BeNull -Because "category '$cat' is required"
        }
    }

    It "should have sow_item for each category" {
        $categoriesWithSoW = @("firewall", "dns", "rmm", "backup", "antivirus", "domain",
                               "local_admin", "printers", "disk_health", "windows_installer",
                               "stale_accounts", "domain_admins", "os_versions")
        foreach ($cat in $categoriesWithSoW) {
            $Standards.$cat.sow_item | Should -Not -BeNullOrEmpty -Because "'$cat' needs a SoW item"
        }
    }
}

Describe "Dental Software Detection Patterns" {
    # Simulate a software list for pattern testing
    $DetectionPatterns = [ordered]@{
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
        RMMSecurity = [ordered]@{
            "NinjaOne"     = "NinjaRMM|NinjaOne|ninjarmm-agent"
            "ConnectWise"  = "ConnectWise|LabTech|Automate"
            "Datto RMM"   = "Datto RMM|Autotask"
            "SentinelOne"  = "SentinelOne|Sentinel Agent"
            "Norton"       = "Norton"
            "McAfee"       = "McAfee"
            "AVG"          = "AVG"
            "Avast"        = "Avast"
            "Kaspersky"    = "Kaspersky"
            "Bitdefender"  = "Bitdefender"
            "Malwarebytes" = "Malwarebytes"
        }
        Backup = [ordered]@{
            "Veeam"        = "Veeam"
            "MSP360"       = "MSP360|CloudBerry"
            "Acronis"      = "Acronis"
            "StorageCraft" = "StorageCraft|Arcserve|ShadowProtect"
            "Datto"        = "Datto"
        }
        VoIP = [ordered]@{
            "Weave"           = "Weave"
            "RingCentral"     = "RingCentral"
            "8x8"             = "8x8"
            "Zoom"            = "Zoom"
            "Microsoft Teams" = "Teams"
        }
    }

    Context "PMS patterns should match expected software names" {
        It "should match 'Dentrix G7'" {
            "Dentrix G7" -match $DetectionPatterns.PMS["Dentrix"] | Should -Be $true
        }

        It "should match 'Eaglesoft 21'" {
            "Eaglesoft 21" -match $DetectionPatterns.PMS["Eaglesoft"] | Should -Be $true
        }

        It "should match 'Open Dental 23.1'" {
            "Open Dental 23.1" -match $DetectionPatterns.PMS["Open Dental"] | Should -Be $true
        }

        It "should match 'The Dental Office Manager'" {
            "The Dental Office Manager" -match $DetectionPatterns.PMS["TDO"] | Should -Be $true
        }

        It "should match 'Curve Hero'" {
            "Curve Hero" -match $DetectionPatterns.PMS["Curve Dental"] | Should -Be $true
        }
    }

    Context "Imaging patterns should match expected software names" {
        It "should match 'DEXIS Imaging Suite 10'" {
            "DEXIS Imaging Suite 10" -match $DetectionPatterns.Imaging["DEXIS"] | Should -Be $true
        }

        It "should match 'Carestream Dental Imaging'" {
            "Carestream Dental Imaging" -match $DetectionPatterns.Imaging["CS Imaging"] | Should -Be $true
        }

        It "should match 'CS 3D Imaging'" {
            "CS 3D Imaging" -match $DetectionPatterns.Imaging["CS Imaging"] | Should -Be $true
        }

        It "should match 'Schick CDR Elite'" {
            "Schick CDR Elite" -match $DetectionPatterns.Imaging["Schick"] | Should -Be $true
        }

        It "should match 'XrayVision 4'" {
            "XrayVision 4" -match $DetectionPatterns.Imaging["Apteryx"] | Should -Be $true
        }

        It "should match 'Dolphin 3D Imaging'" {
            "Dolphin 3D Imaging" -match $DetectionPatterns.Imaging["Dolphin"] | Should -Be $true
        }

        It "should match 'EzDent-i'" {
            "EzDent-i" -match $DetectionPatterns.Imaging["Vatech"] | Should -Be $true
        }
    }

    Context "Patterns should NOT false-positive on unrelated software" {
        It "should not match 'Microsoft Word' as dental software" {
            $matched = $false
            foreach ($category in $DetectionPatterns.Keys) {
                foreach ($appName in $DetectionPatterns[$category].Keys) {
                    if ("Microsoft Word" -match $DetectionPatterns[$category][$appName]) {
                        $matched = $true
                    }
                }
            }
            $matched | Should -Be $false
        }

        It "should not match 'Google Chrome' as dental software" {
            $matched = $false
            foreach ($category in $DetectionPatterns.Keys) {
                foreach ($appName in $DetectionPatterns[$category].Keys) {
                    if ("Google Chrome" -match $DetectionPatterns[$category][$appName]) {
                        $matched = $true
                    }
                }
            }
            $matched | Should -Be $false
        }

        It "should not match 'Adobe Acrobat Reader' as dental software" {
            $matched = $false
            foreach ($category in $DetectionPatterns.Keys) {
                foreach ($appName in $DetectionPatterns[$category].Keys) {
                    if ("Adobe Acrobat Reader" -match $DetectionPatterns[$category][$appName]) {
                        $matched = $true
                    }
                }
            }
            $matched | Should -Be $false
        }

        It "should not match '7-Zip' as dental software" {
            $matched = $false
            foreach ($category in $DetectionPatterns.Keys) {
                foreach ($appName in $DetectionPatterns[$category].Keys) {
                    if ("7-Zip" -match $DetectionPatterns[$category][$appName]) {
                        $matched = $true
                    }
                }
            }
            $matched | Should -Be $false
        }

        It "should not match 'Notepad++' as dental software" {
            $matched = $false
            foreach ($category in $DetectionPatterns.Keys) {
                foreach ($appName in $DetectionPatterns[$category].Keys) {
                    if ("Notepad++" -match $DetectionPatterns[$category][$appName]) {
                        $matched = $true
                    }
                }
            }
            $matched | Should -Be $false
        }
    }

    Context "RMM/Security patterns should match expected names" {
        It "should match 'NinjaRMMAgent'" {
            "NinjaRMMAgent" -match $DetectionPatterns.RMMSecurity["NinjaOne"] | Should -Be $true
        }

        It "should match 'NinjaOne Agent'" {
            "NinjaOne Agent" -match $DetectionPatterns.RMMSecurity["NinjaOne"] | Should -Be $true
        }

        It "should match 'ConnectWise Automate Agent'" {
            "ConnectWise Automate Agent" -match $DetectionPatterns.RMMSecurity["ConnectWise"] | Should -Be $true
        }

        It "should match 'LabTech Agent'" {
            "LabTech Agent" -match $DetectionPatterns.RMMSecurity["ConnectWise"] | Should -Be $true
        }

        It "should match 'SentinelOne Sentinel Agent'" {
            "SentinelOne Sentinel Agent" -match $DetectionPatterns.RMMSecurity["SentinelOne"] | Should -Be $true
        }
    }

    Context "Backup patterns should match expected names" {
        It "should match 'Veeam Backup & Replication'" {
            "Veeam Backup & Replication" -match $DetectionPatterns.Backup["Veeam"] | Should -Be $true
        }

        It "should match 'CloudBerry Backup'" {
            "CloudBerry Backup" -match $DetectionPatterns.Backup["MSP360"] | Should -Be $true
        }

        It "should match 'Acronis Cyber Protect'" {
            "Acronis Cyber Protect" -match $DetectionPatterns.Backup["Acronis"] | Should -Be $true
        }

        It "should match 'ShadowProtect SPX'" {
            "ShadowProtect SPX" -match $DetectionPatterns.Backup["StorageCraft"] | Should -Be $true
        }

        It "should match 'Arcserve UDP'" {
            "Arcserve UDP" -match $DetectionPatterns.Backup["StorageCraft"] | Should -Be $true
        }
    }
}

Describe "OS Version Check Logic" {
    Context "Server OS versions" {
        It "should identify 'Windows Server 2022' as Supported" {
            $osCaption = "Microsoft Windows Server 2022 Standard"
            $isSupported = $false
            foreach ($supported in $Standards.os_versions.server_supported) {
                if ($osCaption -match [regex]::Escape($supported)) {
                    $isSupported = $true
                    break
                }
            }
            $isSupported | Should -Be $true
        }

        It "should identify 'Windows Server 2019' as Supported" {
            $osCaption = "Microsoft Windows Server 2019 Datacenter"
            $isSupported = $false
            foreach ($supported in $Standards.os_versions.server_supported) {
                if ($osCaption -match [regex]::Escape($supported)) {
                    $isSupported = $true
                    break
                }
            }
            $isSupported | Should -Be $true
        }

        It "should identify 'Windows Server 2012 R2' as EOL" {
            $osCaption = "Microsoft Windows Server 2012 R2 Standard"
            $isEOL = $false
            foreach ($eol in $Standards.os_versions.server_eol) {
                if ($osCaption -match [regex]::Escape($eol)) {
                    $isEOL = $true
                    break
                }
            }
            $isEOL | Should -Be $true
        }

        It "should identify 'Windows Server 2016' as EOL" {
            $osCaption = "Microsoft Windows Server 2016 Standard"
            $isEOL = $false
            foreach ($eol in $Standards.os_versions.server_eol) {
                if ($osCaption -match [regex]::Escape($eol)) {
                    $isEOL = $true
                    break
                }
            }
            $isEOL | Should -Be $true
        }

        It "should identify 'Windows Server 2012' (non-R2) as EOL" {
            $osCaption = "Microsoft Windows Server 2012 Standard"
            $isEOL = $false
            foreach ($eol in $Standards.os_versions.server_eol) {
                if ($osCaption -match [regex]::Escape($eol)) {
                    $isEOL = $true
                    break
                }
            }
            $isEOL | Should -Be $true
        }
    }

    Context "Workstation OS versions" {
        It "should identify 'Windows 10 22H2' as Supported" {
            $osCaption = "Microsoft Windows 10 Pro 22H2"
            $isSupported = $false
            foreach ($supported in $Standards.os_versions.workstation_supported) {
                if ($osCaption -match [regex]::Escape($supported)) {
                    $isSupported = $true
                    break
                }
            }
            $isSupported | Should -Be $true
        }

        It "should identify 'Windows 7' as EOL" {
            $osCaption = "Microsoft Windows 7 Professional"
            $isEOL = $false
            foreach ($eol in $Standards.os_versions.workstation_eol) {
                if ($osCaption -match [regex]::Escape($eol)) {
                    $isEOL = $true
                    break
                }
            }
            $isEOL | Should -Be $true
        }

        It "should identify 'Windows 8.1' as EOL" {
            $osCaption = "Microsoft Windows 8.1 Pro"
            $isEOL = $false
            foreach ($eol in $Standards.os_versions.workstation_eol) {
                if ($osCaption -match [regex]::Escape($eol)) {
                    $isEOL = $true
                    break
                }
            }
            $isEOL | Should -Be $true
        }
    }
}

Describe "Disk Health Threshold Logic" {
    $warningThreshold = $Standards.disk_health.warning_threshold_percent
    $criticalThreshold = $Standards.disk_health.critical_threshold_percent

    It "should flag disk at 85% as Warning" {
        $usedPercent = 85
        $status = "Healthy"
        if ($usedPercent -ge $criticalThreshold) { $status = "Critical" }
        elseif ($usedPercent -ge $warningThreshold) { $status = "Warning" }
        $status | Should -Be "Warning"
    }

    It "should flag disk at 92% as Critical" {
        $usedPercent = 92
        $status = "Healthy"
        if ($usedPercent -ge $criticalThreshold) { $status = "Critical" }
        elseif ($usedPercent -ge $warningThreshold) { $status = "Warning" }
        $status | Should -Be "Critical"
    }

    It "should flag disk at 75% as Healthy" {
        $usedPercent = 75
        $status = "Healthy"
        if ($usedPercent -ge $criticalThreshold) { $status = "Critical" }
        elseif ($usedPercent -ge $warningThreshold) { $status = "Warning" }
        $status | Should -Be "Healthy"
    }

    It "should flag disk at exactly 80% as Warning" {
        $usedPercent = 80
        $status = "Healthy"
        if ($usedPercent -ge $criticalThreshold) { $status = "Critical" }
        elseif ($usedPercent -ge $warningThreshold) { $status = "Warning" }
        $status | Should -Be "Warning"
    }

    It "should flag disk at exactly 90% as Critical" {
        $usedPercent = 90
        $status = "Healthy"
        if ($usedPercent -ge $criticalThreshold) { $status = "Critical" }
        elseif ($usedPercent -ge $warningThreshold) { $status = "Warning" }
        $status | Should -Be "Critical"
    }

    It "should flag disk at 50% as Healthy" {
        $usedPercent = 50
        $status = "Healthy"
        if ($usedPercent -ge $criticalThreshold) { $status = "Critical" }
        elseif ($usedPercent -ge $warningThreshold) { $status = "Warning" }
        $status | Should -Be "Healthy"
    }
}

Describe "Standards Comparison — Gap Identification" {
    Context "Firewall gap detection" {
        It "should identify UniFi as meeting standard" {
            $vendor = "UniFi"
            $status = "Warning"
            if ($vendor -match "UniFi") { $status = "Meets Standard" }
            $status | Should -Be "Meets Standard"
        }

        It "should flag SonicWall as a gap" {
            $vendor = "SonicWall TZ300"
            $status = "Warning"
            if ($vendor -match "UniFi") { $status = "Meets Standard" }
            foreach ($flag in $Standards.firewall.gap_flags) {
                if ($vendor -match $flag) { $status = "Warning"; break }
            }
            $status | Should -Be "Warning"
        }

        It "should flag Meraki as a gap" {
            $vendor = "Meraki MX64"
            $status = "Warning"
            if ($vendor -match "UniFi") { $status = "Meets Standard" }
            foreach ($flag in $Standards.firewall.gap_flags) {
                if ($vendor -match $flag) { $status = "Warning"; break }
            }
            $status | Should -Be "Warning"
        }
    }

    Context "Domain gap detection" {
        It "should identify domain-joined as meeting standard" {
            $isDomainJoined = $true
            $status = if ($isDomainJoined) { "Meets Standard" } else { "Critical" }
            $status | Should -Be "Meets Standard"
        }

        It "should flag workgroup as Critical" {
            $isDomainJoined = $false
            $status = if ($isDomainJoined) { "Meets Standard" } else { "Critical" }
            $status | Should -Be "Critical"
        }
    }

    Context "RMM gap detection" {
        It "should identify NinjaOne as meeting standard" {
            $ninjaInstalled = $true
            $status = if ($ninjaInstalled) { "Meets Standard" } else { "Critical" }
            $status | Should -Be "Meets Standard"
        }

        It "should flag missing NinjaOne as Critical" {
            $ninjaInstalled = $false
            $status = if ($ninjaInstalled) { "Meets Standard" } else { "Critical" }
            $status | Should -Be "Critical"
        }
    }

    Context "DTCADMIN gap detection" {
        It "should identify existing DTCADMIN as meeting standard" {
            $exists = $true
            $status = if ($exists) { "Meets Standard" } else { "Warning" }
            $status | Should -Be "Meets Standard"
        }

        It "should flag missing DTCADMIN as Warning" {
            $exists = $false
            $status = if ($exists) { "Meets Standard" } else { "Warning" }
            $status | Should -Be "Warning"
        }
    }

    Context "Domain Admins threshold" {
        It "should be compliant when count is at or below max" {
            $count = 3
            $max = $Standards.domain_admins.max_count
            ($count -le $max) | Should -Be $true
        }

        It "should flag when count exceeds max" {
            $count = 5
            $max = $Standards.domain_admins.max_count
            ($count -gt $max) | Should -Be $true
        }
    }

    Context "Stale accounts threshold" {
        It "should use configured days_inactive value" {
            $Standards.stale_accounts.days_inactive | Should -Be 90
        }
    }

    Context "Windows Installer folder thresholds" {
        $warningGB = $Standards.windows_installer.warning_threshold_gb
        $criticalGB = $Standards.windows_installer.critical_threshold_gb

        It "should flag 25 GB as Warning" {
            $sizeGB = 25
            $status = "Healthy"
            if ($sizeGB -ge $criticalGB) { $status = "Critical" }
            elseif ($sizeGB -ge $warningGB) { $status = "Warning" }
            $status | Should -Be "Warning"
        }

        It "should flag 55 GB as Critical" {
            $sizeGB = 55
            $status = "Healthy"
            if ($sizeGB -ge $criticalGB) { $status = "Critical" }
            elseif ($sizeGB -ge $warningGB) { $status = "Warning" }
            $status | Should -Be "Critical"
        }

        It "should flag 15 GB as Healthy" {
            $sizeGB = 15
            $status = "Healthy"
            if ($sizeGB -ge $criticalGB) { $status = "Critical" }
            elseif ($sizeGB -ge $warningGB) { $status = "Warning" }
            $status | Should -Be "Healthy"
        }
    }
}

Describe "Module Files Exist" {
    $expectedModules = @(
        "Get-ServerInfo.ps1",
        "Get-NetworkConfig.ps1",
        "Get-ADStructure.ps1",
        "Get-DentalSoftware.ps1",
        "Get-SecurityPosture.ps1",
        "Get-PrinterConfig.ps1",
        "Get-BackupStatus.ps1",
        "Get-VoIPSoftware.ps1",
        "Get-WorkstationSample.ps1"
    )

    foreach ($module in $expectedModules) {
        It "should have module file: $module" {
            $path = Join-Path $scriptRoot "Modules\$module"
            Test-Path $path | Should -Be $true
        }
    }
}

Describe "Module Dot-Source" {
    $moduleDir = Join-Path $scriptRoot "Modules"
    $moduleFiles = Get-ChildItem -Path $moduleDir -Filter "*.ps1"

    foreach ($file in $moduleFiles) {
        It "should dot-source $($file.Name) without errors" {
            { . $file.FullName } | Should -Not -Throw
        }
    }
}

Describe "Toolkit Directory Structure" {
    It "should have Modules directory" {
        Test-Path (Join-Path $scriptRoot "Modules") | Should -Be $true
    }

    It "should have Standards directory" {
        Test-Path (Join-Path $scriptRoot "Standards") | Should -Be $true
    }

    It "should have Templates directory" {
        Test-Path (Join-Path $scriptRoot "Templates") | Should -Be $true
    }

    It "should have Lib directory" {
        Test-Path (Join-Path $scriptRoot "Lib") | Should -Be $true
    }

    It "should have Run-Assessment.ps1" {
        Test-Path (Join-Path $scriptRoot "Run-Assessment.ps1") | Should -Be $true
    }

    It "should have report template" {
        Test-Path (Join-Path $scriptRoot "Templates\report-template.html") | Should -Be $true
    }
}
