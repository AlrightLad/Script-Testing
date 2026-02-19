<#
.SYNOPSIS
    DTC Network Assessment Toolkit — Main Orchestrator
.DESCRIPTION
    Runs all assessment modules against a client's server, compares results against
    DTC infrastructure standards, generates a gap analysis, and produces a professional
    PDF report for attachment to a HALO PSA ticket. Designed for field technicians
    running from a USB drive on Windows Server 2016/2019/2022.
.PARAMETER ClientName
    Required. The client/practice name used in report headers and output filenames.
.PARAMETER TechName
    Required. The technician name printed on the report.
.PARAMETER HaloTicket
    Optional. HALO PSA ticket number to print on the report.
.PARAMETER ScanWorkstations
    Optional. Array of workstation IP addresses for remote spot-check scanning.
.PARAMETER Verbose
    Optional switch. Enables detailed progress output for troubleshooting.
.EXAMPLE
    .\Run-Assessment.ps1 -ClientName "Happy Smiles Dental" -TechName "John Smith"
.EXAMPLE
    .\Run-Assessment.ps1 -ClientName "Happy Smiles" -TechName "John Smith" -HaloTicket "12345" -ScanWorkstations "10.0.1.50","10.0.1.51"
#>
[CmdletBinding()]
param(
    [string]$ClientName,
    [string]$TechName,
    [string]$HaloTicket,
    [string[]]$ScanWorkstations
)

#region --- Elevation Check ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Red
    Write-Host "  ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "========================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Right-click PowerShell and select 'Run as Administrator'," -ForegroundColor Yellow
    Write-Host "then navigate back to this folder and run the script again." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
#endregion

#region --- Interactive Prompts ---
if (-not $ClientName) {
    $ClientName = Read-Host "Enter client/practice name"
    if (-not $ClientName) {
        Write-Host "Client name is required. Exiting." -ForegroundColor Red
        exit 1
    }
}

if (-not $TechName) {
    $TechName = Read-Host "Enter technician name"
    if (-not $TechName) {
        Write-Host "Technician name is required. Exiting." -ForegroundColor Red
        exit 1
    }
}
#endregion

#region --- Validate Toolkit Structure ---
$scriptRoot = $PSScriptRoot
Write-Verbose "Script root: $scriptRoot"

$requiredDirs = @("Modules", "Standards", "Lib")
foreach ($dir in $requiredDirs) {
    $dirPath = Join-Path $scriptRoot $dir
    if (-not (Test-Path $dirPath)) {
        Write-Host "ERROR: Required directory '$dir' not found at $dirPath" -ForegroundColor Red
        Write-Host "Ensure the toolkit USB has the complete directory structure." -ForegroundColor Yellow
        exit 1
    }
}

# Create Output directory if missing
$outputDir = Join-Path $scriptRoot "Output"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Verbose "Created Output directory: $outputDir"
}
#endregion

#region --- Load Standards ---
$standardsPath = Join-Path $scriptRoot "Standards\DTC-Standards.json"
if (-not (Test-Path $standardsPath)) {
    Write-Host "ERROR: DTC-Standards.json not found at $standardsPath" -ForegroundColor Red
    exit 1
}

try {
    $standardsRaw = Get-Content $standardsPath -Raw -ErrorAction Stop
    $Standards = $standardsRaw | ConvertFrom-Json
    if (-not $Standards.meta.version) {
        Write-Host "ERROR: DTC-Standards.json is missing the 'meta.version' field" -ForegroundColor Red
        exit 1
    }
    Write-Verbose "Loaded DTC-Standards.json v$($Standards.meta.version)"
}
catch {
    Write-Host "ERROR: Failed to parse DTC-Standards.json — $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region --- Load Modules ---
$moduleFiles = @(
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

foreach ($moduleFile in $moduleFiles) {
    $modulePath = Join-Path $scriptRoot "Modules\$moduleFile"
    if (Test-Path $modulePath) {
        . $modulePath
        Write-Verbose "Loaded module: $moduleFile"
    }
    else {
        Write-Warning "Module not found: $modulePath"
    }
}
#endregion

#region --- Initialize Data Collection ---
$AssessmentData = @{
    Meta = @{
        ClientName    = $ClientName
        TechName      = $TechName
        HaloTicket    = $HaloTicket
        AssessmentDate = (Get-Date -Format "yyyy-MM-dd")
        AssessmentTime = (Get-Date -Format "HH:mm:ss")
        ToolkitVersion = $Standards.meta.version
        ServerName     = $env:COMPUTERNAME
    }
}
$Script:ErrorLog = @()
$assessmentStart = Get-Date

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  DTC Network Assessment Toolkit v$($Standards.meta.version)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Client:     $ClientName" -ForegroundColor White
Write-Host "  Technician: $TechName" -ForegroundColor White
if ($HaloTicket) { Write-Host "  HALO Ticket: $HaloTicket" -ForegroundColor White }
Write-Host "  Date:       $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "  Server:     $env:COMPUTERNAME" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
#endregion

#region --- Execute Modules ---
$moduleSteps = @(
    @{ Name = "Get-ServerInfo";       Label = "Collecting server info...";        Percent = 10 }
    @{ Name = "Get-NetworkConfig";    Label = "Scanning network configuration..."; Percent = 25 }
    @{ Name = "Get-ADStructure";      Label = "Querying Active Directory...";      Percent = 40 }
    @{ Name = "Get-DentalSoftware";   Label = "Detecting dental software...";      Percent = 50 }
    @{ Name = "Get-SecurityPosture";  Label = "Assessing security posture...";     Percent = 60 }
    @{ Name = "Get-PrinterConfig";    Label = "Checking printer configuration..."; Percent = 70 }
    @{ Name = "Get-BackupStatus";     Label = "Checking backup status...";         Percent = 80 }
    @{ Name = "Get-VoIPSoftware";     Label = "Detecting VoIP software...";        Percent = 85 }
)

# Step 1: Server Info
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[0].Label -PercentComplete $moduleSteps[0].Percent
    Write-Host "[1/9] $($moduleSteps[0].Label)" -ForegroundColor Yellow
    $AssessmentData.Server = Get-ServerInfo -Standards $Standards
    Write-Host "  [OK] Server info collected" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-ServerInfo"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.Server = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 2: Network Config
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[1].Label -PercentComplete $moduleSteps[1].Percent
    Write-Host "[2/9] $($moduleSteps[1].Label)" -ForegroundColor Yellow
    $AssessmentData.Network = Get-NetworkConfig -Standards $Standards
    Write-Host "  [OK] Network configuration collected" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-NetworkConfig"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.Network = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 3: AD Structure
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[2].Label -PercentComplete $moduleSteps[2].Percent
    Write-Host "[3/9] $($moduleSteps[2].Label)" -ForegroundColor Yellow
    $AssessmentData.ActiveDirectory = Get-ADStructure -Standards $Standards
    Write-Host "  [OK] Active Directory data collected" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-ADStructure"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.ActiveDirectory = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 4: Dental Software
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[3].Label -PercentComplete $moduleSteps[3].Percent
    Write-Host "[4/9] $($moduleSteps[3].Label)" -ForegroundColor Yellow
    $AssessmentData.DentalSoftware = Get-DentalSoftware
    Write-Host "  [OK] Dental software detection complete" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-DentalSoftware"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.DentalSoftware = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 5: Security Posture (depends on DentalSoftware)
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[4].Label -PercentComplete $moduleSteps[4].Percent
    Write-Host "[5/9] $($moduleSteps[4].Label)" -ForegroundColor Yellow
    $dentalDataForSecurity = if ($AssessmentData.DentalSoftware.Error) {
        @{ DetectedSoftware = @{ RMMSecurity = @() }; WindowsDefender = @{} }
    } else {
        $AssessmentData.DentalSoftware
    }
    $AssessmentData.Security = Get-SecurityPosture -DentalSoftwareData $dentalDataForSecurity -Standards $Standards
    Write-Host "  [OK] Security posture assessed" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-SecurityPosture"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.Security = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 6: Printer Config
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[5].Label -PercentComplete $moduleSteps[5].Percent
    Write-Host "[6/9] $($moduleSteps[5].Label)" -ForegroundColor Yellow
    $AssessmentData.Printers = Get-PrinterConfig -Standards $Standards
    Write-Host "  [OK] Printer configuration collected" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-PrinterConfig"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.Printers = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 7: Backup Status (depends on DentalSoftware)
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[6].Label -PercentComplete $moduleSteps[6].Percent
    Write-Host "[7/9] $($moduleSteps[6].Label)" -ForegroundColor Yellow
    $dentalDataForBackup = if ($AssessmentData.DentalSoftware.Error) {
        @{ DetectedSoftware = @{ Backup = @() } }
    } else {
        $AssessmentData.DentalSoftware
    }
    $AssessmentData.Backup = Get-BackupStatus -DentalSoftwareData $dentalDataForBackup -Standards $Standards
    Write-Host "  [OK] Backup status checked" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-BackupStatus"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.Backup = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 8: VoIP Software (depends on DentalSoftware)
try {
    Write-Progress -Activity "DTC Assessment" -Status $moduleSteps[7].Label -PercentComplete $moduleSteps[7].Percent
    Write-Host "[8/9] $($moduleSteps[7].Label)" -ForegroundColor Yellow
    $dentalDataForVoIP = if ($AssessmentData.DentalSoftware.Error) {
        @{ DetectedSoftware = @{ VoIP = @() } }
    } else {
        $AssessmentData.DentalSoftware
    }
    $AssessmentData.VoIP = Get-VoIPSoftware -DentalSoftwareData $dentalDataForVoIP
    Write-Host "  [OK] VoIP software detected" -ForegroundColor Green
}
catch {
    $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-VoIPSoftware"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
    $AssessmentData.VoIP = @{ Error = $_.Exception.Message }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

# Step 9: Workstation Samples (optional)
if ($ScanWorkstations -and $ScanWorkstations.Count -gt 0) {
    try {
        Write-Progress -Activity "DTC Assessment" -Status "Scanning workstations..." -PercentComplete 90
        Write-Host "[9/9] Scanning $($ScanWorkstations.Count) workstation(s)..." -ForegroundColor Yellow
        $AssessmentData.Workstations = Get-WorkstationSample -WorkstationIPs $ScanWorkstations -Standards $Standards
        Write-Host "  [OK] Workstation scan complete" -ForegroundColor Green
    }
    catch {
        $Script:ErrorLog += [PSCustomObject]@{ Module = "Get-WorkstationSample"; Error = $_.Exception.Message; Timestamp = (Get-Date -Format "o") }
        $AssessmentData.Workstations = @{ Error = $_.Exception.Message }
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "[9/9] Workstation scan skipped (no -ScanWorkstations provided)" -ForegroundColor DarkGray
}

Write-Progress -Activity "DTC Assessment" -Completed
#endregion

#region --- Standards Comparison / Gap Analysis ---
Write-Host ""
Write-Host "Running gap analysis against DTC standards..." -ForegroundColor Yellow

$GapAnalysis = @()

# 1. Firewall
$fwVendor = if ($AssessmentData.Network.GatewayFingerprint) { $AssessmentData.Network.GatewayFingerprint.DetectedVendor } else { "Unknown" }
$fwStatus = "Warning"
if ($fwVendor -match "UniFi") {
    $fwStatus = "Meets Standard"
}
elseif ($fwVendor -match "Unknown") {
    $fwStatus = "Warning"
}
else {
    foreach ($flag in $Standards.firewall.gap_flags) {
        if ($fwVendor -match $flag) {
            $fwStatus = "Warning"
            break
        }
    }
}
$GapAnalysis += @{
    Category     = "Firewall"
    CurrentState = "$fwVendor detected at gateway $($AssessmentData.Network.DefaultGateway)"
    DTCStandard  = $Standards.firewall.standard
    Status       = $fwStatus
    SoWItem      = if ($fwStatus -ne "Meets Standard") { $Standards.firewall.sow_item } else { "" }
}

# 2. DNS
$dnsCompliant = if ($AssessmentData.Network.DNSCompliance) { $AssessmentData.Network.DNSCompliance.Compliant } else { $false }
$dnsDetails = if ($AssessmentData.Network.DNSCompliance) { ($AssessmentData.Network.DNSCompliance.Details -join "; ") } else { "Unable to determine" }
$GapAnalysis += @{
    Category     = "DNS Configuration"
    CurrentState = $dnsDetails
    DTCStandard  = $Standards.dns.standard
    Status       = if ($dnsCompliant) { "Meets Standard" } else { "Warning" }
    SoWItem      = if (-not $dnsCompliant) { $Standards.dns.sow_item } else { "" }
}

# 3. Domain
$domainStatus = if ($AssessmentData.ActiveDirectory.Status) { $AssessmentData.ActiveDirectory.Status } else { "Unknown" }
if ($domainStatus -eq "DomainJoined") {
    $GapAnalysis += @{
        Category     = "Active Directory"
        CurrentState = "Domain-joined: $($AssessmentData.ActiveDirectory.DomainName)"
        DTCStandard  = $Standards.domain.standard
        Status       = "Meets Standard"
        SoWItem      = ""
    }
}
else {
    $GapAnalysis += @{
        Category     = "Active Directory"
        CurrentState = "Workgroup configuration — $($AssessmentData.ActiveDirectory.Message)"
        DTCStandard  = $Standards.domain.standard
        Status       = "Critical"
        SoWItem      = $Standards.domain.sow_item
    }
}

# 4. RMM
$ninjaInstalled = if ($AssessmentData.Security.NinjaOneInstalled) { $true } else { $false }
$competingRMM = if ($AssessmentData.Security.CompetingRMM) { $AssessmentData.Security.CompetingRMM } else { @() }
$rmmCurrentState = if ($ninjaInstalled) { "NinjaOne installed" } else { "NinjaOne NOT installed" }
if ($competingRMM.Count -gt 0) {
    $competingNames = ($competingRMM | ForEach-Object { $_.AppName }) -join ", "
    $rmmCurrentState += " | Competing: $competingNames"
}
$GapAnalysis += @{
    Category     = "RMM Agent"
    CurrentState = $rmmCurrentState
    DTCStandard  = $Standards.rmm.standard
    Status       = if ($ninjaInstalled) { "Meets Standard" } else { "Critical" }
    SoWItem      = if (-not $ninjaInstalled) { $Standards.rmm.sow_item } else { "" }
}

# 5. Backup
$veeamInstalled = if ($AssessmentData.Backup.VeeamInstalled) { $true } else { $false }
$backupSummary = if ($AssessmentData.Backup.Summary) { $AssessmentData.Backup.Summary } else { "No backup software detected" }
$GapAnalysis += @{
    Category     = "Backup"
    CurrentState = $backupSummary
    DTCStandard  = $Standards.backup.standard
    Status       = if ($veeamInstalled) { "Meets Standard" } else { "Warning" }
    SoWItem      = $Standards.backup.sow_item
}

# 6. Antivirus
$consumerAV = if ($AssessmentData.Security.ConsumerAVDetected) { $AssessmentData.Security.ConsumerAVDetected } else { @() }
$defenderEnabled = if ($AssessmentData.Security.WindowsDefender.Enabled -eq $true) { $true } else { $false }
$avCurrentState = if ($defenderEnabled) { "Windows Defender active" } else { "Windows Defender not active or unknown" }
if ($consumerAV.Count -gt 0) {
    $consumerNames = ($consumerAV | ForEach-Object { $_.AppName }) -join ", "
    $avCurrentState += " | Consumer AV detected: $consumerNames"
}
$avStatus = "Meets Standard"
if ($consumerAV.Count -gt 0) { $avStatus = "Critical" }
elseif (-not $defenderEnabled) { $avStatus = "Warning" }
$GapAnalysis += @{
    Category     = "Antivirus"
    CurrentState = $avCurrentState
    DTCStandard  = $Standards.antivirus.standard
    Status       = $avStatus
    SoWItem      = if ($avStatus -ne "Meets Standard") { $Standards.antivirus.sow_item } else { "" }
}

# 7. Local Admin (DTCADMIN)
$dtcAdminExists = if ($AssessmentData.Security.DTCADMINExists) { $true } else { $false }
$GapAnalysis += @{
    Category     = "Local Admin (DTCADMIN)"
    CurrentState = if ($dtcAdminExists) { "DTCADMIN account exists" } else { "DTCADMIN account NOT found" }
    DTCStandard  = $Standards.local_admin.standard
    Status       = if ($dtcAdminExists) { "Meets Standard" } else { "Warning" }
    SoWItem      = if (-not $dtcAdminExists) { $Standards.local_admin.sow_item } else { "" }
}

# 8. Printers
$hasDirectIP = if ($AssessmentData.Printers.HasDirectIPPrinters) { $true } else { $false }
$printServerInstalled = if ($AssessmentData.Printers.PrintServerInstalled) { $true } else { $false }
$printerCurrentState = "Print Server: $(if ($printServerInstalled) {'Installed'} else {'Not installed'})"
if ($hasDirectIP) {
    $directCount = $AssessmentData.Printers.DirectIPPrinters.Count
    $printerCurrentState += " | $directCount direct IP printer(s) detected"
}
$GapAnalysis += @{
    Category     = "Printers"
    CurrentState = $printerCurrentState
    DTCStandard  = $Standards.printers.standard
    Status       = if ($hasDirectIP -or -not $printServerInstalled) { "Warning" } else { "Meets Standard" }
    SoWItem      = if ($hasDirectIP -or -not $printServerInstalled) { $Standards.printers.sow_item } else { "" }
}

# 9. Disk Health
if ($AssessmentData.Server.Disks) {
    foreach ($disk in $AssessmentData.Server.Disks) {
        if ($disk.Status -ne "Healthy") {
            $GapAnalysis += @{
                Category     = "Disk Health ($($disk.Drive))"
                CurrentState = "$($disk.UsedPercent)% used ($($disk.FreeGB) GB free of $($disk.SizeGB) GB)"
                DTCStandard  = "Below $($Standards.disk_health.warning_threshold_percent)% utilization"
                Status       = $disk.Status
                SoWItem      = $Standards.disk_health.sow_item
            }
        }
    }
}

# 10. Windows Installer Folder
$installerGB = if ($AssessmentData.Server.InstallerFolderGB) { $AssessmentData.Server.InstallerFolderGB } else { 0 }
if ($installerGB -ge $Standards.windows_installer.warning_threshold_gb) {
    $installerStatus = if ($installerGB -ge $Standards.windows_installer.critical_threshold_gb) { "Critical" } else { "Warning" }
    $GapAnalysis += @{
        Category     = "Windows Installer Folder"
        CurrentState = "$installerGB GB (Ref: $($Standards.windows_installer.reference))"
        DTCStandard  = "Below $($Standards.windows_installer.warning_threshold_gb) GB"
        Status       = $installerStatus
        SoWItem      = $Standards.windows_installer.sow_item
    }
}

# 11. OS Version
$osVersionStatus = if ($AssessmentData.Server.OSVersionStatus) { $AssessmentData.Server.OSVersionStatus } else { "Unknown" }
$osCaption = if ($AssessmentData.Server.OS.Caption) { $AssessmentData.Server.OS.Caption } else { "Unknown" }
if ($osVersionStatus -eq "EOL") {
    $GapAnalysis += @{
        Category     = "Server OS Version"
        CurrentState = "$osCaption — End of Life"
        DTCStandard  = "Supported: $($Standards.os_versions.server_supported -join ', ')"
        Status       = "Critical"
        SoWItem      = $Standards.os_versions.sow_item
    }
}
elseif ($osVersionStatus -eq "Unknown") {
    $GapAnalysis += @{
        Category     = "Server OS Version"
        CurrentState = "$osCaption — version not in standards list"
        DTCStandard  = "Supported: $($Standards.os_versions.server_supported -join ', ')"
        Status       = "Warning"
        SoWItem      = $Standards.os_versions.sow_item
    }
}

# 12. Stale Accounts
if ($AssessmentData.ActiveDirectory.Status -eq "DomainJoined" -and $AssessmentData.ActiveDirectory.Users) {
    $staleCount = $AssessmentData.ActiveDirectory.Users.StaleCount
    if ($staleCount -gt 0) {
        $GapAnalysis += @{
            Category     = "Stale AD Accounts"
            CurrentState = "$staleCount account(s) inactive > $($Standards.stale_accounts.days_inactive) days"
            DTCStandard  = "No accounts inactive > $($Standards.stale_accounts.days_inactive) days"
            Status       = "Warning"
            SoWItem      = $Standards.stale_accounts.sow_item
        }
    }
}

# 13. Domain Admins count
if ($AssessmentData.ActiveDirectory.Status -eq "DomainJoined" -and $AssessmentData.ActiveDirectory.DomainAdminCount) {
    $daCount = $AssessmentData.ActiveDirectory.DomainAdminCount
    if ($daCount -gt $Standards.domain_admins.max_count) {
        $GapAnalysis += @{
            Category     = "Domain Admins"
            CurrentState = "$daCount Domain Admin(s) (max recommended: $($Standards.domain_admins.max_count))"
            DTCStandard  = "Maximum $($Standards.domain_admins.max_count) Domain Admins"
            Status       = "Warning"
            SoWItem      = $Standards.domain_admins.sow_item
        }
    }
}

$AssessmentData.GapAnalysis = $GapAnalysis
$AssessmentData.ErrorLog = $Script:ErrorLog

# Severity counts
$criticalCount = ($GapAnalysis | Where-Object { $_.Status -eq "Critical" }).Count
$warningCount = ($GapAnalysis | Where-Object { $_.Status -eq "Warning" }).Count
$meetsCount = ($GapAnalysis | Where-Object { $_.Status -eq "Meets Standard" }).Count

Write-Host "  Gap analysis complete: " -NoNewline -ForegroundColor Green
Write-Host "$criticalCount Critical " -NoNewline -ForegroundColor Red
Write-Host "$warningCount Warning " -NoNewline -ForegroundColor Yellow
Write-Host "$meetsCount Meets Standard" -ForegroundColor Green
#endregion

#region --- Generate HTML Report ---
Write-Host ""
Write-Host "Generating report..." -ForegroundColor Yellow

$templatePath = Join-Path $scriptRoot "Templates\report-template.html"
if (Test-Path $templatePath) {
    $htmlTemplate = Get-Content $templatePath -Raw
}
else {
    Write-Warning "HTML template not found at $templatePath — generating basic report"
    $htmlTemplate = "<html><head><title>DTC Assessment</title></head><body>{{REPORT_BODY}}</body></html>"
}

# Build report sections
$reportDate = Get-Date -Format "MMMM dd, yyyy"
$reportTime = Get-Date -Format "hh:mm tt"

# --- Cover Page ---
$logoPath = Join-Path $scriptRoot "Lib\dtc-logo.png"
$logoBase64 = ""
if (Test-Path $logoPath) {
    try {
        $logoBytes = [System.IO.File]::ReadAllBytes($logoPath)
        $logoBase64 = [Convert]::ToBase64String($logoBytes)
    }
    catch {
        Write-Verbose "Failed to encode logo: $($_.Exception.Message)"
    }
}

# --- Executive Summary ---
$topGapDrivers = @($GapAnalysis | Where-Object { $_.Status -ne "Meets Standard" } | Select-Object -First 5)
$execSummaryItems = ""
foreach ($gap in $topGapDrivers) {
    $statusIcon = if ($gap.Status -eq "Critical") { "&#x1F534;" } else { "&#x1F7E1;" }
    $execSummaryItems += "<li>$statusIcon <strong>$($gap.Category)</strong>: $($gap.CurrentState)</li>`n"
}
if (-not $execSummaryItems) {
    $execSummaryItems = "<li>&#x1F7E2; All assessed categories meet DTC standards</li>"
}

# --- Server Info Table ---
$serverInfoHTML = ""
if ($AssessmentData.Server -and -not $AssessmentData.Server.Error) {
    $s = $AssessmentData.Server
    $serverInfoHTML = @"
<table class="data-table">
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Computer Name</td><td>$($s.ComputerName)</td></tr>
    <tr><td>Domain</td><td>$($s.Domain) $(if ($s.IsDomainJoined) {'(Domain-joined)'} else {'(Workgroup)'})</td></tr>
    <tr><td>Operating System</td><td>$($s.OS.Caption)</td></tr>
    <tr><td>OS Version</td><td>$($s.OS.Version) (Build $($s.OS.BuildNumber))</td></tr>
    <tr><td>OS Status</td><td><span class="status-$($s.OSVersionStatus.ToLower())">$($s.OSVersionStatus)</span></td></tr>
    <tr><td>Install Date</td><td>$($s.OS.InstallDate)</td></tr>
    <tr><td>Last Boot</td><td>$($s.OS.LastBoot)</td></tr>
    <tr><td>Uptime</td><td>$($s.UptimeDays) days</td></tr>
    <tr><td>CPU</td><td>$($s.CPU.Name)</td></tr>
    <tr><td>CPU Cores / Logical</td><td>$($s.CPU.Cores) / $($s.CPU.LogicalProcessors)</td></tr>
    <tr><td>RAM</td><td>$($s.RAMTotalGB) GB</td></tr>
    <tr><td>Windows Installer Folder</td><td>$($s.InstallerFolderGB) GB</td></tr>
</table>
"@

    # Disk table
    if ($s.Disks.Count -gt 0) {
        $diskRows = ""
        foreach ($disk in $s.Disks) {
            $barClass = "bar-green"
            if ($disk.Status -eq "Critical") { $barClass = "bar-red" }
            elseif ($disk.Status -eq "Warning") { $barClass = "bar-amber" }
            $diskRows += @"
    <tr>
        <td>$($disk.Drive)</td>
        <td>$($disk.SizeGB) GB</td>
        <td>$($disk.FreeGB) GB</td>
        <td>
            <div class="progress-bar"><div class="progress-fill $barClass" style="width: $($disk.UsedPercent)%"></div></div>
            $($disk.UsedPercent)%
        </td>
        <td><span class="status-$(($disk.Status).ToLower())">$($disk.Status)</span></td>
    </tr>
"@
        }
        $serverInfoHTML += @"
<h3>Disk Utilization</h3>
<table class="data-table">
    <tr><th>Drive</th><th>Size</th><th>Free</th><th>Used</th><th>Status</th></tr>
    $diskRows
</table>
"@
    }

    # Hotfixes
    if ($s.RecentHotfixes.Count -gt 0) {
        $hfRows = ""
        foreach ($hf in $s.RecentHotfixes) {
            $hfRows += "<tr><td>$($hf.HotFixID)</td><td>$($hf.Description)</td><td>$($hf.InstalledOn)</td></tr>`n"
        }
        $serverInfoHTML += @"
<h3>Recent Hotfixes</h3>
<table class="data-table">
    <tr><th>HotFix ID</th><th>Description</th><th>Installed</th></tr>
    $hfRows
</table>
"@
    }
}
else {
    $serverInfoHTML = "<p class='error'>Server information could not be collected.</p>"
}

# --- Network Section ---
$networkHTML = ""
if ($AssessmentData.Network -and -not $AssessmentData.Network.Error) {
    $n = $AssessmentData.Network
    # Adapters
    $adapterRows = ""
    foreach ($adapter in $n.Adapters) {
        $ips = if ($adapter.IPAddresses) { $adapter.IPAddresses -join ", " } else { "N/A" }
        $dns = if ($adapter.DNSServers) { $adapter.DNSServers -join ", " } else { "N/A" }
        $adapterRows += "<tr><td>$($adapter.Name)</td><td>$($adapter.Status)</td><td>$($adapter.LinkSpeed)</td><td>$($adapter.MacAddress)</td><td>$ips</td><td>$dns</td></tr>`n"
    }
    $networkHTML = @"
<table class="data-table">
    <tr><th>Adapter</th><th>Status</th><th>Link Speed</th><th>MAC</th><th>IP Addresses</th><th>DNS Servers</th></tr>
    $adapterRows
</table>
<h3>Network Summary</h3>
<table class="data-table">
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Default Gateway</td><td>$($n.DefaultGateway)</td></tr>
    <tr><td>DHCP</td><td>$($n.DHCPStatus)</td></tr>
    <tr><td>Active Devices (discovery)</td><td>$($n.DeviceDiscovery.ActiveDeviceCount) device(s) on $($n.DeviceDiscovery.IPRange)</td></tr>
    <tr><td>Discovery Duration</td><td>$($n.DeviceDiscovery.SweepDuration) seconds</td></tr>
    <tr><td>Gateway Fingerprint</td><td>$($n.GatewayFingerprint.DetectedVendor) ($($n.GatewayFingerprint.Method))</td></tr>
    <tr><td>DNS Compliance</td><td><span class="status-$(if ($n.DNSCompliance.Compliant) {'meets standard'} else {'warning'})">$(if ($n.DNSCompliance.Compliant) {'Compliant'} else {'Non-compliant'})</span></td></tr>
</table>
"@

    # DHCP Scopes
    if ($n.DHCPScopes.Count -gt 0) {
        $scopeRows = ""
        foreach ($scope in $n.DHCPScopes) {
            $scopeRows += "<tr><td>$($scope.ScopeId)</td><td>$($scope.Name)</td><td>$($scope.StartRange)</td><td>$($scope.EndRange)</td><td>$($scope.SubnetMask)</td><td>$($scope.State)</td></tr>`n"
        }
        $networkHTML += @"
<h3>DHCP Scopes</h3>
<table class="data-table">
    <tr><th>Scope ID</th><th>Name</th><th>Start</th><th>End</th><th>Subnet</th><th>State</th></tr>
    $scopeRows
</table>
"@
    }
}
else {
    $networkHTML = "<p class='error'>Network configuration could not be collected.</p>"
}

# --- AD Section ---
$adHTML = ""
if ($AssessmentData.ActiveDirectory) {
    $ad = $AssessmentData.ActiveDirectory
    if ($ad.Status -eq "DomainJoined") {
        $adHTML = @"
<table class="data-table">
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Domain Name</td><td>$($ad.DomainName)</td></tr>
    <tr><td>Domain Functional Level</td><td>$($ad.DomainFunctionalLevel)</td></tr>
    <tr><td>Forest Functional Level</td><td>$($ad.ForestFunctionalLevel)</td></tr>
    <tr><td>Enabled Users</td><td>$($ad.Users.EnabledCount)</td></tr>
    <tr><td>Disabled Users</td><td>$($ad.Users.DisabledCount)</td></tr>
    <tr><td>Stale Accounts (&gt;$($Standards.stale_accounts.days_inactive) days)</td><td><span class="$(if ($ad.Users.StaleCount -gt 0) {'status-warning'} else {'status-meets standard'})">$($ad.Users.StaleCount)</span></td></tr>
    <tr><td>Domain Admins</td><td><span class="$(if ($ad.DomainAdminCount -gt $Standards.domain_admins.max_count) {'status-warning'} else {'status-meets standard'})">$($ad.DomainAdminCount)</span></td></tr>
</table>
"@
        # Domain Admins list
        if ($ad.DomainAdmins.Count -gt 0) {
            $daRows = ""
            foreach ($da in $ad.DomainAdmins) {
                $daRows += "<tr><td>$($da.Name)</td><td>$($da.SamAccountName)</td></tr>`n"
            }
            $adHTML += @"
<h3>Domain Admins</h3>
<table class="data-table">
    <tr><th>Name</th><th>SAM Account</th></tr>
    $daRows
</table>
"@
        }

        # Password Policy
        if ($ad.PasswordPolicy) {
            $pp = $ad.PasswordPolicy
            $adHTML += @"
<h3>Password Policy</h3>
<table class="data-table">
    <tr><th>Setting</th><th>Value</th></tr>
    <tr><td>Minimum Length</td><td>$($pp.MinLength)</td></tr>
    <tr><td>Max Age (days)</td><td>$($pp.MaxAgeDays)</td></tr>
    <tr><td>History Count</td><td>$($pp.HistoryCount)</td></tr>
    <tr><td>Complexity Required</td><td>$($pp.ComplexityEnabled)</td></tr>
    <tr><td>Lockout Threshold</td><td>$($pp.LockoutThreshold)</td></tr>
</table>
"@
        }

        # GPOs
        if ($ad.GPOs.Count -gt 0) {
            $gpoRows = ""
            foreach ($gpo in $ad.GPOs) {
                $gpoRows += "<tr><td>$($gpo.Name)</td><td>$($gpo.Status)</td><td>$($gpo.LastModified)</td></tr>`n"
            }
            $adHTML += @"
<h3>Group Policy Objects</h3>
<table class="data-table">
    <tr><th>GPO Name</th><th>Status</th><th>Last Modified</th></tr>
    $gpoRows
</table>
"@
        }

        # OU Tree
        if ($ad.OUTree.Count -gt 0) {
            $ouItems = ""
            foreach ($ou in $ad.OUTree) {
                $indent = "&nbsp;&nbsp;&nbsp;&nbsp;" * $ou.Depth
                $ouItems += "<tr><td>${indent}$($ou.Name)</td><td>$($ou.DistinguishedName)</td></tr>`n"
            }
            $adHTML += @"
<h3>Organizational Units</h3>
<table class="data-table">
    <tr><th>Name</th><th>Distinguished Name</th></tr>
    $ouItems
</table>
"@
        }
    }
    else {
        $adHTML = "<div class='info-box'>$($ad.Message)</div>"
    }
}

# --- Dental Software Section ---
$dentalHTML = ""
if ($AssessmentData.DentalSoftware -and -not $AssessmentData.DentalSoftware.Error) {
    $ds = $AssessmentData.DentalSoftware
    $categoryLabels = @{
        PMS            = "Practice Management Systems"
        Imaging        = "Imaging Platforms"
        ImagingDrivers = "Imaging Drivers & Services"
        VoIP           = "VoIP Software"
        Backup         = "Backup Software"
        RMMSecurity    = "RMM & Security"
        Utilities      = "Dental Utilities"
    }
    foreach ($cat in @("PMS", "Imaging", "ImagingDrivers", "VoIP", "Backup", "RMMSecurity", "Utilities")) {
        $apps = $ds.DetectedSoftware[$cat]
        if ($apps -and $apps.Count -gt 0) {
            $appRows = ""
            foreach ($app in $apps) {
                $appRows += "<tr><td>$($app.AppName)</td><td>$($app.DisplayName)</td><td>$($app.Version)</td><td>$($app.InstallDate)</td></tr>`n"
            }
            $dentalHTML += @"
<h3>$($categoryLabels[$cat])</h3>
<table class="data-table">
    <tr><th>Category Match</th><th>Display Name</th><th>Version</th><th>Install Date</th></tr>
    $appRows
</table>
"@
        }
    }
    if (-not $dentalHTML) {
        $dentalHTML = "<p>No dental-specific software detected in registry.</p>"
    }
}
else {
    $dentalHTML = "<p class='error'>Dental software detection could not be completed.</p>"
}

# --- Security Section ---
$securityHTML = ""
if ($AssessmentData.Security -and -not $AssessmentData.Security.Error) {
    $sec = $AssessmentData.Security
    # Defender
    $defStatus = if ($sec.WindowsDefender.Enabled -eq $true) { "Active" } elseif ($sec.WindowsDefender.Enabled -eq $false) { "Disabled" } else { "Unknown" }
    $rtpStatus = if ($sec.WindowsDefender.RealTimeProtection -eq $true) { "Enabled" } elseif ($sec.WindowsDefender.RealTimeProtection -eq $false) { "Disabled" } else { "Unknown" }
    $securityHTML = @"
<h3>Windows Defender</h3>
<table class="data-table">
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Antivirus Status</td><td>$defStatus</td></tr>
    <tr><td>Real-Time Protection</td><td>$rtpStatus</td></tr>
    <tr><td>Signature Date</td><td>$($sec.WindowsDefender.SignatureDate)</td></tr>
</table>
"@

    # Firewall profiles
    if ($sec.WindowsFirewall.Count -gt 0) {
        $fwRows = ""
        foreach ($profile in $sec.WindowsFirewall) {
            $fwRows += "<tr><td>$($profile.Name)</td><td>$(if ($profile.Enabled) {'Enabled'} else {'Disabled'})</td></tr>`n"
        }
        $securityHTML += @"
<h3>Windows Firewall</h3>
<table class="data-table">
    <tr><th>Profile</th><th>Status</th></tr>
    $fwRows
</table>
"@
    }

    # RMM Agents
    if ($sec.RMMAgents.Count -gt 0) {
        $rmmRows = ""
        foreach ($agent in $sec.RMMAgents) {
            $rmmRows += "<tr><td>$($agent.AppName)</td><td>$($agent.DisplayName)</td><td>$($agent.Version)</td></tr>`n"
        }
        $securityHTML += @"
<h3>RMM Agents</h3>
<table class="data-table">
    <tr><th>Agent</th><th>Display Name</th><th>Version</th></tr>
    $rmmRows
</table>
"@
    }
    else {
        $securityHTML += "<h3>RMM Agents</h3><p>No RMM agents detected.</p>"
    }

    # Open Shares
    if ($sec.OpenShares.Count -gt 0) {
        $shareRows = ""
        foreach ($share in $sec.OpenShares) {
            $shareRows += "<tr><td>$($share.Name)</td><td>$($share.Path)</td><td>$($share.Description)</td></tr>`n"
        }
        $securityHTML += @"
<h3>Open File Shares</h3>
<table class="data-table">
    <tr><th>Name</th><th>Path</th><th>Description</th></tr>
    $shareRows
</table>
"@
    }

    # Local Admins
    if ($sec.LocalAdmins.Count -gt 0) {
        $adminRows = ""
        foreach ($admin in $sec.LocalAdmins) {
            $adminRows += "<tr><td>$($admin.Name)</td><td>$($admin.ObjectClass)</td></tr>`n"
        }
        $securityHTML += @"
<h3>Local Administrators</h3>
<table class="data-table">
    <tr><th>Name</th><th>Type</th></tr>
    $adminRows
</table>
<p>DTCADMIN Account: <strong>$(if ($sec.DTCADMINExists) {'Exists'} else {'Not Found'})</strong></p>
"@
    }
}
else {
    $securityHTML = "<p class='error'>Security posture could not be assessed.</p>"
}

# --- Backup Section ---
$backupHTML = ""
if ($AssessmentData.Backup -and -not $AssessmentData.Backup.Error) {
    $bk = $AssessmentData.Backup
    if ($bk.DetectedBackupSoftware.Count -gt 0) {
        $bkRows = ""
        foreach ($sw in $bk.DetectedBackupSoftware) {
            $bkRows += "<tr><td>$($sw.AppName)</td><td>$($sw.DisplayName)</td><td>$($sw.Version)</td></tr>`n"
        }
        $backupHTML = @"
<table class="data-table">
    <tr><th>Product</th><th>Display Name</th><th>Version</th></tr>
    $bkRows
</table>
"@
    }
    else {
        $backupHTML = "<p>No backup software detected on this server.</p>"
    }

    # Veeam jobs
    if ($bk.VeeamJobs.Count -gt 0) {
        $jobRows = ""
        foreach ($job in $bk.VeeamJobs) {
            $jobRows += "<tr><td>$($job.Name)</td><td>$($job.LatestResult)</td><td>$($job.NextRun)</td><td>$($job.IsEnabled)</td></tr>`n"
        }
        $backupHTML += @"
<h3>Veeam Backup Jobs</h3>
<table class="data-table">
    <tr><th>Job Name</th><th>Last Result</th><th>Next Run</th><th>Enabled</th></tr>
    $jobRows
</table>
"@
    }
    elseif ($bk.VeeamJobsNote) {
        $backupHTML += "<p><em>$($bk.VeeamJobsNote)</em></p>"
    }

    $backupHTML += "<div class='info-box'><strong>Note:</strong> $($bk.DTCNote)</div>"
}
else {
    $backupHTML = "<p class='error'>Backup status could not be determined.</p>"
}

# --- Printer Section ---
$printerHTML = ""
if ($AssessmentData.Printers -and -not $AssessmentData.Printers.Error) {
    $pr = $AssessmentData.Printers
    $printerHTML = "<p>Print Server Role: <strong>$(if ($pr.PrintServerInstalled) {'Installed'} else {'Not installed'})</strong></p>"

    if ($pr.Printers.Count -gt 0) {
        $prRows = ""
        foreach ($printer in $pr.Printers) {
            $prRows += "<tr><td>$($printer.Name)</td><td>$($printer.DriverName)</td><td>$($printer.PortName)</td><td>$($printer.Shared)</td><td>$($printer.Type)</td></tr>`n"
        }
        $printerHTML += @"
<table class="data-table">
    <tr><th>Name</th><th>Driver</th><th>Port</th><th>Shared</th><th>Type</th></tr>
    $prRows
</table>
"@
    }

    if ($pr.DirectIPPrinters.Count -gt 0) {
        $directRows = ""
        foreach ($dp in $pr.DirectIPPrinters) {
            $directRows += "<tr><td>$($dp.Name)</td><td>$($dp.IPAddress)</td><td>$($dp.Driver)</td></tr>`n"
        }
        $printerHTML += @"
<h3>Direct IP Printers (Gap)</h3>
<p class="warning-text">These printers use direct IP connections instead of the DTC-standard print server + GPO deployment:</p>
<table class="data-table">
    <tr><th>Printer</th><th>IP Address</th><th>Driver</th></tr>
    $directRows
</table>
"@
    }
}
else {
    $printerHTML = "<p class='error'>Printer configuration could not be collected.</p>"
}

# --- Workstation Section ---
$workstationHTML = ""
if ($AssessmentData.Workstations -and $AssessmentData.Workstations -is [array]) {
    foreach ($ws in $AssessmentData.Workstations) {
        $workstationHTML += "<h3>Workstation: $($ws.IPAddress)</h3>"
        if (-not $ws.Reachable) {
            $workstationHTML += "<p class='error'>$($ws.Error)</p>"
            continue
        }
        $workstationHTML += "<p>Collection method: $($ws.Method)</p>"
        if ($ws.Data.OS) {
            $workstationHTML += "<table class='data-table'><tr><th>Property</th><th>Value</th></tr>"
            $workstationHTML += "<tr><td>OS</td><td>$($ws.Data.OS.Caption)</td></tr>"
            if ($ws.Data.OSVersionStatus) {
                $workstationHTML += "<tr><td>OS Status</td><td><span class='status-$($ws.Data.OSVersionStatus.ToLower())'>$($ws.Data.OSVersionStatus)</span></td></tr>"
            }
            if ($ws.Data.Disks) {
                foreach ($disk in $ws.Data.Disks) {
                    $workstationHTML += "<tr><td>Disk $($disk.Drive)</td><td>$($disk.UsedPercent)% used ($($disk.FreeGB) GB free)</td></tr>"
                }
            }
            if ($ws.Data.InstallerFolderGB) {
                $workstationHTML += "<tr><td>Installer Folder</td><td>$($ws.Data.InstallerFolderGB) GB</td></tr>"
            }
            if ($ws.Data.LocalAdmins) {
                $workstationHTML += "<tr><td>Local Admins</td><td>$($ws.Data.LocalAdmins -join ', ')</td></tr>"
            }
            $workstationHTML += "</table>"
        }
    }
}

# --- Gap Analysis Table ---
$gapHTML = ""
foreach ($gap in $GapAnalysis) {
    $statusClass = switch ($gap.Status) {
        "Critical"       { "status-critical" }
        "Warning"        { "status-warning" }
        "Meets Standard" { "status-meets-standard" }
        default          { "" }
    }
    $statusIcon = switch ($gap.Status) {
        "Critical"       { "&#x1F534;" }
        "Warning"        { "&#x1F7E1;" }
        "Meets Standard" { "&#x1F7E2;" }
        default          { "" }
    }
    $gapHTML += @"
    <tr>
        <td>$($gap.Category)</td>
        <td>$($gap.CurrentState)</td>
        <td>$($gap.DTCStandard)</td>
        <td class="$statusClass">$statusIcon $($gap.Status)</td>
        <td>$($gap.SoWItem)</td>
    </tr>
"@
}

# --- Appendix: All Installed Software ---
$allSoftwareHTML = ""
if ($AssessmentData.DentalSoftware.AllInstalledSoftware) {
    $swRows = ""
    foreach ($sw in $AssessmentData.DentalSoftware.AllInstalledSoftware) {
        $swRows += "<tr><td>$($sw.DisplayName)</td><td>$($sw.DisplayVersion)</td><td>$($sw.Publisher)</td><td>$($sw.InstallDate)</td></tr>`n"
    }
    $allSoftwareHTML = @"
<table class="data-table">
    <tr><th>Name</th><th>Version</th><th>Publisher</th><th>Install Date</th></tr>
    $swRows
</table>
"@
}

# --- Appendix: Services ---
$servicesHTML = ""
try {
    $services = Get-Service | Sort-Object Status, DisplayName
    $svcRows = ""
    foreach ($svc in $services) {
        $svcRows += "<tr><td>$($svc.DisplayName)</td><td>$($svc.Name)</td><td>$($svc.Status)</td><td>$($svc.StartType)</td></tr>`n"
    }
    $servicesHTML = @"
<table class="data-table">
    <tr><th>Display Name</th><th>Service Name</th><th>Status</th><th>Start Type</th></tr>
    $svcRows
</table>
"@
}
catch {
    $servicesHTML = "<p>Service list could not be collected.</p>"
}

# --- Appendix: AD Users ---
$adUsersHTML = ""
if ($AssessmentData.ActiveDirectory.Status -eq "DomainJoined") {
    try {
        $allADUsers = Get-ADUser -Filter * -Properties LastLogonDate, Enabled | Sort-Object Name
        $userRows = ""
        foreach ($user in $allADUsers) {
            $lastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
            $userRows += "<tr><td>$($user.Name)</td><td>$($user.SamAccountName)</td><td>$($user.Enabled)</td><td>$lastLogon</td></tr>`n"
        }
        $adUsersHTML = @"
<table class="data-table">
    <tr><th>Name</th><th>SAM Account</th><th>Enabled</th><th>Last Logon</th></tr>
    $userRows
</table>
"@
    }
    catch {
        $adUsersHTML = "<p>AD user export could not be completed.</p>"
    }
}

# --- Assemble Full HTML ---
$htmlContent = $htmlTemplate

# Replace tokens
$htmlContent = $htmlContent -replace '{{CLIENT_NAME}}', $ClientName
$htmlContent = $htmlContent -replace '{{TECH_NAME}}', $TechName
$htmlContent = $htmlContent -replace '{{REPORT_DATE}}', $reportDate
$htmlContent = $htmlContent -replace '{{REPORT_TIME}}', $reportTime
$htmlContent = $htmlContent -replace '{{HALO_TICKET}}', $(if ($HaloTicket) { "HALO Ticket: $HaloTicket" } else { "" })
$htmlContent = $htmlContent -replace '{{LOGO_BASE64}}', $logoBase64
$htmlContent = $htmlContent -replace '{{STANDARDS_VERSION}}', $Standards.meta.version
$htmlContent = $htmlContent -replace '{{CRITICAL_COUNT}}', $criticalCount.ToString()
$htmlContent = $htmlContent -replace '{{WARNING_COUNT}}', $warningCount.ToString()
$htmlContent = $htmlContent -replace '{{MEETS_COUNT}}', $meetsCount.ToString()
$htmlContent = $htmlContent -replace '{{EXEC_SUMMARY_ITEMS}}', $execSummaryItems
$htmlContent = $htmlContent -replace '{{SERVER_INFO}}', $serverInfoHTML
$htmlContent = $htmlContent -replace '{{NETWORK_INFO}}', $networkHTML
$htmlContent = $htmlContent -replace '{{AD_INFO}}', $adHTML
$htmlContent = $htmlContent -replace '{{DENTAL_SOFTWARE}}', $dentalHTML
$htmlContent = $htmlContent -replace '{{SECURITY_INFO}}', $securityHTML
$htmlContent = $htmlContent -replace '{{BACKUP_INFO}}', $backupHTML
$htmlContent = $htmlContent -replace '{{PRINTER_INFO}}', $printerHTML
$htmlContent = $htmlContent -replace '{{WORKSTATION_INFO}}', $workstationHTML
$htmlContent = $htmlContent -replace '{{GAP_ANALYSIS_ROWS}}', $gapHTML
$htmlContent = $htmlContent -replace '{{ALL_SOFTWARE}}', $allSoftwareHTML
$htmlContent = $htmlContent -replace '{{SERVICES_LIST}}', $servicesHTML
$htmlContent = $htmlContent -replace '{{AD_USERS}}', $adUsersHTML
$htmlContent = $htmlContent -replace '{{SERVER_NAME}}', $env:COMPUTERNAME
$htmlContent = $htmlContent -replace '{{TOTAL_GAPS}}', ($criticalCount + $warningCount).ToString()

# VoIP section
$voipHTML = ""
if ($AssessmentData.VoIP -and -not $AssessmentData.VoIP.Error) {
    $voip = $AssessmentData.VoIP
    if ($voip.DetectedVoIPSoftware.Count -gt 0) {
        $voipRows = ""
        foreach ($v in $voip.DetectedVoIPSoftware) {
            $voipRows += "<tr><td>$($v.AppName)</td><td>$($v.DisplayName)</td><td>$($v.Version)</td></tr>`n"
        }
        $voipHTML = @"
<table class="data-table">
    <tr><th>Product</th><th>Display Name</th><th>Version</th></tr>
    $voipRows
</table>
"@
    }
    else {
        $voipHTML = "<p>No VoIP software detected on this server.</p>"
    }
    $voipHTML += "<div class='info-box'><strong>Limitations:</strong><ul>"
    foreach ($lim in $voip.Limitations) {
        $voipHTML += "<li>$lim</li>"
    }
    $voipHTML += "</ul></div>"
}
$htmlContent = $htmlContent -replace '{{VOIP_INFO}}', $voipHTML

# Error log
$errorHTML = ""
if ($Script:ErrorLog.Count -gt 0) {
    $errRows = ""
    foreach ($err in $Script:ErrorLog) {
        $errRows += "<tr><td>$($err.Module)</td><td>$($err.Error)</td><td>$($err.Timestamp)</td></tr>`n"
    }
    $errorHTML = @"
<h3>Collection Errors</h3>
<table class="data-table">
    <tr><th>Module</th><th>Error</th><th>Timestamp</th></tr>
    $errRows
</table>
"@
}
$htmlContent = $htmlContent -replace '{{ERROR_LOG}}', $errorHTML
#endregion

#region --- PDF Generation ---
$dateStamp = Get-Date -Format "yyyy-MM-dd"
$safeClientName = $ClientName -replace '[^\w\-]', '_'

$wkhtmltopdfPath = Join-Path $scriptRoot "Lib\wkhtmltopdf.exe"
if (Test-Path $wkhtmltopdfPath) {
    $htmlPath = Join-Path $outputDir "temp_report.html"
    $pdfPath = Join-Path $outputDir "${safeClientName}_Assessment_${dateStamp}.pdf"

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8

    Write-Host "  Converting to PDF..." -ForegroundColor Yellow
    try {
        & $wkhtmltopdfPath --quiet --page-size Letter --margin-top 15mm --margin-bottom 15mm --margin-left 10mm --margin-right 10mm $htmlPath $pdfPath 2>$null
        if (Test-Path $pdfPath) {
            Remove-Item $htmlPath -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] PDF generated" -ForegroundColor Green
        }
        else {
            Write-Warning "PDF generation may have failed — saving HTML fallback"
            $htmlFallback = Join-Path $outputDir "${safeClientName}_Assessment_${dateStamp}.html"
            Move-Item $htmlPath $htmlFallback -Force
        }
    }
    catch {
        Write-Warning "PDF conversion error: $($_.Exception.Message) — saving HTML fallback"
        $htmlFallback = Join-Path $outputDir "${safeClientName}_Assessment_${dateStamp}.html"
        Move-Item $htmlPath $htmlFallback -Force
    }
}
else {
    $htmlPath = Join-Path $outputDir "${safeClientName}_Assessment_${dateStamp}.html"
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Warning "wkhtmltopdf.exe not found in Lib/ — saved as HTML instead"
}
#endregion

#region --- Save Raw JSON ---
$jsonPath = Join-Path $outputDir "${safeClientName}_RawData_${dateStamp}.json"
try {
    $AssessmentData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "  [OK] Raw JSON saved" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to save JSON: $($_.Exception.Message)"
}
#endregion

#region --- Completion Summary ---
$assessmentDuration = ((Get-Date) - $assessmentStart).TotalSeconds

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Assessment Complete!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Client:       $ClientName" -ForegroundColor White
Write-Host "  Duration:     $([math]::Round($assessmentDuration, 0)) seconds" -ForegroundColor White
Write-Host ""
Write-Host "  Findings:" -ForegroundColor White
Write-Host "    Critical:       $criticalCount" -ForegroundColor Red
Write-Host "    Warning:        $warningCount" -ForegroundColor Yellow
Write-Host "    Meets Standard: $meetsCount" -ForegroundColor Green
Write-Host ""

if (Test-Path (Join-Path $outputDir "${safeClientName}_Assessment_${dateStamp}.pdf")) {
    Write-Host "  Report: $(Join-Path $outputDir "${safeClientName}_Assessment_${dateStamp}.pdf")" -ForegroundColor Cyan
}
else {
    Write-Host "  Report: $(Join-Path $outputDir "${safeClientName}_Assessment_${dateStamp}.html")" -ForegroundColor Cyan
}
Write-Host "  Raw Data: $jsonPath" -ForegroundColor Cyan

if ($Script:ErrorLog.Count -gt 0) {
    Write-Host ""
    Write-Host "  Errors during collection ($($Script:ErrorLog.Count)):" -ForegroundColor Yellow
    foreach ($err in $Script:ErrorLog) {
        Write-Host "    - $($err.Module): $($err.Error)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Attach the report to HALO ticket$(if ($HaloTicket) {" $HaloTicket"})." -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
#endregion
