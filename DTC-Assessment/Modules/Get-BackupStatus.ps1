function Get-BackupStatus {
    <#
    .SYNOPSIS
        Detects backup software and queries Veeam job status if available.
    .DESCRIPTION
        Uses dental software detection results to identify backup products, checks
        Veeam services and job status via PowerShell snap-in when available, and
        includes DTC deployment note about Veeam BDR onboarding.
    .PARAMETER DentalSoftwareData
        The output from Get-DentalSoftware, used to identify detected backup software.
    .PARAMETER Standards
        The DTC standards object loaded from DTC-Standards.json.
    .EXAMPLE
        $backupData = Get-BackupStatus -DentalSoftwareData $dentalData -Standards $standards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$DentalSoftwareData,

        [Parameter(Mandatory = $true)]
        [PSObject]$Standards
    )

    Write-Verbose "Get-BackupStatus: Starting backup status collection"

    $result = @{}

    # --- Backup Software Detection (from dental software results) ---
    $result.DetectedBackupSoftware = @()
    if ($DentalSoftwareData.DetectedSoftware.Backup) {
        $result.DetectedBackupSoftware = $DentalSoftwareData.DetectedSoftware.Backup
    }
    Write-Verbose "Get-BackupStatus: Found $($result.DetectedBackupSoftware.Count) backup product(s)"

    # --- Veeam Specific Checks ---
    $veeamDetected = ($result.DetectedBackupSoftware | Where-Object { $_.AppName -eq "Veeam" }).Count -gt 0
    $result.VeeamInstalled = $veeamDetected

    if ($veeamDetected) {
        Write-Verbose "Get-BackupStatus: Veeam detected — checking services and jobs"

        # Veeam services
        try {
            $veeamServices = Get-Service -Name "Veeam*" -ErrorAction Stop
            $result.VeeamServices = @($veeamServices | ForEach-Object {
                @{
                    Name        = $_.Name
                    DisplayName = $_.DisplayName
                    Status      = $_.Status.ToString()
                    StartType   = $_.StartType.ToString()
                }
            })
            Write-Verbose "Get-BackupStatus: Found $($result.VeeamServices.Count) Veeam service(s)"
        }
        catch {
            Write-Verbose "Get-BackupStatus: Failed to get Veeam services — $($_.Exception.Message)"
            $result.VeeamServices = @()
        }

        # Veeam B&R job status via snap-in
        try {
            Add-PSSnapin VeeamPSSnapin -ErrorAction Stop
            $vbrJobs = Get-VBRJob -ErrorAction Stop
            $result.VeeamJobs = @($vbrJobs | ForEach-Object {
                @{
                    Name         = $_.Name
                    LatestResult = $_.GetLastResult().ToString()
                    NextRun      = if ($_.GetScheduleOptions().NextRun) { $_.GetScheduleOptions().NextRun.ToString("yyyy-MM-dd HH:mm:ss") } else { "Not scheduled" }
                    IsEnabled    = $_.IsScheduleEnabled
                }
            })
            Write-Verbose "Get-BackupStatus: Found $($result.VeeamJobs.Count) Veeam B&R job(s)"
        }
        catch {
            Write-Verbose "Get-BackupStatus: Veeam PS snap-in not available — $($_.Exception.Message)"
            $result.VeeamJobs = @()
            $result.VeeamJobsNote = "Veeam PowerShell snap-in not available — job details could not be queried"
        }
    }
    else {
        $result.VeeamServices = @()
        $result.VeeamJobs = @()
    }

    # --- DTC Deployment Note ---
    $result.DTCNote = $Standards.backup.note

    # --- Summary ---
    $backupNames = @($result.DetectedBackupSoftware | ForEach-Object { $_.AppName } | Select-Object -Unique)
    if ($backupNames.Count -eq 0) {
        $result.Summary = "No backup software detected"
    }
    else {
        $result.Summary = "Detected: $($backupNames -join ', ')"
    }

    Write-Verbose "Get-BackupStatus: Summary = $($result.Summary)"

    return $result
}
