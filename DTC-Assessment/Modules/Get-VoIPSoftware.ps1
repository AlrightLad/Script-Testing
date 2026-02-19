function Get-VoIPSoftware {
    <#
    .SYNOPSIS
        Detects installed VoIP software from dental software scan results.
    .DESCRIPTION
        Extracts VoIP software detections from the dental software scan and documents
        known limitations — this module detects SOFTWARE only, not phone hardware,
        analog lines, VoIP providers, call trees, or VLAN assignments.
    .PARAMETER DentalSoftwareData
        The output from Get-DentalSoftware, used to identify detected VoIP software.
    .EXAMPLE
        $voipData = Get-VoIPSoftware -DentalSoftwareData $dentalData
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$DentalSoftwareData
    )

    Write-Verbose "Get-VoIPSoftware: Starting VoIP software detection"

    $result = @{}

    # --- VoIP Software (from dental software results) ---
    $result.DetectedVoIPSoftware = @()
    if ($DentalSoftwareData.DetectedSoftware.VoIP) {
        $result.DetectedVoIPSoftware = $DentalSoftwareData.DetectedSoftware.VoIP
    }
    Write-Verbose "Get-VoIPSoftware: Found $($result.DetectedVoIPSoftware.Count) VoIP software product(s)"

    # --- Summary ---
    $voipNames = @($result.DetectedVoIPSoftware | ForEach-Object { $_.AppName } | Select-Object -Unique)
    if ($voipNames.Count -eq 0) {
        $result.Summary = "No VoIP software detected on this server"
    }
    else {
        $result.Summary = "Detected: $($voipNames -join ', ')"
    }

    # --- Limitations Documentation ---
    $result.Limitations = @(
        "This module detects installed VoIP SOFTWARE only.",
        "It cannot detect: phone hardware (manufacturer, model, count)",
        "It cannot detect: analog/POTS lines",
        "It cannot detect: VoIP provider",
        "It cannot detect: call tree configuration",
        "It cannot detect: phone network VLAN assignment",
        "These items must be documented manually by the technician."
    )

    Write-Verbose "Get-VoIPSoftware: Summary = $($result.Summary)"

    return $result
}
