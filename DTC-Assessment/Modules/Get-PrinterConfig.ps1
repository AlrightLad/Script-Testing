function Get-PrinterConfig {
    <#
    .SYNOPSIS
        Collects printer configuration including drivers, ports, and print server status.
    .DESCRIPTION
        Gathers installed printers, printer ports, detects Print and Document Services role,
        and flags direct IP printers vs. print server managed printers per DTC standards.
    .PARAMETER Standards
        The DTC standards object loaded from DTC-Standards.json.
    .EXAMPLE
        $printerData = Get-PrinterConfig -Standards $standards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Standards
    )

    Write-Verbose "Get-PrinterConfig: Starting printer configuration collection"

    $result = @{}

    # --- Installed Printers ---
    try {
        $printers = Get-Printer -ErrorAction Stop
        $result.Printers = @($printers | ForEach-Object {
            @{
                Name       = $_.Name
                DriverName = $_.DriverName
                PortName   = $_.PortName
                Shared     = $_.Shared
                Published  = $_.Published
                Type       = $_.Type.ToString()
            }
        })
        Write-Verbose "Get-PrinterConfig: Found $($result.Printers.Count) printer(s)"
    }
    catch {
        Write-Verbose "Get-PrinterConfig: Failed to get printers — $($_.Exception.Message)"
        $result.Printers = @()
    }

    # --- Printer Ports ---
    try {
        $ports = Get-PrinterPort -ErrorAction Stop
        $result.PrinterPorts = @($ports | ForEach-Object {
            @{
                Name            = $_.Name
                PrinterHostAddress = $_.PrinterHostAddress
                PortMonitor     = $_.PortMonitor
            }
        })
        Write-Verbose "Get-PrinterConfig: Found $($result.PrinterPorts.Count) printer port(s)"
    }
    catch {
        Write-Verbose "Get-PrinterConfig: Failed to get printer ports — $($_.Exception.Message)"
        $result.PrinterPorts = @()
    }

    # --- Print Server Detection ---
    try {
        $printServerInstalled = $false
        try {
            $feature = Get-WindowsFeature -Name 'Print-Server' -ErrorAction SilentlyContinue
            if ($feature -and $feature.Installed) {
                $printServerInstalled = $true
            }
        }
        catch {
            Write-Verbose "Get-PrinterConfig: Get-WindowsFeature not available"
            # Fallback: check for Print Spooler service and shared printers
            $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
            if ($spooler -and $spooler.Status -eq 'Running') {
                $sharedPrinters = @($result.Printers | Where-Object { $_.Shared -eq $true })
                if ($sharedPrinters.Count -gt 0) {
                    $printServerInstalled = $true
                }
            }
        }

        $result.PrintServerInstalled = $printServerInstalled
        Write-Verbose "Get-PrinterConfig: Print Server role installed = $printServerInstalled"
    }
    catch {
        Write-Verbose "Get-PrinterConfig: Print server detection failed — $($_.Exception.Message)"
        $result.PrintServerInstalled = $false
    }

    # --- Direct IP vs. Print Server Analysis ---
    $directIPPrinters = @()
    $printServerPrinters = @()

    foreach ($printer in $result.Printers) {
        $portName = $printer.PortName
        $portInfo = $result.PrinterPorts | Where-Object { $_.Name -eq $portName }

        # Determine if this is a direct IP connection
        $isDirect = $false

        if ($portName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
            $isDirect = $true
        }
        elseif ($portName -match '^IP_') {
            $isDirect = $true
        }
        elseif ($portName -match '^TCP/IP') {
            $isDirect = $true
        }
        elseif ($portInfo -and $portInfo.PrinterHostAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
            $isDirect = $true
        }

        # Skip virtual / system printers
        if ($printer.Name -match 'Microsoft|XPS|PDF|Fax|OneNote|Send To') {
            continue
        }

        if ($isDirect) {
            $directIPPrinters += @{
                Name     = $printer.Name
                Port     = $portName
                Driver   = $printer.DriverName
                IPAddress = if ($portInfo.PrinterHostAddress) { $portInfo.PrinterHostAddress } else { $portName }
            }
        }
        else {
            $printServerPrinters += @{
                Name   = $printer.Name
                Port   = $portName
                Driver = $printer.DriverName
                Shared = $printer.Shared
            }
        }
    }

    $result.DirectIPPrinters = $directIPPrinters
    $result.PrintServerPrinters = $printServerPrinters
    $result.HasDirectIPPrinters = $directIPPrinters.Count -gt 0

    Write-Verbose "Get-PrinterConfig: Direct IP printers = $($directIPPrinters.Count), Print server printers = $($printServerPrinters.Count)"

    return $result
}
