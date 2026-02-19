function Get-NetworkConfig {
    <#
    .SYNOPSIS
        Collects network configuration and performs device discovery.
    .DESCRIPTION
        Gathers network adapter details, DNS configuration, DHCP scope information,
        performs ARP table analysis and ping sweep for device discovery, attempts
        gateway/firewall fingerprinting, and checks DNS compliance against DTC standards.
    .PARAMETER Standards
        The DTC standards object loaded from DTC-Standards.json.
    .EXAMPLE
        $networkData = Get-NetworkConfig -Standards $standards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Standards
    )

    Write-Verbose "Get-NetworkConfig: Starting network configuration collection"

    $result = @{}

    # --- Network Adapters ---
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop
        $ipAddresses = Get-NetIPAddress -ErrorAction SilentlyContinue
        $dnsServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue

        $result.Adapters = @()
        foreach ($adapter in $adapters) {
            $adapterIPs = @($ipAddresses | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex -and $_.AddressFamily -eq 'IPv4' } | ForEach-Object { $_.IPAddress })
            $adapterDNS = @($dnsServers | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex -and $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)

            $result.Adapters += @{
                Name        = $adapter.Name
                Status      = $adapter.Status
                LinkSpeed   = $adapter.LinkSpeed
                MacAddress  = $adapter.MacAddress
                IPAddresses = $adapterIPs
                DNSServers  = $adapterDNS
            }
        }
        Write-Verbose "Get-NetworkConfig: Found $($result.Adapters.Count) adapter(s)"
    }
    catch {
        Write-Verbose "Get-NetworkConfig: Failed to get adapters — $($_.Exception.Message)"
        $result.Adapters = @()
    }

    # --- Default Gateway ---
    try {
        $defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Select-Object -First 1
        $result.DefaultGateway = $defaultRoute.NextHop
        Write-Verbose "Get-NetworkConfig: Default gateway = $($result.DefaultGateway)"
    }
    catch {
        Write-Verbose "Get-NetworkConfig: Failed to get default gateway — $($_.Exception.Message)"
        $result.DefaultGateway = "Unknown"
    }

    # --- DHCP Scopes ---
    try {
        $dhcpInstalled = $false

        # Check if DHCP server service is running
        $dhcpService = Get-Service -Name 'DHCPServer' -ErrorAction SilentlyContinue
        if ($dhcpService -and $dhcpService.Status -eq 'Running') {
            $dhcpInstalled = $true
        }

        # Also try Windows Feature check
        if (-not $dhcpInstalled) {
            try {
                $dhcpFeature = Get-WindowsFeature -Name 'DHCP' -ErrorAction SilentlyContinue
                if ($dhcpFeature -and $dhcpFeature.Installed) {
                    $dhcpInstalled = $true
                }
            }
            catch {
                Write-Verbose "Get-NetworkConfig: Get-WindowsFeature not available"
            }
        }

        if ($dhcpInstalled) {
            $result.DHCPStatus = "Managed by this server"
            try {
                $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
                $result.DHCPScopes = @()
                foreach ($scope in $scopes) {
                    $result.DHCPScopes += @{
                        ScopeId    = $scope.ScopeId.ToString()
                        Name       = $scope.Name
                        StartRange = $scope.StartRange.ToString()
                        EndRange   = $scope.EndRange.ToString()
                        SubnetMask = $scope.SubnetMask.ToString()
                        State      = $scope.State
                    }
                }
                Write-Verbose "Get-NetworkConfig: Found $($result.DHCPScopes.Count) DHCP scope(s)"
            }
            catch {
                Write-Verbose "Get-NetworkConfig: DHCP installed but failed to query scopes — $($_.Exception.Message)"
                $result.DHCPScopes = @()
            }
        }
        else {
            $result.DHCPStatus = "Not managed by this server (likely handled by network gateway)"
            $result.DHCPScopes = @()
            Write-Verbose "Get-NetworkConfig: DHCP not managed by this server"
        }
    }
    catch {
        Write-Verbose "Get-NetworkConfig: DHCP detection failed — $($_.Exception.Message)"
        $result.DHCPStatus = "Unable to determine"
        $result.DHCPScopes = @()
    }

    # --- Device Discovery ---
    try {
        $discoveryStart = Get-Date

        # Parse ARP table
        $arpOutput = & arp -a 2>$null
        $arpEntries = @()
        foreach ($line in $arpOutput) {
            if ($line -match '^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f-]{17})\s+(\w+)') {
                $arpEntries += @{
                    IP   = $Matches[1]
                    MAC  = $Matches[2]
                    Type = $Matches[3]
                }
            }
        }
        $arpDeviceCount = ($arpEntries | Where-Object { $_.Type -eq 'dynamic' }).Count
        Write-Verbose "Get-NetworkConfig: ARP table shows $arpDeviceCount dynamic entries"

        # Determine primary subnet for ping sweep
        $primaryIP = $null
        $primaryPrefix = $null
        foreach ($adp in $result.Adapters) {
            if ($adp.Status -eq 'Up' -and $adp.IPAddresses.Count -gt 0) {
                $primaryIP = $adp.IPAddresses[0]
                break
            }
        }

        $sweepResults = @()
        $sweepDeviceCount = 0
        if ($primaryIP) {
            # Get subnet mask to determine sweep range
            $ipConfig = Get-NetIPAddress -IPAddress $primaryIP -ErrorAction SilentlyContinue
            $prefixLength = if ($ipConfig) { $ipConfig.PrefixLength } else { 24 }

            # For /24 or larger, sweep the /24
            $ipParts = $primaryIP.Split('.')
            $subnetBase = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
            $ipRange = 1..254 | ForEach-Object { "$subnetBase.$_" }

            Write-Verbose "Get-NetworkConfig: Ping sweeping $subnetBase.0/24 ($($ipRange.Count) addresses)"

            # Use runspace pool for parallel ping sweep
            $runspacePool = [System.Management.Automation.Runspaces.RunspacePool]::CreateRunspacePool(1, 50)
            $runspacePool.Open()

            $scriptBlock = {
                param($ip)
                $ping = New-Object System.Net.NetworkInformation.Ping
                try {
                    $reply = $ping.Send($ip, 1000)
                    if ($reply.Status -eq 'Success') {
                        return $ip
                    }
                }
                catch { }
                finally {
                    $ping.Dispose()
                }
                return $null
            }

            $jobs = @()
            foreach ($ip in $ipRange) {
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $runspacePool
                $null = $ps.AddScript($scriptBlock).AddArgument($ip)
                $jobs += @{
                    PowerShell = $ps
                    Handle     = $ps.BeginInvoke()
                }
            }

            foreach ($job in $jobs) {
                $jobResult = $job.PowerShell.EndInvoke($job.Handle)
                if ($jobResult -and $jobResult[0]) {
                    $sweepResults += $jobResult[0]
                }
                $job.PowerShell.Dispose()
            }

            $runspacePool.Close()
            $runspacePool.Dispose()

            $sweepDeviceCount = $sweepResults.Count
            Write-Verbose "Get-NetworkConfig: Ping sweep found $sweepDeviceCount active device(s)"
        }

        $discoveryDuration = ((Get-Date) - $discoveryStart).TotalSeconds

        $result.DeviceDiscovery = @{
            ActiveDeviceCount = [math]::Max($arpDeviceCount, $sweepDeviceCount)
            ARPCount          = $arpDeviceCount
            PingSweepCount    = $sweepDeviceCount
            IPRange           = if ($primaryIP) { "$subnetBase.1 - $subnetBase.254" } else { "Unknown" }
            SweepDuration     = [math]::Round($discoveryDuration, 1)
        }
    }
    catch {
        Write-Verbose "Get-NetworkConfig: Device discovery failed — $($_.Exception.Message)"
        $result.DeviceDiscovery = @{
            ActiveDeviceCount = 0
            ARPCount          = 0
            PingSweepCount    = 0
            IPRange           = "Unknown"
            SweepDuration     = 0
        }
    }

    # --- Gateway/Firewall Fingerprinting ---
    try {
        $gwIP = $result.DefaultGateway
        $result.GatewayFingerprint = @{
            IP                     = $gwIP
            DetectedVendor         = "Unknown"
            Method                 = "None"
            ManualConfirmRequired  = $true
        }

        if ($gwIP -and $gwIP -ne "Unknown") {
            # Ignore certificate errors
            try {
                Add-Type @"
                    using System.Net;
                    using System.Net.Security;
                    using System.Security.Cryptography.X509Certificates;
                    public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult(
                            ServicePoint srvPoint, X509Certificate certificate,
                            WebRequest request, int certificateProblem) {
                            return true;
                        }
                    }
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }
            catch {
                Write-Verbose "Get-NetworkConfig: TrustAllCertsPolicy already loaded"
            }
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls

            $detected = $false
            $vendorPatterns = @(
                @{ Vendor = "UniFi"; Patterns = @("UniFi", "ubnt", "Ubiquiti") }
                @{ Vendor = "SonicWall"; Patterns = @("SonicWall", "SonicOS") }
                @{ Vendor = "Meraki"; Patterns = @("Meraki") }
                @{ Vendor = "Fortinet"; Patterns = @("Fortinet", "FortiGate", "FortiOS") }
                @{ Vendor = "pfSense"; Patterns = @("pfSense") }
                @{ Vendor = "Netgear"; Patterns = @("Netgear", "NETGEAR") }
            )

            foreach ($proto in @("https", "http")) {
                if ($detected) { break }
                $url = "${proto}://${gwIP}"
                Write-Verbose "Get-NetworkConfig: Attempting $url for gateway fingerprint"
                try {
                    $request = [System.Net.WebRequest]::Create($url)
                    $request.Timeout = 5000
                    $request.AllowAutoRedirect = $true
                    $response = $request.GetResponse()
                    $stream = $response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $body = $reader.ReadToEnd()
                    $reader.Close()
                    $response.Close()

                    foreach ($vp in $vendorPatterns) {
                        foreach ($pattern in $vp.Patterns) {
                            if ($body -match $pattern) {
                                $result.GatewayFingerprint.DetectedVendor = $vp.Vendor
                                $result.GatewayFingerprint.Method = "HTTP response body match ($proto)"
                                $detected = $true
                                break
                            }
                        }
                        if ($detected) { break }
                    }
                }
                catch {
                    Write-Verbose "Get-NetworkConfig: $proto request to gateway failed — $($_.Exception.Message)"

                    # Try to read certificate subject for HTTPS failures
                    if ($proto -eq "https") {
                        try {
                            $tcpClient = New-Object System.Net.Sockets.TcpClient
                            $tcpClient.Connect($gwIP, 443)
                            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
                            $sslStream.AuthenticateAsClient($gwIP)
                            $cert = $sslStream.RemoteCertificate
                            if ($cert) {
                                $certSubject = $cert.Subject
                                $certIssuer = $cert.Issuer
                                Write-Verbose "Get-NetworkConfig: Certificate subject = $certSubject"
                                foreach ($vp in $vendorPatterns) {
                                    foreach ($pattern in $vp.Patterns) {
                                        if ($certSubject -match $pattern -or $certIssuer -match $pattern) {
                                            $result.GatewayFingerprint.DetectedVendor = $vp.Vendor
                                            $result.GatewayFingerprint.Method = "SSL certificate match"
                                            $detected = $true
                                            break
                                        }
                                    }
                                    if ($detected) { break }
                                }
                            }
                            $sslStream.Close()
                            $tcpClient.Close()
                        }
                        catch {
                            Write-Verbose "Get-NetworkConfig: Certificate inspection failed — $($_.Exception.Message)"
                        }
                    }
                }
            }

            if (-not $detected) {
                $result.GatewayFingerprint.DetectedVendor = "Unknown — tech must identify manually"
                $result.GatewayFingerprint.Method = "No vendor signature detected"
            }
        }
        Write-Verbose "Get-NetworkConfig: Gateway fingerprint = $($result.GatewayFingerprint.DetectedVendor)"
    }
    catch {
        Write-Verbose "Get-NetworkConfig: Gateway fingerprinting failed — $($_.Exception.Message)"
        $result.GatewayFingerprint = @{
            IP                    = $result.DefaultGateway
            DetectedVendor        = "Error during detection"
            Method                = "Failed"
            ManualConfirmRequired = $true
        }
    }

    # --- DNS Compliance Check ---
    try {
        $dnsCompliant = $true
        $dnsDetails = @()
        $gwIP = $result.DefaultGateway

        foreach ($adapter in $result.Adapters) {
            if ($adapter.Status -ne 'Up') { continue }
            if (-not $adapter.DNSServers -or $adapter.DNSServers.Count -eq 0) { continue }

            foreach ($dns in $adapter.DNSServers) {
                if ($dns -ne $gwIP -and $dns -ne '127.0.0.1' -and $dns -ne '::1') {
                    $dnsCompliant = $false
                    $dnsDetails += "Adapter '$($adapter.Name)': DNS server $dns is not the gateway ($gwIP)"
                }
            }
        }

        if ($dnsCompliant) {
            $dnsDetails += "All active adapters use gateway IP ($gwIP) as DNS — compliant with DTC standard"
        }

        $result.DNSCompliance = @{
            Compliant = $dnsCompliant
            Details   = $dnsDetails
        }
        Write-Verbose "Get-NetworkConfig: DNS compliance = $dnsCompliant"
    }
    catch {
        Write-Verbose "Get-NetworkConfig: DNS compliance check failed — $($_.Exception.Message)"
        $result.DNSCompliance = @{
            Compliant = $false
            Details   = @("Unable to determine DNS compliance: $($_.Exception.Message)")
        }
    }

    return $result
}
