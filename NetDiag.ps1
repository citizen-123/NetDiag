#Requires -Version 5.1
<#
.SYNOPSIS
    Network Stack Diagnostic Tool v3.0 — pinpoints where in the network stack a problem occurs.
.DESCRIPTION
    Comprehensive network diagnostic that walks each layer of the stack and reports exactly
    where failures or degradation occur. Supports IPv4/IPv6, DNSSEC, MTU path discovery,
    baseline comparison, repeat/intermittent detection, remote execution, bandwidth testing,
    and exports to JSON/interactive HTML.

    Layers tested:
      0. Local overrides  (HOSTS file, proxy/PAC, firewall rules, VPN, DoH)
      1. Control target    (verify internet connectivity vs target-specific failure)
      2. Local network     (adapters, IP config, gateway, IPv6 readiness)
      3. DNS resolution    (parallel multi-server, AAAA, DNSSEC, rDNS/FCrDNS, consistency)
      4. Route trace       (ICMP TTL + TCP fallback, latency spike detection)
      5. MTU path          (binary search with DF bit, PMTU blackhole detection)
      6. TCP connectivity  (parallel port scan, IPv4 + IPv6)
      7. TLS/SSL           (cert chain, expiry, SAN match, protocol version)
      8. HTTP/HTTPS        (multi-path, status, headers, proxy detection)
      9. Bandwidth         (optional download/upload speed estimation)
.PARAMETER Target
    Hostname or URL to diagnose
.PARAMETER Ports
    TCP ports to test. Default: 80, 443
.PARAMETER Paths
    URL paths to test during HTTP phase. Default: /
.PARAMETER DnsServers
    Additional DNS servers to test against
.PARAMETER ControlTarget
    Known-good host to verify internet connectivity. Default: 1.1.1.1
.PARAMETER MaxHops
    Max hops for traceroute. Default: 30
.PARAMETER Timeout
    Timeout in ms for individual tests. Default: 3000
.PARAMETER SkipHttp
    Skip HTTP/HTTPS tests
.PARAMETER SkipTrace
    Skip traceroute
.PARAMETER SkipMtu
    Skip MTU discovery
.PARAMETER SkipIPv6
    Skip IPv6 path testing
.PARAMETER TestBandwidth
    Run bandwidth estimation (opt-in)
.PARAMETER Detailed
    Verbose per-hop and per-test output
.PARAMETER RepeatCount
    Number of diagnostic runs. Default: 1
.PARAMETER RepeatInterval
    Seconds between runs. Default: 10
.PARAMETER OutputJson
    Path for JSON report
.PARAMETER OutputHtml
    Path for interactive HTML report
.PARAMETER SaveBaseline
    Save this run as baseline JSON for future comparison
.PARAMETER CompareBaseline
    Path to baseline JSON to compare against
.PARAMETER ComputerName
    Remote computer to run diagnostic on (requires PSRemoting)
.PARAMETER Credential
    Credential for remote execution
.EXAMPLE
    .\NetDiag.ps1 -Target example.com
.EXAMPLE
    .\NetDiag.ps1 -Target example.com -Detailed -OutputHtml report.html -TestBandwidth
.EXAMPLE
    .\NetDiag.ps1 -Target example.com -RepeatCount 5 -RepeatInterval 30 -OutputJson results.json
.EXAMPLE
    .\NetDiag.ps1 -Target example.com -SaveBaseline baseline.json
    .\NetDiag.ps1 -Target example.com -CompareBaseline baseline.json
.EXAMPLE
    .\NetDiag.ps1 -Target example.com -ComputerName SERVER01 -Credential (Get-Credential)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Target,

    [int[]]$Ports = @(80, 443),

    [string[]]$Paths = @('/'),

    [string[]]$DnsServers,

    [string]$ControlTarget = '1.1.1.1',

    [int]$MaxHops = 30,

    [int]$Timeout = 3000,

    [switch]$SkipHttp,
    [switch]$SkipTrace,
    [switch]$SkipMtu,
    [switch]$SkipIPv6,
    [switch]$TestBandwidth,
    [switch]$Detailed,

    [ValidateRange(1, 100)]
    [int]$RepeatCount = 1,

    [ValidateRange(1, 3600)]
    [int]$RepeatInterval = 10,

    [string]$OutputJson,
    [string]$OutputHtml,
    [string]$SaveBaseline,
    [string]$CompareBaseline,

    [string]$ComputerName,
    [PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 1: COMPATIBILITY LAYER                              ║
# ╚═══════════════════════════════════════════════════════════════╝

$script:PSMajor = $PSVersionTable.PSVersion.Major
$script:IsPS7 = $script:PSMajor -ge 7
$script:IsWin = $IsWindows -or ($PSVersionTable.PSEdition -eq 'Desktop')

function Get-PingLatency {
    <# Returns latency from a ping reply, handling PS 5.1 vs 7 #>
    param($PingResult)
    if ($null -eq $PingResult) { return $null }
    if ($PingResult.PSObject.Properties.Name -contains 'Latency') {
        return $PingResult.Latency
    } elseif ($PingResult.PSObject.Properties.Name -contains 'ResponseTime') {
        return $PingResult.ResponseTime
    }
    return $null
}

function Invoke-PingTest {
    <# Cross-version ping wrapper returning [PSCustomObject]@{Success;LatencyMs;Count;Sent} #>
    param([string]$Target, [int]$Count = 3)
    try {
        $results = @(Test-Connection -ComputerName $Target -Count $Count -ErrorAction SilentlyContinue)
        if ($results.Count -gt 0) {
            $latencies = @($results | ForEach-Object { Get-PingLatency $_ } | Where-Object { $null -ne $_ })
            $avg = if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Average).Average, 1) } else { 0 }
            return [PSCustomObject]@{ Success = $true; LatencyMs = $avg; Count = $results.Count; Sent = $Count }
        }
    } catch {}
    return [PSCustomObject]@{ Success = $false; LatencyMs = 0; Count = 0; Sent = $Count }
}

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 2: HELPERS                                          ║
# ╚═══════════════════════════════════════════════════════════════╝

#region --- Display Helpers ---

function Write-Phase {
    param([string]$Name, [string]$Icon = "►")
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "  $Icon $Name" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
}

function Write-Result {
    param(
        [string]$Label, [string]$Value,
        [ValidateSet('OK','WARN','FAIL','INFO')][string]$Status = 'INFO'
    )
    $colors = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'White' }
    $icons  = @{ OK = '[OK]'; WARN = '[!!]'; FAIL = '[XX]'; INFO = '[--]' }
    Write-Host "    $($icons[$Status]) " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host "${Label}: " -NoNewline -ForegroundColor Gray
    Write-Host "$Value" -ForegroundColor $colors[$Status]
}

function Write-Diagnosis {
    param([string]$Message, [string]$Severity = 'FAIL')
    $color = switch ($Severity) { 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Cyan' } }
    Write-Host ""
    Write-Host "    >> DIAGNOSIS: $Message" -ForegroundColor $color
}

#endregion

#region --- Data Helpers ---

function Get-CleanHostname {
    param([string]$Raw)
    $r = $Raw -replace '^https?://',''
    $r = ($r -split '/')[0]
    $r = ($r -split ':')[0]
    return $r.Trim()
}

function New-FindingsCollector {
    return [System.Collections.Generic.List[PSCustomObject]]::new()
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Collector,
        [string]$Layer,
        [ValidateSet('OK','WARN','FAIL')][string]$Severity,
        [string]$Detail
    )
    $Collector.Add([PSCustomObject]@{
        Layer = $Layer; Severity = $Severity; Detail = $Detail; Time = (Get-Date).ToString('o')
    })
}

#endregion

#region --- Disposable Tracking & Cleanup ---

$script:Disposables = [System.Collections.Generic.List[IDisposable]]::new()

function Register-Disposable {
    param([System.IDisposable]$Obj)
    if ($Obj) { $script:Disposables.Add($Obj) }
    return $Obj
}

function Invoke-Cleanup {
    foreach ($d in $script:Disposables) {
        try { $d.Dispose() } catch {}
    }
    $script:Disposables.Clear()
}

#endregion

#region --- Progress Wrapper ---

$script:TotalPhases = 10
$script:CurrentPhaseNum = 0
$script:PhaseTimings = [System.Collections.Generic.List[double]]::new()

function Start-DiagProgress {
    param([string]$PhaseName, [int]$PhaseNumber)
    $script:CurrentPhaseNum = $PhaseNumber
    $script:CurrentPhaseSW = [System.Diagnostics.Stopwatch]::StartNew()
    $pct = [math]::Min(100, [math]::Round(($PhaseNumber / $script:TotalPhases) * 100))
    try {
        Write-Progress -Activity "NetDiag v3.0" -Status "Phase $PhaseNumber/$($script:TotalPhases): $PhaseName" -PercentComplete $pct
    } catch {}
}

function Update-DiagSubProgress {
    param([string]$Status, [int]$Step, [int]$TotalSteps)
    $pct = [math]::Min(100, [math]::Round(($Step / [math]::Max(1, $TotalSteps)) * 100))
    try {
        Write-Progress -Activity "NetDiag v3.0" -Status $Status -PercentComplete $pct -Id 1
    } catch {}
}

function Complete-DiagProgress {
    if ($script:CurrentPhaseSW) {
        $script:CurrentPhaseSW.Stop()
        $script:PhaseTimings.Add($script:CurrentPhaseSW.Elapsed.TotalSeconds)
    }
    try { Write-Progress -Activity "NetDiag v3.0" -Id 1 -Completed } catch {}
}

function Complete-AllProgress {
    try {
        Write-Progress -Activity "NetDiag v3.0" -Completed
        Write-Progress -Activity "NetDiag v3.0" -Id 1 -Completed
    } catch {}
}

#endregion

#region --- Parallel Execution (Safe) ---

function Invoke-Parallel {
    <#
    .SYNOPSIS
        Runs scriptblocks in parallel via runspaces with proper argument passing.
        No string interpolation — immune to injection from adversarial hostnames.
    #>
    param(
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentSets,
        [int]$ThrottleLimit = 10,
        [int]$TimeoutMs = 30000
    )

    $pool = Register-Disposable ([RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit))
    $pool.Open()

    $jobs = foreach ($args in $ArgumentSets) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ScriptBlock)
        if ($args -is [array]) {
            foreach ($a in $args) { [void]$ps.AddArgument($a) }
        } else {
            [void]$ps.AddArgument($args)
        }
        [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
    }

    $results = foreach ($job in $jobs) {
        try {
            if ($job.Handle.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                $job.PS.EndInvoke($job.Handle)
            } else {
                [PSCustomObject]@{ Error = "Timed out after ${TimeoutMs}ms" }
            }
        } catch {
            [PSCustomObject]@{ Error = $_.Exception.Message }
        } finally {
            $job.PS.Dispose()
        }
    }

    $pool.Close()
    $pool.Dispose()
    $script:Disposables.Remove($pool) | Out-Null
    return $results
}

#endregion

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 3: PHASE FUNCTIONS                                  ║
# ╚═══════════════════════════════════════════════════════════════╝

#region === Phase 0: Local Overrides ===

function Test-LocalOverrides {
    param(
        [string]$Hostname,
        [int[]]$Ports,
        [bool]$Detailed,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 0: Local Overrides Check"
    Start-DiagProgress "Local Overrides" 1
    $data = [ordered]@{}

    # ── HOSTS file ──
    $hostsOverride = $null
    if ($script:IsWin) {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    } else {
        $hostsPath = '/etc/hosts'
    }
    try {
        if (Test-Path $hostsPath) {
            $hostsLines = Get-Content $hostsPath -ErrorAction SilentlyContinue |
                Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
            foreach ($line in $hostsLines) {
                $parts = $line.Trim() -split '\s+'
                if ($parts.Count -ge 2 -and ($parts[1..($parts.Count-1)] -contains $Hostname)) {
                    $hostsOverride = $parts[0]
                    break
                }
            }
            if ($hostsOverride) {
                Write-Result "HOSTS file" "OVERRIDE: $Hostname => $hostsOverride" "WARN"
                Add-Finding $Findings "HOSTS" "WARN" "HOSTS file overrides $Hostname to $hostsOverride — DNS bypassed"
            } else {
                Write-Result "HOSTS file" "No override for $Hostname" "OK"
            }
        }
    } catch {
        Write-Result "HOSTS file" "Could not read: $($_.Exception.Message)" "WARN"
    }
    $data['HostsOverride'] = $hostsOverride

    # ── Proxy / PAC ──
    $proxyInfo = [ordered]@{ Enabled = $false }
    if ($script:IsWin) {
        try {
            $proxyReg = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
            $autoConfigUrl = $proxyReg.AutoConfigURL
            $proxyEnabled = [bool]$proxyReg.ProxyEnable
            $proxyServer = $proxyReg.ProxyServer
            $proxyBypass = $proxyReg.ProxyOverride

            if ($autoConfigUrl) {
                Write-Result "PAC / Auto-config" $autoConfigUrl "WARN"
                Add-Finding $Findings "PROXY" "WARN" "PAC at $autoConfigUrl — requests may route through proxy"
                $proxyInfo['PAC'] = $autoConfigUrl
                try {
                    $pacContent = (Invoke-WebRequest -Uri $autoConfigUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop).Content
                    $pacProxies = @([regex]::Matches($pacContent, 'PROXY\s+([^";\s]+)') | ForEach-Object { $_.Groups[1].Value })
                    if ($pacProxies.Count -gt 0) {
                        Write-Result "PAC proxies" ($pacProxies -join ', ') "INFO"
                        $proxyInfo['PACProxies'] = $pacProxies
                    }
                    $proxyInfo['PACAllowsDirect'] = [bool]($pacContent -match 'DIRECT')
                    if ($proxyInfo['PACAllowsDirect']) { Write-Result "PAC allows DIRECT" "Yes" "INFO" }
                } catch {
                    Write-Result "PAC fetch" "Failed: $($_.Exception.Message)" "WARN"
                    Add-Finding $Findings "PROXY" "WARN" "Could not fetch PAC from $autoConfigUrl"
                }
            } else {
                Write-Result "PAC" "None configured" "OK"
            }

            if ($proxyEnabled -and $proxyServer) {
                Write-Result "System proxy" "$proxyServer (ENABLED)" "WARN"
                Add-Finding $Findings "PROXY" "WARN" "System proxy: $proxyServer"
                $proxyInfo['Enabled'] = $true
                $proxyInfo['Server'] = $proxyServer

                # Bypass check
                if ($proxyBypass) {
                    $bypassed = $false
                    foreach ($p in ($proxyBypass -split ';')) {
                        $regex = '^' + ($p.Trim() -replace '\*', '.*') + '$'
                        if ($Hostname -match $regex) { $bypassed = $true; break }
                    }
                    $bypassStatus = if ($bypassed) { "INFO" } else { "WARN" }
                    $bypassMsg = if ($bypassed) { "$Hostname IS bypassed — goes DIRECT" } else { "$Hostname NOT bypassed — goes through proxy" }
                    Write-Result "Proxy bypass" $bypassMsg $bypassStatus
                    $proxyInfo['TargetBypassed'] = $bypassed
                }

                # Proxy reachability
                $proxySplit = $proxyServer -split ':'
                $proxyHost = $proxySplit[0]
                $proxyPort = if ($proxySplit.Count -gt 1) { [int]$proxySplit[1] } else { 8080 }
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $ar = $tcp.BeginConnect($proxyHost, $proxyPort, $null, $null)
                    $proxyReachable = $ar.AsyncWaitHandle.WaitOne(2000, $false) -and $tcp.Connected
                    if ($proxyReachable) { $tcp.EndConnect($ar) }
                    $tcp.Close()
                    if ($proxyReachable) {
                        Write-Result "Proxy reachable" "$proxyServer — YES" "OK"
                    } else {
                        Write-Result "Proxy reachable" "$proxyServer — NO" "FAIL"
                        Add-Finding $Findings "PROXY" "FAIL" "Proxy $proxyServer unreachable — HTTP traffic will fail"
                    }
                    $proxyInfo['ProxyReachable'] = $proxyReachable
                } catch {
                    Write-Result "Proxy test" "Failed: $($_.Exception.Message)" "WARN"
                }
            } elseif (-not $autoConfigUrl) {
                Write-Result "System proxy" "None (direct)" "OK"
            }

            # WinHTTP
            try {
                $winhttp = netsh winhttp show proxy 2>$null
                $whl = ($winhttp | Select-String 'Proxy Server' | Select-Object -First 1)
                if ($whl) {
                    $whStr = $whl.ToString().Trim()
                    if ($whStr -match 'Direct access') {
                        Write-Result "WinHTTP" "Direct access" "OK"
                    } else {
                        Write-Result "WinHTTP" $whStr "WARN"
                        $proxyInfo['WinHTTP'] = $whStr
                    }
                }
            } catch {}
        } catch {
            Write-Result "Proxy detection" "Error: $($_.Exception.Message)" "WARN"
        }
    }
    $data['Proxy'] = $proxyInfo

    # ── Windows Firewall ──
    $firewallInfo = @()
    if ($script:IsWin) {
        try {
            $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            $active = @($fwProfiles | Where-Object { $_.Enabled })
            if ($active.Count -gt 0) { Write-Result "Firewall active" ($active.Name -join ', ') "INFO" }

            $outBlocks = @(Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block -ErrorAction SilentlyContinue)
            $relevant = @()
            foreach ($rule in $outBlocks) {
                $pf = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $af = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                $portMatch = ($pf.RemotePort -eq 'Any') -or ($Ports | Where-Object { $_ -in @($pf.RemotePort) })
                $addrMatch = ($af.RemoteAddress -eq 'Any') -or ($af.RemoteAddress -contains '*')
                if ($portMatch -and $addrMatch) {
                    $relevant += [ordered]@{ Name = $rule.DisplayName; Ports = "$($pf.RemotePort)"; Protocol = $pf.Protocol }
                    Write-Result "Outbound BLOCK" "'$($rule.DisplayName)' blocks port(s) $($pf.RemotePort)" "WARN"
                    Add-Finding $Findings "FIREWALL" "WARN" "Firewall rule '$($rule.DisplayName)' may block port(s) $($pf.RemotePort)"
                }
            }
            if ($relevant.Count -eq 0) { Write-Result "Outbound blocks" "None matching target ports" "OK" }
            $firewallInfo = $relevant
        } catch {
            Write-Result "Firewall" "Could not query (elevation may be needed)" "WARN"
        }
    }
    $data['Firewall'] = $firewallInfo

    # ── VPN ──
    if ($script:IsWin) {
        try {
            $vpns = @(Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionStatus -eq 'Connected' })
            if ($vpns.Count -gt 0) {
                foreach ($v in $vpns) {
                    $st = if ($v.SplitTunneling) { "Split-tunnel" } else { "Full-tunnel" }
                    Write-Result "Active VPN" "$($v.Name) ($st)" "WARN"
                    Add-Finding $Findings "VPN" "WARN" "VPN '$($v.Name)' active ($st) — may alter routing"
                }
                $data['VPN'] = @($vpns | ForEach-Object { @{ Name=$_.Name; Split=$_.SplitTunneling } })
            } else {
                Write-Result "VPN" "None detected" "OK"
                $data['VPN'] = $null
            }
        } catch {
            if ($Detailed) { Write-Result "VPN" "Could not query" "INFO" }
        }
    }

    # ── DNS-over-HTTPS (Win11+) ──
    if ($script:IsWin) {
        try {
            $dohServers = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
            if ($dohServers.Count -gt 0) {
                $dohActive = @($dohServers | Where-Object { $_.AutoUpgrade })
                if ($dohActive.Count -gt 0) {
                    Write-Result "DNS-over-HTTPS" "Active for: $(($dohActive.ServerAddress) -join ', ')" "WARN"
                    Add-Finding $Findings "DOH" "WARN" "DNS-over-HTTPS active — traditional DNS debugging may not reflect actual resolution"
                    $data['DoH'] = @($dohActive.ServerAddress)
                } else {
                    Write-Result "DNS-over-HTTPS" "Configured but not auto-upgrading" "INFO"
                }
            } else {
                Write-Result "DNS-over-HTTPS" "Not configured" "OK"
            }
        } catch {
            # Get-DnsClientDohServerAddress not available on older Windows
            if ($Detailed) { Write-Result "DoH" "Not available on this OS version" "INFO" }
        }
    }

    Complete-DiagProgress
    return $data
}

#endregion

#region === Phase 1: Control Target ===

function Test-ControlTarget {
    param(
        [string]$ControlTarget,
        [int]$Timeout,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 1: Control Target ($ControlTarget)"
    Start-DiagProgress "Control Target" 2
    $data = [ordered]@{ Target = $ControlTarget }

    # ICMP
    $ping = Invoke-PingTest -Target $ControlTarget -Count 2
    if ($ping.Success) {
        Write-Result "ICMP" "OK ($($ping.LatencyMs)ms)" "OK"
        $data['ICMP'] = $true
    } else {
        Write-Result "ICMP" "No response (may be blocked)" "WARN"
        $data['ICMP'] = $false
    }

    # TCP 443
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $ar = $tcp.BeginConnect($ControlTarget, 443, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($Timeout, $false) -and $tcp.Connected
        $sw.Stop()
        if ($ok) { $tcp.EndConnect($ar) }
        $tcp.Close()
        if ($ok) {
            Write-Result "TCP 443" "OK ($($sw.ElapsedMilliseconds)ms)" "OK"
            $data['TCP443'] = $true
        } else {
            Write-Result "TCP 443" "FAILED" "FAIL"
            $data['TCP443'] = $false
        }
    } catch {
        Write-Result "TCP 443" "Error: $($_.Exception.Message)" "FAIL"
        $data['TCP443'] = $false
    }

    if (-not $data['ICMP'] -and -not $data['TCP443']) {
        Write-Diagnosis "Control target $ControlTarget unreachable — your internet connection itself may be down. Problems with $($script:Hostname) could be a side effect." "FAIL"
        Add-Finding $Findings "CONTROL" "FAIL" "Control target $ControlTarget unreachable — general internet connectivity failure"
        $data['InternetDown'] = $true
    } elseif ($data['TCP443']) {
        Write-Result "Internet connectivity" "Confirmed via $ControlTarget" "OK"
        $data['InternetDown'] = $false
    }

    Complete-DiagProgress
    return $data
}

#endregion

#region === Phase 2: Local Network ===

function Test-LocalNetwork {
    param(
        [bool]$SkipIPv6,
        [bool]$Detailed,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 2: Local Network Configuration"
    Start-DiagProgress "Local Network" 3
    $data = [ordered]@{}
    $systemDns = @()

    if (-not $script:IsWin) {
        Write-Result "Platform" "Non-Windows — using limited network checks" "INFO"
        # Basic DNS from resolv.conf
        try {
            $resolvConf = Get-Content '/etc/resolv.conf' -ErrorAction SilentlyContinue |
                Where-Object { $_ -match '^nameserver' } |
                ForEach-Object { ($_ -split '\s+')[1] }
            $systemDns = @($resolvConf)
            if ($systemDns.Count -gt 0) {
                Write-Result "System DNS" ($systemDns -join ', ') "INFO"
            }
        } catch {}
        $data['SystemDNS'] = $systemDns
        Complete-DiagProgress
        return @{ Data = $data; SystemDNS = $systemDns }
    }

    try {
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
        if ($adapters.Count -eq 0) {
            Write-Result "Adapters" "NONE ACTIVE" "FAIL"
            Add-Finding $Findings "LOCAL" "FAIL" "No active network adapters"
        } else {
            foreach ($a in $adapters) {
                Write-Result "Adapter" "$($a.Name) ($($a.LinkSpeed))" "OK"
            }
        }

        # IPv4
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -in $adapters.Name -and $_.IPAddress -ne '127.0.0.1' })
        if ($ips.Count -eq 0) {
            Write-Result "IPv4" "No address assigned" "FAIL"
            Add-Finding $Findings "LOCAL" "FAIL" "No IPv4 address on active adapters"
        } else {
            foreach ($ip in $ips) { Write-Result "IPv4" "$($ip.IPAddress)/$($ip.PrefixLength) on $($ip.InterfaceAlias)" "OK" }
        }

        # IPv6 readiness
        if (-not $SkipIPv6) {
            $ip6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceAlias -in $adapters.Name -and $_.IPAddress -notmatch '^fe80' -and $_.IPAddress -ne '::1' })
            if ($ip6.Count -gt 0) {
                foreach ($i6 in $ip6) { Write-Result "IPv6 (global)" "$($i6.IPAddress) on $($i6.InterfaceAlias)" "OK" }
                $data['IPv6Ready'] = $true
            } else {
                Write-Result "IPv6 (global)" "No global IPv6 address" "INFO"
                $data['IPv6Ready'] = $false
            }
        }

        # Gateways
        $gateways = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
        if ($gateways.Count -eq 0) {
            Write-Result "Default gateway" "NONE" "FAIL"
            Add-Finding $Findings "LOCAL" "FAIL" "No default gateway"
        } else {
            foreach ($gw in $gateways) {
                Write-Result "Gateway" "$($gw.NextHop) via $($gw.InterfaceAlias)" "OK"
                $gwPing = Invoke-PingTest -Target $gw.NextHop -Count 1
                if ($gwPing.Success) {
                    Write-Result "Gateway reachable" "$($gwPing.LatencyMs)ms" "OK"
                } else {
                    Write-Result "Gateway reachable" "NO RESPONSE" "FAIL"
                    Add-Finding $Findings "LOCAL" "FAIL" "Gateway $($gw.NextHop) unreachable"
                }
            }
        }

        # IPv6 gateway
        if (-not $SkipIPv6 -and $data['IPv6Ready']) {
            $gw6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)
            if ($gw6.Count -gt 0) {
                Write-Result "IPv6 gateway" "$($gw6[0].NextHop)" "OK"
            } else {
                Write-Result "IPv6 gateway" "None — IPv6 may not route externally" "WARN"
            }
        }

        # DNS
        $systemDns = @((Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses.Count -gt 0 }).ServerAddresses | Select-Object -Unique)
        if ($systemDns.Count -gt 0) {
            Write-Result "System DNS" ($systemDns -join ', ') "INFO"
        } else {
            Write-Result "System DNS" "None configured" "WARN"
            Add-Finding $Findings "LOCAL" "WARN" "No DNS servers configured"
        }
    } catch {
        Write-Result "Local network" "Query error: $($_.Exception.Message)" "WARN"
    }

    $data['SystemDNS'] = $systemDns
    Complete-DiagProgress
    return @{ Data = $data; SystemDNS = $systemDns }
}

#endregion

#region === Phase 3: DNS Resolution ===

function Test-DnsResolution {
    param(
        [string]$Hostname,
        [string[]]$ExtraDnsServers,
        [string[]]$SystemDns,
        [int]$Timeout,
        [bool]$SkipIPv6,
        [bool]$Detailed,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 3: DNS Resolution (parallel)"
    Start-DiagProgress "DNS Resolution" 4
    $data = [ordered]@{}

    # Build server list
    $servers = [ordered]@{}
    if ($ExtraDnsServers) { foreach ($s in $ExtraDnsServers) { $servers[$s] = "User-specified" } }
    if ($SystemDns) { foreach ($s in $SystemDns) { if (-not $servers.Contains($s)) { $servers[$s] = "System DNS" } } }
    foreach ($kv in @{ '8.8.8.8' = 'Google'; '1.1.1.1' = 'Cloudflare'; '9.9.9.9' = 'Quad9' }.GetEnumerator()) {
        if (-not $servers.Contains($kv.Key)) { $servers[$kv.Key] = $kv.Value }
    }

    # Parallel DNS scriptblock — arguments passed safely, no string interpolation
    $dnsBlock = {
        param($Server, $Label, $Hostname, $TestIPv6)
        $results = [ordered]@{ Server = $Server; Label = $Label; A = @(); AAAA = @(); CNAME = @(); ATimeMs = 0; AAAATimeMs = 0; ASuccess = $false; AAAASuccess = $false; AError = $null; AAAAError = $null; DNSSEC = 'Unknown'; PTR = $null; FCrDNS = $null }

        # A record
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $r = Resolve-DnsName -Name $Hostname -Server $Server -DnsOnly -Type A -ErrorAction Stop
            $sw.Stop()
            $results.A = @($r | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress })
            $results.CNAME = @($r | Where-Object { $_.QueryType -eq 'CNAME' } | ForEach-Object { $_.NameHost })
            $results.ATimeMs = $sw.ElapsedMilliseconds
            $results.ASuccess = ($results.A.Count -gt 0)
        } catch {
            $sw.Stop()
            $results.ATimeMs = $sw.ElapsedMilliseconds
            $results.AError = $_.Exception.Message
        }

        # AAAA record
        if ($TestIPv6) {
            $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $r6 = Resolve-DnsName -Name $Hostname -Server $Server -DnsOnly -Type AAAA -ErrorAction Stop
                $sw2.Stop()
                $results.AAAA = @($r6 | Where-Object { $_.QueryType -eq 'AAAA' } | ForEach-Object { $_.IPAddress })
                $results.AAAATimeMs = $sw2.ElapsedMilliseconds
                $results.AAAASuccess = ($results.AAAA.Count -gt 0)
            } catch {
                $sw2.Stop()
                $results.AAAAError = $_.Exception.Message
            }
        }

        # DNSSEC
        try {
            $dnssecResult = Resolve-DnsName -Name $Hostname -Server $Server -DnssecOk -ErrorAction Stop
            $hasRRSIG = ($dnssecResult | Where-Object { $_.QueryType -eq 'RRSIG' }).Count -gt 0
            if ($hasRRSIG) { $results.DNSSEC = 'Validated' } else { $results.DNSSEC = 'NotSigned' }
        } catch {
            $results.DNSSEC = 'Error'
        }

        # Reverse DNS / FCrDNS (only for first A result)
        if ($results.A.Count -gt 0) {
            try {
                $ptr = Resolve-DnsName -Name $results.A[0] -Type PTR -DnsOnly -ErrorAction Stop
                $ptrName = ($ptr | Where-Object { $_.QueryType -eq 'PTR' } | Select-Object -First 1).NameHost
                $results.PTR = $ptrName
                if ($ptrName) {
                    $fwd = Resolve-DnsName -Name $ptrName -Type A -DnsOnly -ErrorAction Stop
                    $fwdIPs = @($fwd | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress })
                    $results.FCrDNS = $results.A[0] -in $fwdIPs
                }
            } catch {}
        }

        return [PSCustomObject]$results
    }

    $argSets = @($servers.Keys | ForEach-Object {
        @($_, $servers[$_], $Hostname, (-not $SkipIPv6))
    })

    $dnsResults = Invoke-Parallel -ScriptBlock $dnsBlock -ArgumentSets $argSets -TimeoutMs ($Timeout * 3)

    $resolvedIPs = @{}
    $resolvedIPv6 = @{}
    $dnsFailures = @()
    $ptrResult = $null
    $fcrDnsResult = $null
    $dnssecStatus = 'Unknown'

    foreach ($dr in $dnsResults) {
        if ($dr.ASuccess) {
            $ipStr = ($dr.A -join ', ')
            if ($dr.CNAME.Count -gt 0) { $ipStr += " (CNAME: $($dr.CNAME -join ' -> '))" }
            $status = if ($dr.ATimeMs -gt 500) { "WARN" } else { "OK" }
            Write-Result "$($dr.Label) ($($dr.Server))" "A: $ipStr [$($dr.ATimeMs)ms]" $status
            $resolvedIPs[$dr.Server] = $dr.A
            if ($dr.ATimeMs -gt 500) { Add-Finding $Findings "DNS" "WARN" "DNS $($dr.Server) slow ($($dr.ATimeMs)ms)" }
        } else {
            Write-Result "$($dr.Label) ($($dr.Server))" "A: FAILED — $($dr.AError)" "FAIL"
            $dnsFailures += $dr.Server
            Add-Finding $Findings "DNS" "FAIL" "DNS $($dr.Server) ($($dr.Label)) A query failed — $($dr.AError)"
        }

        # IPv6
        if (-not $SkipIPv6 -and $dr.AAAASuccess) {
            Write-Result "$($dr.Label) ($($dr.Server))" "AAAA: $($dr.AAAA -join ', ') [$($dr.AAAATimeMs)ms]" "INFO"
            $resolvedIPv6[$dr.Server] = $dr.AAAA
        }

        # Capture first PTR/FCrDNS/DNSSEC result
        if (-not $ptrResult -and $dr.PTR) { $ptrResult = $dr.PTR }
        if ($null -eq $fcrDnsResult -and $null -ne $dr.FCrDNS) { $fcrDnsResult = $dr.FCrDNS }
        if ($dnssecStatus -eq 'Unknown' -and $dr.DNSSEC -ne 'Unknown') { $dnssecStatus = $dr.DNSSEC }
    }

    # Consistency
    $uniqueA = @($resolvedIPs.Values | ForEach-Object { ($_ | Sort-Object) -join ',' } | Select-Object -Unique)
    if ($uniqueA.Count -gt 1) {
        Write-Result "DNS consistency" "MISMATCH" "WARN"
        Add-Finding $Findings "DNS" "WARN" "DNS servers returning different IPs"
        $data['Consistent'] = $false
    } elseif ($uniqueA.Count -eq 1) {
        Write-Result "DNS consistency" "All agree" "OK"
        $data['Consistent'] = $true
    }

    # rDNS / FCrDNS
    if ($ptrResult) {
        Write-Result "Reverse DNS (PTR)" $ptrResult "INFO"
        if ($null -ne $fcrDnsResult) {
            if ($fcrDnsResult) {
                Write-Result "FCrDNS" "PASS — PTR resolves back to same IP" "OK"
            } else {
                Write-Result "FCrDNS" "FAIL — PTR hostname doesn't resolve back" "WARN"
                Add-Finding $Findings "DNS" "WARN" "Forward-confirmed reverse DNS failed — may cause rejection by mail/API servers"
            }
        }
    }
    $data['PTR'] = $ptrResult
    $data['FCrDNS'] = $fcrDnsResult

    # DNSSEC
    $dnssecDisplay = switch ($dnssecStatus) {
        'Validated' { Write-Result "DNSSEC" "Validated (RRSIG present)" "OK"; "Validated" }
        'NotSigned' { Write-Result "DNSSEC" "Not signed" "INFO"; "NotSigned" }
        'Error'     { Write-Result "DNSSEC" "Validation error" "WARN"; "Error" }
        default     { Write-Result "DNSSEC" "Unknown" "INFO"; "Unknown" }
    }
    $data['DNSSEC'] = $dnssecStatus

    # IPv6 Happy Eyeballs check
    if (-not $SkipIPv6 -and $resolvedIPv6.Count -gt 0 -and $resolvedIPs.Count -gt 0) {
        $ipv6Addr = ($resolvedIPv6.Values | Select-Object -First 1) | Select-Object -First 1
        # Quick TCP test to IPv6
        $ipv6Works = $false
        try {
            $tcp6 = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
            $ar6 = $tcp6.BeginConnect($ipv6Addr, 443, $null, $null)
            $ipv6Works = $ar6.AsyncWaitHandle.WaitOne(2000, $false) -and $tcp6.Connected
            if ($ipv6Works) { $tcp6.EndConnect($ar6) }
            $tcp6.Close()
        } catch {}

        if (-not $ipv6Works) {
            Write-Result "IPv6 connectivity" "AAAA record exists but IPv6 unreachable — browsers will delay 3s" "WARN"
            Add-Finding $Findings "IPV6" "WARN" "AAAA record exists for $Hostname but IPv6 path broken — Happy Eyeballs fallback adds ~3s delay"
            $data['HappyEyeballsIssue'] = $true
        } else {
            Write-Result "IPv6 connectivity" "AAAA reachable on TCP 443" "OK"
            $data['HappyEyeballsIssue'] = $false
        }
    }

    $data['Results'] = @($dnsResults | ForEach-Object {
        [ordered]@{ Server=$_.Server; Label=$_.Label; A=$_.A; AAAA=$_.AAAA; ATimeMs=$_.ATimeMs; ASuccess=$_.ASuccess; AError=$_.AError; DNSSEC=$_.DNSSEC }
    })

    Complete-DiagProgress
    return @{
        Data = $data
        ResolvedIPs = $resolvedIPs
        ResolvedIPv6 = $resolvedIPv6
        DnsFailures = $dnsFailures
    }
}

#endregion

#region === Phase 4: Route Trace ===

function Test-RouteTrace {
    param(
        [string]$TargetIP,
        [int[]]$Ports,
        [int]$MaxHops,
        [int]$Timeout,
        [bool]$Detailed,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 4: Route Trace to $TargetIP"
    Start-DiagProgress "Route Trace" 5
    $data = [ordered]@{ Hops = @() }

    $tracePort = if ($Ports -contains 443) { 443 } elseif ($Ports -contains 80) { 80 } else { $Ports[0] }
    Write-Result "Method" "ICMP TTL + TCP fallback (port $tracePort)" "INFO"

    $lastHop = $null; $lastHopNum = 0; $reached = $false
    $hops = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timeouts = 0

    for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {
        Update-DiagSubProgress "Hop $ttl/$MaxHops" $ttl $MaxHops
        $hopIP = $null; $hopRtt = $null; $hopStatus = 'timeout'

        try {
            $p = New-Object System.Net.NetworkInformation.Ping
            $po = New-Object System.Net.NetworkInformation.PingOptions($ttl, $true)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $pr = $p.Send($TargetIP, $Timeout, [byte[]]::new(32), $po)
            $sw.Stop()
            switch ($pr.Status) {
                'TtlExpired' { $hopIP = $pr.Address.ToString(); $hopRtt = [math]::Max($pr.RoundtripTime, $sw.ElapsedMilliseconds); $hopStatus = 'hop' }
                'Success'    { $hopIP = $pr.Address.ToString(); $hopRtt = [math]::Max($pr.RoundtripTime, $sw.ElapsedMilliseconds); $hopStatus = 'destination'; $reached = $true }
            }
            $p.Dispose()
        } catch {}

        if (-not $reached -and -not $hopIP) {
            try {
                $t = New-Object System.Net.Sockets.TcpClient
                $ar = $t.BeginConnect($TargetIP, $tracePort, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne(800, $false) -and $t.Connected) {
                    $hopIP = $TargetIP; $hopStatus = 'destination'; $reached = $true; $t.EndConnect($ar)
                }
                $t.Close()
            } catch {}
        }

        $hopName = if ($hopIP) { try { ([System.Net.Dns]::GetHostEntry($hopIP)).HostName } catch { $null } } else { $null }
        $hops.Add([PSCustomObject]@{ TTL=$ttl; IP=$hopIP; Hostname=$hopName; RTT=$hopRtt; Status=$hopStatus })

        if ($hopIP) {
            $timeouts = 0
            $display = if ($hopName -and $hopName -ne $hopIP) { "$hopIP ($hopName)" } else { $hopIP }
            $rtt = if ($hopRtt) { "${hopRtt}ms" } else { "n/a" }
            if ($hopStatus -eq 'destination') {
                Write-Result "Hop $ttl" "$display — DESTINATION [$rtt]" "OK"
            } elseif ($Detailed) {
                Write-Result "Hop $ttl" "$display [$rtt]" $(if ($hopRtt -gt 150) { "WARN" } else { "OK" })
            }
            # Spike detection
            if ($hopRtt -and $hopRtt -gt 150) {
                $prev = $hops | Where-Object { $_.IP -and $_.TTL -lt $ttl } | Select-Object -Last 1
                if ($prev -and $prev.RTT -and ($hopRtt - $prev.RTT) -gt 100) {
                    $spike = $hopRtt - $prev.RTT
                    if ($Detailed) { Write-Result "Spike" "+${spike}ms at hop $ttl" "WARN" }
                    Add-Finding $Findings "ROUTE" "WARN" "+${spike}ms spike at hop $ttl ($display)"
                }
            }
            $lastHop = $hopIP; $lastHopNum = $ttl
        } else {
            $timeouts++
            if ($Detailed) { Write-Result "Hop $ttl" "* (no response)" "WARN" }
        }

        if ($reached) { break }
        if ($timeouts -ge 5) { Write-Result "Trace halted" "5 consecutive timeouts" "WARN"; break }
    }

    $responded = ($hops | Where-Object { $_.IP }).Count
    Write-Result "Hops" "$($hops.Count) probed, $responded responded" "INFO"

    if ($reached) {
        $fh = $hops | Where-Object { $_.Status -eq 'destination' } | Select-Object -Last 1
        Write-Result "Destination" "Reached ($($fh.RTT)ms, hop $($fh.TTL))" "OK"
    } else {
        Write-Result "Destination" "NOT reached" "FAIL"
        if ($lastHop) {
            $ln = try { ([System.Net.Dns]::GetHostEntry($lastHop)).HostName } catch { $lastHop }
            $d = if ($ln -ne $lastHop) { "$lastHop ($ln)" } else { $lastHop }
            Write-Diagnosis "Last responsive: $d at hop $lastHopNum."
            Add-Finding $Findings "ROUTE" "FAIL" "Packets lost after hop $lastHopNum [$d]"
        } else {
            Write-Diagnosis "No hops responded — blocked at/near local network."
            Add-Finding $Findings "ROUTE" "FAIL" "No hops responded — local firewall/gateway blocking"
        }
    }

    $data['Hops'] = @($hops | ForEach-Object { [ordered]@{ TTL=$_.TTL; IP=$_.IP; Hostname=$_.Hostname; RTT=$_.RTT; Status=$_.Status } })
    $data['Reached'] = $reached
    Complete-DiagProgress
    return $data
}

#endregion

#region === Phase 5: MTU ===

function Test-MtuPath {
    param(
        [string]$TargetIP,
        [int]$Timeout,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 5: MTU Path Discovery"
    Start-DiagProgress "MTU Discovery" 6
    $data = [ordered]@{}

    $pinger = New-Object System.Net.NetworkInformation.Ping
    $opts = New-Object System.Net.NetworkInformation.PingOptions(128, $true)

    # Test 1500 first
    $standardOk = $false
    try {
        $r = $pinger.Send($TargetIP, $Timeout, [byte[]]::new(1472), $opts)
        if ($r.Status -eq 'Success') { $standardOk = $true }
    } catch {}

    if ($standardOk) {
        Write-Result "MTU 1500" "Standard Ethernet works" "OK"
        $data['PathMTU'] = 1500; $data['Status'] = 'OK'
    } else {
        # Verify small packets work
        $smallOk = $false
        try {
            $r = $pinger.Send($TargetIP, $Timeout, [byte[]]::new(40), $opts)
            if ($r.Status -eq 'Success') { $smallOk = $true }
        } catch {}

        if (-not $smallOk) {
            Write-Result "MTU" "ICMP blocked — cannot test" "WARN"
            Add-Finding $Findings "MTU" "WARN" "Cannot test path MTU — ICMP blocked"
            $data['Status'] = 'ICMP_BLOCKED'
        } else {
            $lo = 68; $hi = 1500; $best = 68
            for ($i = 0; $i -lt 15 -and ($hi - $lo) -gt 1; $i++) {
                Update-DiagSubProgress "Binary search: $lo-$hi" $i 15
                $mid = [math]::Floor(($lo + $hi) / 2)
                $pl = [math]::Max($mid - 28, 1)
                $ok = $false
                try { $r = $pinger.Send($TargetIP, $Timeout, [byte[]]::new($pl), $opts); $ok = ($r.Status -eq 'Success') } catch {}
                if ($ok) { $lo = $mid; $best = $mid } else { $hi = $mid }
            }
            $data['PathMTU'] = $best
            if ($best -lt 1500) {
                Write-Result "Path MTU" "$best bytes (below 1500)" "WARN"
                $msg = if ($best -le 1400) { "Path MTU $best — PMTU blackhole risk (VPN/tunnel overhead)" } else { "Path MTU $best (below 1500)" }
                Add-Finding $Findings "MTU" "WARN" $msg
                if ($best -le 1400) { Write-Diagnosis "MTU $best suggests VPN/tunnel overhead or router misconfiguration." "WARN" }
            } else {
                Write-Result "Path MTU" "$best bytes" "OK"
            }
            $data['Status'] = 'OK'
        }
    }

    $pinger.Dispose()
    Complete-DiagProgress
    return $data
}

#endregion

#region === Phase 6: TCP Connectivity ===

function Test-TcpConnectivity {
    param(
        [string]$TargetIP,
        [string]$TargetIPv6,
        [int[]]$Ports,
        [int]$Timeout,
        [bool]$SkipIPv6,
        [bool]$Detailed,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 6: TCP Port Connectivity (parallel)"
    Start-DiagProgress "TCP Connectivity" 7
    $data = [ordered]@{}

    $tcpBlock = {
        param($IP, $Port, $TimeoutMs, $Label)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $ar = $tcp.BeginConnect($IP, $Port, $null, $null)
            $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tcp.Connected
            $sw.Stop()
            if ($ok) { $tcp.EndConnect($ar) }
            $tcp.Close()
            [PSCustomObject]@{ IP=$IP; Port=$Port; Open=$ok; TimeMs=$sw.ElapsedMilliseconds; Error=$(if(-not $ok){'Timeout'}else{$null}); Label=$Label }
        } catch {
            $sw.Stop()
            $err = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            [PSCustomObject]@{ IP=$IP; Port=$Port; Open=$false; TimeMs=$sw.ElapsedMilliseconds; Error=$err; Label=$Label }
        }
    }

    $argSets = @()
    foreach ($port in $Ports) {
        $argSets += ,@($TargetIP, $port, $Timeout, "IPv4")
    }
    if (-not $SkipIPv6 -and $TargetIPv6) {
        foreach ($port in $Ports) {
            $argSets += ,@($TargetIPv6, $port, $Timeout, "IPv6")
        }
    }

    $results = Invoke-Parallel -ScriptBlock $tcpBlock -ArgumentSets $argSets -TimeoutMs ($Timeout * 2)
    $tcpMap = @{}

    foreach ($r in $results) {
        $prefix = if ($r.Label -eq 'IPv6') { "IPv6 " } else { "" }
        if ($r.Open) {
            $tcpMap["$($r.Label):$($r.Port)"] = $true
            $st = if ($r.TimeMs -gt 1000) { "WARN" } else { "OK" }
            Write-Result "${prefix}Port $($r.Port)" "OPEN [$($r.TimeMs)ms]" $st
            if ($st -eq 'WARN') { Add-Finding $Findings "TCP" "WARN" "${prefix}Port $($r.Port) slow ($($r.TimeMs)ms)" }
        } else {
            $tcpMap["$($r.Label):$($r.Port)"] = $false
            Write-Result "${prefix}Port $($r.Port)" "CLOSED/FILTERED: $($r.Error)" "FAIL"
            Add-Finding $Findings "TCP" "FAIL" "${prefix}Port $($r.Port) on $($r.IP) — $($r.Error)"
        }
    }

    # ICMP
    $ping = Invoke-PingTest -Target $TargetIP -Count 3
    if ($ping.Success) {
        $loss = $ping.Sent - $ping.Count
        Write-Result "ICMP Ping" "avg $($ping.LatencyMs)ms, $loss/$($ping.Sent) lost" $(if ($ping.LatencyMs -gt 200 -or $loss -gt 0) { "WARN" } else { "OK" })
        if ($ping.LatencyMs -gt 200) { Add-Finding $Findings "TCP" "WARN" "High latency $($ping.LatencyMs)ms" }
    } else {
        Write-Result "ICMP Ping" "No response" "WARN"
    }

    $data['Results'] = @($results | ForEach-Object { [ordered]@{ IP=$_.IP; Port=$_.Port; Open=$_.Open; TimeMs=$_.TimeMs; Error=$_.Error; Label=$_.Label } })
    Complete-DiagProgress
    return @{ Data = $data; TcpMap = $tcpMap }
}

#endregion

#region === Phase 7: TLS/SSL ===

function Test-TlsSsl {
    param(
        [string]$Hostname,
        [string]$TargetIP,
        [hashtable]$TcpMap,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    if (-not $TcpMap['IPv4:443']) {
        if ($TcpMap.Keys -match ':443$') { } else {
            Write-Phase "Phase 7: TLS/SSL"
            Write-Result "TLS" "Skipped — port 443 not reachable" "WARN"
            return [ordered]@{ Skipped = $true }
        }
    }

    Write-Phase "Phase 7: TLS/SSL Handshake"
    Start-DiagProgress "TLS/SSL" 8
    $data = [ordered]@{}

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($TargetIP, 443)
        Register-Disposable $tcp | Out-Null
        $certState = [hashtable]::Synchronized(@{ Errors = 'None'; Cert = $null })
        $cs = $certState  # local ref for closure

        $sslStream = New-Object System.Net.Security.SslStream(
            $tcp.GetStream(), $false,
            ([System.Net.Security.RemoteCertificateValidationCallback]{
                param($sender, $cert, $chain, $errors)
                $cs.Errors = $errors
                $cs.Cert = $cert
                return $true
            })
        )
        Register-Disposable $sslStream | Out-Null

        $sslStream.AuthenticateAsClient($Hostname)

        $proto = "$($sslStream.SslProtocol)"
        $cipher = "$($sslStream.CipherAlgorithm)"
        $bits = $sslStream.CipherStrength
        Write-Result "Protocol" $proto $(if ($proto -match 'Tls12|Tls13') { "OK" } else { "WARN" })
        Write-Result "Cipher" "$cipher (${bits}-bit)" "INFO"
        $data['Protocol'] = $proto; $data['Cipher'] = "$cipher (${bits}-bit)"

        if ($proto -notmatch 'Tls12|Tls13') { Add-Finding $Findings "TLS" "WARN" "Using $proto — should be TLS 1.2+" }

        if ($certState.Cert) {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$certState.Cert
            $daysLeft = ($cert.NotAfter - (Get-Date)).Days

            Write-Result "Subject" $cert.Subject "INFO"
            Write-Result "Issuer" $cert.Issuer "INFO"
            Write-Result "Expires" "$($cert.NotAfter) ($daysLeft days)" $(if ($daysLeft -lt 0){"FAIL"} elseif ($daysLeft -lt 30){"WARN"} else {"OK"})
            $data['Subject'] = $cert.Subject; $data['Issuer'] = $cert.Issuer
            $data['Expiry'] = $cert.NotAfter.ToString('o'); $data['DaysLeft'] = $daysLeft

            if ($daysLeft -lt 0) { Add-Finding $Findings "TLS" "FAIL" "Certificate EXPIRED $([math]::Abs($daysLeft)) days ago" }
            elseif ($daysLeft -lt 30) { Add-Finding $Findings "TLS" "WARN" "Certificate expires in $daysLeft days" }

            # SAN
            $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
            if ($san) {
                $sanText = $san.Format($true)
                $escaped = [regex]::Escape($Hostname)
                $wildcard = [regex]::Escape(($Hostname -replace '^[^.]+\.',''))
                $match = ($sanText -match $escaped) -or ($sanText -match "\*\.$wildcard")
                if (-not $match) {
                    Write-Result "SAN" "'$Hostname' NOT matched" "FAIL"
                    Add-Finding $Findings "TLS" "FAIL" "Certificate doesn't cover '$Hostname'"
                } else {
                    Write-Result "SAN" "Hostname matched" "OK"
                }
                $data['SANMatch'] = $match
            }

            if ("$($certState.Errors)" -ne 'None') {
                Write-Result "Validation" "$($certState.Errors)" "FAIL"
                Add-Finding $Findings "TLS" "FAIL" "Cert validation: $($certState.Errors)"
            }
        }

        $sslStream.Close(); $tcp.Close()
    } catch {
        $err = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Result "TLS" "FAILED: $err" "FAIL"
        Add-Finding $Findings "TLS" "FAIL" "TLS handshake failed — $err"
        $data['Error'] = $err
    }

    Complete-DiagProgress
    return $data
}

#endregion

#region === Phase 8: HTTP/HTTPS ===

function Test-HttpLayer {
    param(
        [string]$Hostname,
        [hashtable]$TcpMap,
        [string[]]$Paths,
        [int]$Timeout,
        [bool]$Detailed,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 8: HTTP/HTTPS Application Layer"
    Start-DiagProgress "HTTP/HTTPS" 9
    $data = [ordered]@{}

    $protocols = @()
    if ($TcpMap['IPv4:443']) { $protocols += 'https' }
    if ($TcpMap['IPv4:80'])  { $protocols += 'http' }

    if ($protocols.Count -eq 0) {
        Write-Result "HTTP" "Skipped — no ports reachable" "WARN"
        Complete-DiagProgress
        return $data
    }

    $step = 0; $total = $protocols.Count * $Paths.Count
    foreach ($proto in $protocols) {
        foreach ($path in $Paths) {
            $step++
            Update-DiagSubProgress "$proto $path" $step $total
            $url = "${proto}://${Hostname}${path}"
            $result = [ordered]@{ URL = $url }

            try {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $req = [System.Net.HttpWebRequest]::Create($url)
                $req.Timeout = $Timeout * 2
                $req.AllowAutoRedirect = $false
                $req.UserAgent = "NetDiag/3.0"

                $response = $req.GetResponse()
                $sw.Stop()

                $sc = [int]$response.StatusCode
                $sd = $response.StatusDescription
                $server = $response.Headers['Server']
                $via = $response.Headers['Via']

                $status = if ($sc -ge 200 -and $sc -lt 400) { "OK" } elseif ($sc -ge 400 -and $sc -lt 500) { "WARN" } else { "FAIL" }
                Write-Result "$($proto.ToUpper()) $path" "$sc $sd [$($sw.ElapsedMilliseconds)ms]" $status
                if ($server) { Write-Result "Server" $server "INFO" }
                if ($via) { Write-Result "Via (proxy)" $via "WARN"; Add-Finding $Findings "HTTP" "WARN" "Via: $via — proxied" }

                $result['Status'] = $sc; $result['TimeMs'] = $sw.ElapsedMilliseconds; $result['Server'] = $server

                if ($sc -in 301,302,307,308) {
                    $loc = $response.Headers['Location']
                    Write-Result "Redirect" $loc "INFO"
                    $result['Redirect'] = $loc
                }
                if ($sc -ge 500) { Add-Finding $Findings "HTTP" "FAIL" "$($proto.ToUpper()) $path returned $sc" }
                elseif ($sc -ge 400) { Add-Finding $Findings "HTTP" "WARN" "$($proto.ToUpper()) $path returned $sc" }
                if ($sw.ElapsedMilliseconds -gt 3000) { Add-Finding $Findings "HTTP" "WARN" "$($proto.ToUpper()) $path slow ($($sw.ElapsedMilliseconds)ms)" }

                $response.Close()
            } catch [System.Net.WebException] {
                $sw.Stop()
                $we = $_.Exception
                if ($we.Response) {
                    $sc = [int]$we.Response.StatusCode
                    Write-Result "$($proto.ToUpper()) $path" "$sc [$($sw.ElapsedMilliseconds)ms]" "FAIL"
                    Add-Finding $Findings "HTTP" "FAIL" "$($proto.ToUpper()) $path: $sc"
                    $result['Status'] = $sc; $we.Response.Close()
                } else {
                    Write-Result "$($proto.ToUpper()) $path" "FAILED: $($we.Message)" "FAIL"
                    Add-Finding $Findings "HTTP" "FAIL" "$($proto.ToUpper()) $path: $($we.Message)"
                    $result['Error'] = $we.Message
                }
            } catch {
                Write-Result "$($proto.ToUpper()) $path" "FAILED: $($_.Exception.Message)" "FAIL"
                $result['Error'] = $_.Exception.Message
            }
            $data["${proto}${path}"] = $result
        }
    }

    Complete-DiagProgress
    return $data
}

#endregion

#region === Phase 9: Bandwidth ===

function Test-Bandwidth {
    param(
        [int]$Timeout,
        [System.Collections.Generic.List[PSCustomObject]]$Findings
    )

    Write-Phase "Phase 9: Bandwidth Estimation"
    Start-DiagProgress "Bandwidth" 10
    $data = [ordered]@{}

    # Download test via Cloudflare
    $testUrls = @(
        @{ URL = 'https://speed.cloudflare.com/__down?bytes=1000000'; Size = 1000000; Label = '1MB' }
        @{ URL = 'https://speed.cloudflare.com/__down?bytes=10000000'; Size = 10000000; Label = '10MB' }
    )

    foreach ($test in $testUrls) {
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $wc = New-Object System.Net.WebClient
            $null = $wc.DownloadData($test.URL)
            $sw.Stop()
            $secs = $sw.Elapsed.TotalSeconds
            if ($secs -gt 0) {
                $mbps = [math]::Round(($test.Size * 8 / $secs) / 1000000, 2)
                Write-Result "Download ($($test.Label))" "${mbps} Mbps ($([math]::Round($secs, 2))s)" $(if ($mbps -lt 1) { "WARN" } else { "OK" })
                $data["Download_$($test.Label)"] = @{ Mbps = $mbps; Seconds = [math]::Round($secs, 2) }
                if ($mbps -lt 1) { Add-Finding $Findings "BANDWIDTH" "WARN" "Download speed ${mbps} Mbps (below 1 Mbps)" }
            }
            $wc.Dispose()
            # If 1MB was fast enough, skip 10MB
            if ($secs -lt 2 -and $test.Label -eq '1MB') { continue }
            # If 1MB was slow, skip 10MB
            if ($secs -gt 10 -and $test.Label -eq '1MB') {
                Write-Result "Download (10MB)" "Skipped — 1MB was too slow" "INFO"
                break
            }
        } catch {
            Write-Result "Download ($($test.Label))" "Failed: $($_.Exception.Message)" "WARN"
            $data["Download_$($test.Label)"] = @{ Error = $_.Exception.Message }
            break
        }
    }

    Complete-DiagProgress
    return $data
}

#endregion

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 4: SUMMARY & DIAGNOSIS                              ║
# ╚═══════════════════════════════════════════════════════════════╝

function Invoke-DiagSummary {
    param($Findings, [string]$Hostname, [string]$TargetIP)

    Write-Phase "DIAGNOSIS SUMMARY" "■"

    $failures = @($Findings | Where-Object { $_.Severity -eq 'FAIL' })
    $warnings = @($Findings | Where-Object { $_.Severity -eq 'WARN' })

    if ($failures.Count -eq 0 -and $warnings.Count -eq 0) {
        Write-Host "    All layers passed. $Hostname appears healthy." -ForegroundColor Green
        return
    }

    if ($failures.Count -gt 0) {
        Write-Host ""; Write-Host "    FAILURES ($($failures.Count)):" -ForegroundColor Red
        foreach ($f in $failures) { Write-Host "    [$($f.Layer)] $($f.Detail)" -ForegroundColor Red }
    }
    if ($warnings.Count -gt 0) {
        Write-Host ""; Write-Host "    WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
        foreach ($w in $warnings) { Write-Host "    [$($w.Layer)] $($w.Detail)" -ForegroundColor Yellow }
    }

    Write-Host ""; Write-Host "    ─── ROOT CAUSE ANALYSIS ───" -ForegroundColor Cyan
    $order = @('CONTROL','LOCAL','HOSTS','FIREWALL','VPN','PROXY','DOH','DNS','IPV6','ROUTE','MTU','TCP','TLS','HTTP','BANDWIDTH')
    $root = $null
    foreach ($l in $order) { if ($failures | Where-Object { $_.Layer -eq $l }) { $root = $l; break } }

    if ($root) {
        $rf = @($failures | Where-Object { $_.Layer -eq $root })
        switch ($root) {
            'CONTROL'  { Write-Host "    INTERNET CONNECTIVITY FAILURE — not specific to $Hostname." -ForegroundColor Red }
            'LOCAL'    { Write-Host "    LOCAL NETWORK problem. Fix before investigating further." -ForegroundColor Red }
            'HOSTS'    { Write-Host "    HOSTS file override affecting $Hostname." -ForegroundColor Red }
            'FIREWALL' { Write-Host "    Local FIREWALL blocking outbound." -ForegroundColor Red; $rf | ForEach-Object { Write-Host "    $($_.Detail)" -ForegroundColor Yellow } }
            'VPN'      { Write-Host "    VPN altering routing." -ForegroundColor Red }
            'PROXY'    { Write-Host "    PROXY unreachable — HTTP will fail." -ForegroundColor Red }
            'DOH'      { Write-Host "    DNS-over-HTTPS misconfiguration." -ForegroundColor Red }
            'DNS'      { Write-Host "    DNS resolution failure." -ForegroundColor Red }
            'IPV6'     { Write-Host "    IPv6 path broken (AAAA exists) — browsers delayed ~3s." -ForegroundColor Red }
            'ROUTE'    { Write-Host "    ROUTING failure between you and $TargetIP." -ForegroundColor Red; $rf | ForEach-Object { Write-Host "    $($_.Detail)" -ForegroundColor Yellow } }
            'MTU'      { Write-Host "    PATH MTU issue — large packets silently dropped." -ForegroundColor Red }
            'TCP'      { Write-Host "    TCP ports blocked/closed on $TargetIP." -ForegroundColor Red }
            'TLS'      { Write-Host "    TLS/SSL issue (network fine)." -ForegroundColor Red; $rf | ForEach-Object { Write-Host "    $($_.Detail)" -ForegroundColor Yellow } }
            'HTTP'     { Write-Host "    APPLICATION layer error (network + TLS fine)." -ForegroundColor Red }
            'BANDWIDTH'{ Write-Host "    BANDWIDTH severely limited." -ForegroundColor Red }
        }
    } elseif ($warnings.Count -gt 0) {
        Write-Host "    No hard failures — minor issues detected." -ForegroundColor Yellow
    }

    Write-Host ""; Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
}

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 5: SINGLE RUN ORCHESTRATOR                          ║
# ╚═══════════════════════════════════════════════════════════════╝

function Invoke-NetDiagRun {
    param(
        [string]$Hostname, [int[]]$Ports, [string[]]$Paths, [string[]]$DnsServers, [string]$ControlTarget,
        [int]$MaxHops, [int]$Timeout, [bool]$SkipHttp, [bool]$SkipTrace, [bool]$SkipMtu, [bool]$SkipIPv6,
        [bool]$TestBandwidth, [bool]$Detailed, [int]$RunNumber
    )

    $findings = New-FindingsCollector
    $run = [ordered]@{ RunNumber = $RunNumber; Timestamp = (Get-Date).ToString('o'); Target = $Hostname; Phases = [ordered]@{} }

    # Phase 0
    $p0 = Test-LocalOverrides -Hostname $Hostname -Ports $Ports -Detailed $Detailed -Findings $findings
    $run.Phases['Overrides'] = $p0
    $hostsOverride = $p0['HostsOverride']

    # Phase 1
    $p1 = Test-ControlTarget -ControlTarget $ControlTarget -Timeout $Timeout -Findings $findings
    $run.Phases['Control'] = $p1

    # Phase 2
    $p2Result = Test-LocalNetwork -SkipIPv6 $SkipIPv6 -Detailed $Detailed -Findings $findings
    $run.Phases['LocalNet'] = $p2Result.Data
    $systemDns = $p2Result.SystemDNS

    # Phase 3
    $p3Result = Test-DnsResolution -Hostname $Hostname -ExtraDnsServers $DnsServers -SystemDns $systemDns `
        -Timeout $Timeout -SkipIPv6 $SkipIPv6 -Detailed $Detailed -Findings $findings
    $run.Phases['DNS'] = $p3Result.Data
    $resolvedIPs = $p3Result.ResolvedIPs
    $resolvedIPv6 = $p3Result.ResolvedIPv6

    # Determine target IP
    $targetIP = $null; $targetIPv6 = $null
    if ($hostsOverride) {
        $targetIP = $hostsOverride
    } elseif ($resolvedIPs.Count -gt 0) {
        $targetIP = ($resolvedIPs.Values | Select-Object -First 1) | Select-Object -First 1
    }
    if ($resolvedIPv6.Count -gt 0) {
        $targetIPv6 = ($resolvedIPv6.Values | Select-Object -First 1) | Select-Object -First 1
    }

    if (-not $targetIP) {
        Invoke-DiagSummary -Findings $findings -Hostname $Hostname -TargetIP $null
        $run['Findings'] = @($findings | ForEach-Object { [ordered]@{ Layer=$_.Layer; Severity=$_.Severity; Detail=$_.Detail; Time=$_.Time } })
        return $run
    }

    # Phase 4
    if (-not $SkipTrace) {
        $run.Phases['Route'] = Test-RouteTrace -TargetIP $targetIP -Ports $Ports -MaxHops $MaxHops -Timeout $Timeout -Detailed $Detailed -Findings $findings
    }

    # Phase 5
    if (-not $SkipMtu) {
        $run.Phases['MTU'] = Test-MtuPath -TargetIP $targetIP -Timeout $Timeout -Findings $findings
    }

    # Phase 6
    $p6Result = Test-TcpConnectivity -TargetIP $targetIP -TargetIPv6 $targetIPv6 -Ports $Ports -Timeout $Timeout -SkipIPv6 $SkipIPv6 -Detailed $Detailed -Findings $findings
    $run.Phases['TCP'] = $p6Result.Data
    $tcpMap = $p6Result.TcpMap

    # Phase 7
    if ($Ports -contains 443) {
        $run.Phases['TLS'] = Test-TlsSsl -Hostname $Hostname -TargetIP $targetIP -TcpMap $tcpMap -Findings $findings
    }

    # Phase 8
    if (-not $SkipHttp) {
        $run.Phases['HTTP'] = Test-HttpLayer -Hostname $Hostname -TcpMap $tcpMap -Paths $Paths -Timeout $Timeout -Detailed $Detailed -Findings $findings
    }

    # Phase 9
    if ($TestBandwidth) {
        $run.Phases['Bandwidth'] = Test-Bandwidth -Timeout $Timeout -Findings $findings
    }

    # Summary
    Invoke-DiagSummary -Findings $findings -Hostname $Hostname -TargetIP $targetIP

    $run['Findings'] = @($findings | ForEach-Object { [ordered]@{ Layer=$_.Layer; Severity=$_.Severity; Detail=$_.Detail; Time=$_.Time } })
    $run['TargetIP'] = $targetIP
    return $run
}

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 6: BASELINE COMPARISON                              ║
# ╚═══════════════════════════════════════════════════════════════╝

function Compare-Baseline {
    param($Current, $BaselinePath)

    Write-Phase "BASELINE COMPARISON" "◆"

    try {
        $baseline = Get-Content $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Host "    Could not load baseline: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $baseFindings = @($baseline.Runs[0].Findings)
    $currFindings = @($Current.Runs[0].Findings)

    $baseSet = @{}; foreach ($f in $baseFindings) { $baseSet["$($f.Layer)|$($f.Detail)"] = $f }
    $currSet = @{}; foreach ($f in $currFindings) { $currSet["$($f.Layer)|$($f.Detail)"] = $f }

    $newIssues = @(); $resolved = @(); $ongoing = @()

    foreach ($key in $currSet.Keys) {
        if ($baseSet.ContainsKey($key)) { $ongoing += $currSet[$key] }
        else { $newIssues += $currSet[$key] }
    }
    foreach ($key in $baseSet.Keys) {
        if (-not $currSet.ContainsKey($key)) { $resolved += $baseSet[$key] }
    }

    if ($newIssues.Count -gt 0) {
        Write-Host ""; Write-Host "    NEW ISSUES ($($newIssues.Count)):" -ForegroundColor Red
        foreach ($i in $newIssues) { Write-Host "    [$($i.Layer)] $($i.Severity): $($i.Detail)" -ForegroundColor Red }
    }
    if ($resolved.Count -gt 0) {
        Write-Host ""; Write-Host "    RESOLVED ($($resolved.Count)):" -ForegroundColor Green
        foreach ($r in $resolved) { Write-Host "    [$($r.Layer)] $($r.Detail)" -ForegroundColor Green }
    }
    if ($ongoing.Count -gt 0) {
        Write-Host ""; Write-Host "    ONGOING ($($ongoing.Count)):" -ForegroundColor Yellow
        foreach ($o in $ongoing) { Write-Host "    [$($o.Layer)] $($o.Detail)" -ForegroundColor Yellow }
    }
    if ($newIssues.Count -eq 0 -and $resolved.Count -eq 0 -and $ongoing.Count -eq 0) {
        Write-Host "    No findings in either baseline or current run." -ForegroundColor Green
    }

    # IP change detection
    $baseIP = $baseline.Runs[0].TargetIP
    $currIP = $Current.Runs[0].TargetIP
    if ($baseIP -and $currIP -and $baseIP -ne $currIP) {
        Write-Host ""; Write-Host "    IP CHANGED: $baseIP -> $currIP" -ForegroundColor Magenta
    }
}

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 7: HTML REPORT GENERATOR                            ║
# ╚═══════════════════════════════════════════════════════════════╝

function Export-HtmlReport {
    param($ExportData, [string]$Path)

    $hostname = $ExportData.Metadata.Target
    $runs = $ExportData.Runs

    # Build findings rows
    $findingsHtml = foreach ($run in $runs) {
        foreach ($f in $run.Findings) {
            $color = switch ($f.Severity) { 'FAIL' { '#e74c3c' } 'WARN' { '#f39c12' } default { '#2ecc71' } }
            $badge = "<span class='badge' style='background:$color'>$($f.Severity)</span>"
            "<tr><td>$($run.RunNumber)</td><td>$badge</td><td><strong>$($f.Layer)</strong></td><td>$($f.Detail)</td></tr>"
        }
    }

    # Build phase detail sections
    $phaseHtml = foreach ($run in $runs) {
        $sections = foreach ($phaseName in $run.Phases.Keys) {
            $pd = $run.Phases[$phaseName]
            $pdJson = ($pd | ConvertTo-Json -Depth 5 -Compress) -replace '<', '&lt;' -replace '>', '&gt;'
            @"
<details class="phase-detail">
<summary>$phaseName</summary>
<pre>$pdJson</pre>
</details>
"@
        }
        if ($runs.Count -gt 1) {
            "<h3>Run $($run.RunNumber)</h3>" + ($sections -join "`n")
        } else {
            $sections -join "`n"
        }
    }

    # Traceroute SVG (first run)
    $traceSvg = ""
    $firstRoute = $runs[0].Phases['Route']
    if ($firstRoute -and $firstRoute.Hops) {
        $hops = $firstRoute.Hops
        $maxRtt = [math]::Max(1, ($hops | Where-Object { $_.RTT } | ForEach-Object { $_.RTT } | Measure-Object -Maximum).Maximum)
        $barWidth = 600; $barHeight = [math]::Max(100, $hops.Count * 22 + 40)
        $bars = for ($i = 0; $i -lt $hops.Count; $i++) {
            $h = $hops[$i]
            $y = 20 + ($i * 22)
            $label = if ($h.IP) { "$($h.TTL). $($h.IP)" } else { "$($h.TTL). *" }
            $w = if ($h.RTT) { [math]::Max(2, [math]::Round(($h.RTT / $maxRtt) * 450)) } else { 0 }
            $fill = if ($h.Status -eq 'destination') { '#2ecc71' } elseif (-not $h.IP) { '#555' } elseif ($h.RTT -gt 150) { '#f39c12' } else { '#3498db' }
            $rttLabel = if ($h.RTT) { "$($h.RTT)ms" } else { "" }
            "<text x='2' y='$($y+14)' fill='#aaa' font-size='11'>$label</text><rect x='140' y='$($y+2)' width='$w' height='16' fill='$fill' rx='3'/><text x='$($w+145)' y='$($y+14)' fill='#ccc' font-size='10'>$rttLabel</text>"
        }
        $traceSvg = @"
<h2>Route Trace Visualization</h2>
<svg width='$barWidth' height='$barHeight' xmlns='http://www.w3.org/2000/svg' style='background:#111;border-radius:8px;padding:5px'>
$($bars -join "`n")
</svg>
"@
    }

    # DNS timing chart
    $dnsSvg = ""
    $firstDns = $runs[0].Phases['DNS']
    if ($firstDns -and $firstDns.Results) {
        $dnsR = $firstDns.Results
        $maxDns = [math]::Max(1, ($dnsR | ForEach-Object { $_.ATimeMs } | Measure-Object -Maximum).Maximum)
        $dnsH = [math]::Max(60, $dnsR.Count * 28 + 30)
        $dnsBars = for ($i = 0; $i -lt $dnsR.Count; $i++) {
            $d = $dnsR[$i]
            $y = 15 + ($i * 28)
            $w = [math]::Max(2, [math]::Round(($d.ATimeMs / $maxDns) * 400))
            $fill = if ($d.ASuccess) { if ($d.ATimeMs -gt 500) { '#f39c12' } else { '#2ecc71' } } else { '#e74c3c' }
            $label = "$($d.Label) ($($d.Server))"
            "<text x='2' y='$($y+14)' fill='#aaa' font-size='11'>$label</text><rect x='180' y='$($y+2)' width='$w' height='18' fill='$fill' rx='3'/><text x='$($w+185)' y='$($y+14)' fill='#ccc' font-size='10'>$($d.ATimeMs)ms</text>"
        }
        $dnsSvg = @"
<h2>DNS Timing</h2>
<svg width='620' height='$dnsH' xmlns='http://www.w3.org/2000/svg' style='background:#111;border-radius:8px;padding:5px'>
$($dnsBars -join "`n")
</svg>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetDiag Report — $hostname</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;line-height:1.6}
.container{max-width:1100px;margin:0 auto}
h1{color:#58a6ff;margin-bottom:5px;font-size:1.8em}
h2{color:#8b949e;margin:25px 0 10px;font-size:1.2em;border-bottom:1px solid #21262d;padding-bottom:5px}
h3{color:#58a6ff;margin:15px 0 5px}
.subtitle{color:#8b949e;margin-bottom:20px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;background:#161b22;padding:15px;border-radius:8px;margin:15px 0}
.meta-item .label{color:#8b949e;font-size:.8em;text-transform:uppercase;letter-spacing:.5px}
.meta-item .value{color:#f0f6fc;font-weight:600;font-size:1.05em}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:.9em}
th{background:#161b22;color:#58a6ff;text-align:left;padding:10px 12px;position:sticky;top:0}
td{padding:8px 12px;border-bottom:1px solid #21262d}
tr:hover{background:#161b22}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:.75em;font-weight:600}
details{background:#161b22;border:1px solid #21262d;border-radius:6px;margin:8px 0}
details summary{padding:10px 15px;cursor:pointer;font-weight:600;color:#c9d1d9}
details summary:hover{color:#58a6ff}
details pre{padding:15px;overflow-x:auto;font-size:.8em;color:#8b949e;border-top:1px solid #21262d;white-space:pre-wrap;word-break:break-all}
.summary-box{background:#161b22;border-left:4px solid #58a6ff;padding:15px;margin:20px 0;border-radius:0 6px 6px 0;font-size:.9em}
.footer{text-align:center;color:#484f58;margin-top:40px;padding:15px;border-top:1px solid #21262d;font-size:.8em}
svg{margin:10px 0;display:block}
@media print{body{background:#fff;color:#000}th{background:#eee;color:#000}td{border-color:#ccc}.badge{border:1px solid #000}details{border-color:#ccc}}
</style>
</head>
<body>
<div class="container">
<h1>Network Stack Diagnostic Report</h1>
<p class="subtitle">NetDiag v3.0</p>

<div class="meta-grid">
<div class="meta-item"><div class="label">Target</div><div class="value">$hostname</div></div>
<div class="meta-item"><div class="label">Generated</div><div class="value">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div></div>
<div class="meta-item"><div class="label">Machine</div><div class="value">$($env:COMPUTERNAME ?? $(hostname))</div></div>
<div class="meta-item"><div class="label">Runs</div><div class="value">$($runs.Count)</div></div>
<div class="meta-item"><div class="label">Ports</div><div class="value">$($ExportData.Metadata.Ports -join ', ')</div></div>
<div class="meta-item"><div class="label">Resolved IP</div><div class="value">$($runs[0].TargetIP ?? 'N/A')</div></div>
</div>

<h2>Findings</h2>
<table><tr><th>Run</th><th>Severity</th><th>Layer</th><th>Detail</th></tr>
$($findingsHtml -join "`n")
</table>

$traceSvg
$dnsSvg

<h2>Phase Details</h2>
$($phaseHtml -join "`n")

<div class="summary-box">
<strong>Layer order:</strong> Control &rarr; Local Overrides (HOSTS, Proxy, Firewall, VPN, DoH) &rarr; Local Network &rarr; DNS (A, AAAA, DNSSEC, rDNS) &rarr; Route &rarr; MTU &rarr; TCP &rarr; TLS &rarr; HTTP &rarr; Bandwidth<br>
<strong>Methodology:</strong> Earliest failing layer = root cause. Later failures are typically downstream effects.
</div>

<div class="footer">NetDiag v3.0 &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
</div>
</body>
</html>
"@

    $html | Set-Content -Path $Path -Encoding UTF8
    Write-Host "  HTML report: $Path" -ForegroundColor Green
}

# ╔═══════════════════════════════════════════════════════════════╗
# ║  SECTION 8: MAIN EXECUTION                                   ║
# ╚═══════════════════════════════════════════════════════════════╝

$script:Hostname = Get-CleanHostname $Target

# ── Remote execution wrapper ──

if ($ComputerName) {
    Write-Host ""
    Write-Host "  Executing remotely on $ComputerName..." -ForegroundColor Magenta

    $remoteParams = @{
        Target = $Target; Ports = $Ports; Paths = $Paths; MaxHops = $MaxHops; Timeout = $Timeout
        SkipHttp = $SkipHttp.IsPresent; SkipTrace = $SkipTrace.IsPresent; SkipMtu = $SkipMtu.IsPresent
        SkipIPv6 = $SkipIPv6.IsPresent; TestBandwidth = $TestBandwidth.IsPresent; Detailed = $Detailed.IsPresent
        RepeatCount = $RepeatCount; RepeatInterval = $RepeatInterval; ControlTarget = $ControlTarget
    }
    if ($DnsServers) { $remoteParams['DnsServers'] = $DnsServers }

    $sessionParams = @{ ComputerName = $ComputerName }
    if ($Credential) { $sessionParams['Credential'] = $Credential }

    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath) { $scriptPath = $PSCommandPath }

        $session = New-PSSession @sessionParams
        # Copy script to remote
        $remotePath = "C:\Temp\NetDiag_Remote.ps1"
        Invoke-Command -Session $session -ScriptBlock { param($p) New-Item -Path (Split-Path $p) -ItemType Directory -Force | Out-Null } -ArgumentList $remotePath
        Copy-Item -Path $scriptPath -Destination $remotePath -ToSession $session

        $argString = ($remoteParams.GetEnumerator() | ForEach-Object {
            $v = $_.Value
            if ($v -is [bool]) { if ($v) { "-$($_.Key)" } }
            elseif ($v -is [array]) { "-$($_.Key) $($v -join ',')" }
            else { "-$($_.Key) '$v'" }
        }) -join ' '

        Invoke-Command -Session $session -ScriptBlock {
            param($path, $args)
            & $path @args
        } -ArgumentList $remotePath, $remoteParams

        Remove-PSSession $session
    } catch {
        Write-Host "  Remote execution failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Ensure PSRemoting is enabled: Enable-PSRemoting -Force" -ForegroundColor Yellow
    }
    return
}

# ── Local execution ──

Write-Host ""
Write-Host "  ╔════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "  ║         Network Stack Diagnostic v3.0                  ║" -ForegroundColor White
Write-Host "  ╚════════════════════════════════════════════════════════╝" -ForegroundColor White
Write-Host "  Target:   $($script:Hostname)" -ForegroundColor Gray
Write-Host "  Ports:    $($Ports -join ', ')" -ForegroundColor Gray
Write-Host "  Paths:    $($Paths -join ', ')" -ForegroundColor Gray
Write-Host "  Control:  $ControlTarget" -ForegroundColor Gray
Write-Host "  Time:     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "  PS:       $($PSVersionTable.PSVersion)" -ForegroundColor Gray
if ($RepeatCount -gt 1) { Write-Host "  Repeats:  $RepeatCount x ${RepeatInterval}s" -ForegroundColor Gray }

$allRuns = [System.Collections.Generic.List[object]]::new()

try {
    for ($run = 1; $run -le $RepeatCount; $run++) {
        if ($RepeatCount -gt 1) {
            Write-Host ""
            Write-Host "  ════════════ RUN $run of $RepeatCount ════════════" -ForegroundColor Magenta
        }

        $result = Invoke-NetDiagRun `
            -Hostname $script:Hostname -Ports $Ports -Paths $Paths -DnsServers $DnsServers `
            -ControlTarget $ControlTarget -MaxHops $MaxHops -Timeout $Timeout `
            -SkipHttp $SkipHttp.IsPresent -SkipTrace $SkipTrace.IsPresent -SkipMtu $SkipMtu.IsPresent `
            -SkipIPv6 $SkipIPv6.IsPresent -TestBandwidth $TestBandwidth.IsPresent `
            -Detailed $Detailed.IsPresent -RunNumber $run

        $allRuns.Add($result)

        if ($run -lt $RepeatCount) {
            Write-Host ""; Write-Host "  Waiting ${RepeatInterval}s..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $RepeatInterval
        }
    }
} finally {
    Complete-AllProgress
    Invoke-Cleanup
}

# ── Repeat analysis ──
if ($RepeatCount -gt 1) {
    Write-Phase "REPEAT ANALYSIS ($RepeatCount runs)" "■"
    $allF = @($allRuns | ForEach-Object { $_.Findings } | Where-Object { $_ })
    $failGroups = @($allF | Where-Object { $_.Severity -eq 'FAIL' } | Group-Object Layer)

    if ($failGroups.Count -gt 0) {
        Write-Host ""; Write-Host "    Failure frequency:" -ForegroundColor Cyan
        foreach ($g in $failGroups | Sort-Object Count -Descending) {
            $pct = [math]::Round(($g.Count / $RepeatCount) * 100)
            $label = if ($pct -eq 100) { "CONSISTENT" } elseif ($pct -ge 50) { "INTERMITTENT (freq)" } else { "INTERMITTENT (rare)" }
            Write-Host "    [$($g.Name)] $($g.Count)/$RepeatCount ($pct%) — $label" -ForegroundColor $(if ($pct -ge 50) { 'Red' } else { 'Yellow' })
        }
        Write-Host ""
        $allF | Where-Object { $_.Severity -eq 'FAIL' } | Select-Object Layer, Detail -Unique |
            ForEach-Object { Write-Host "    [$($_.Layer)] $($_.Detail)" -ForegroundColor Red }
    } else {
        Write-Host "    No failures across $RepeatCount runs." -ForegroundColor Green
    }
}

# ── Export ──
$exportData = [ordered]@{
    Metadata = [ordered]@{
        Tool = 'NetDiag v3.0'; Target = $script:Hostname; Ports = $Ports; Paths = $Paths
        ControlTarget = $ControlTarget; RunCount = $RepeatCount
        GeneratedAt = (Get-Date).ToString('o')
        Machine = $env:COMPUTERNAME ?? $(hostname); User = $env:USERNAME ?? $(whoami)
        PSVersion = "$($PSVersionTable.PSVersion)"
    }
    Runs = @($allRuns)
}

if ($OutputJson) {
    try {
        $exportData | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputJson -Encoding UTF8
        Write-Host ""; Write-Host "  JSON report: $OutputJson" -ForegroundColor Green
    } catch { Write-Host "  JSON failed: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($OutputHtml) {
    try { Export-HtmlReport -ExportData $exportData -Path $OutputHtml }
    catch { Write-Host "  HTML failed: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($SaveBaseline) {
    try {
        $exportData | ConvertTo-Json -Depth 10 | Set-Content -Path $SaveBaseline -Encoding UTF8
        Write-Host ""; Write-Host "  Baseline saved: $SaveBaseline" -ForegroundColor Green
    } catch { Write-Host "  Baseline save failed: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($CompareBaseline) {
    Compare-Baseline -Current $exportData -BaselinePath $CompareBaseline
}

Write-Host ""
Write-Host "  Diagnostic complete." -ForegroundColor Gray
Write-Host ""
