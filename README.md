# NetDiag

**Network Stack Diagnostic Tool** — pinpoints exactly where in the network stack a connection problem occurs.

Instead of telling you "it doesn't work," NetDiag walks through every layer from your NIC to the HTTP response and tells you *which device, service, or configuration* is responsible.

```
.\NetDiag.ps1 -Target api.example.com

    ─── ROOT CAUSE ANALYSIS ───
    TCP ports blocked/closed on 203.0.113.42.
    Firewall, security group, or service not running.
```

---

## Table of Contents

- [What It Tests](#what-it-tests)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Parameters](#parameters)
- [Usage Examples](#usage-examples)
- [Understanding the Output](#understanding-the-output)
- [Diagnostic Layers](#diagnostic-layers)
- [Export & Reporting](#export--reporting)
- [Baseline Comparison](#baseline-comparison)
- [Repeat Mode](#repeat-mode)
- [Remote Execution](#remote-execution)
- [Architecture](#architecture)
- [Troubleshooting the Tool Itself](#troubleshooting-the-tool-itself)

---

## What It Tests

NetDiag runs through 10 diagnostic phases in dependency order. Each phase only runs if the prior layers support it — there's no point testing TLS if TCP can't connect.

| Phase | Layer | What It Checks |
|-------|-------|----------------|
| 0 | Local Overrides | HOSTS file, system proxy, PAC files, WinHTTP proxy, Windows Firewall outbound rules, active VPNs, DNS-over-HTTPS config |
| 1 | Control Target | Pings a known-good host (default `1.1.1.1`) to distinguish "my internet is down" from "their server is down" |
| 2 | Local Network | Active adapters, IPv4/IPv6 addresses, default gateways, gateway reachability, system DNS servers |
| 3 | DNS Resolution | Parallel queries to system + public DNS (Google, Cloudflare, Quad9), AAAA records, DNSSEC validation, reverse DNS, forward-confirmed rDNS, consistency checks, Happy Eyeballs detection |
| 4 | Route Trace | ICMP TTL stepping with TCP fallback, per-hop latency, spike detection, last-responsive-device identification |
| 5 | MTU Path | Binary search for path MTU with DF bit set, PMTU blackhole detection |
| 6 | TCP Connectivity | Parallel port scanning with latency measurement, IPv4 + IPv6, ICMP comparison |
| 7 | TLS/SSL | Protocol version, cipher suite, certificate subject/issuer/expiry, SAN hostname matching, chain validation errors |
| 8 | HTTP/HTTPS | Multi-path status codes, response timing, server headers, redirect chains, proxy `Via` header detection |
| 9 | Bandwidth | Optional download speed estimation via Cloudflare (1MB/10MB payloads) |

---

## Requirements

- **PowerShell 5.1** (Windows built-in) or **PowerShell 7+** (cross-platform)
- The script auto-detects the version and adjusts behavior accordingly
- **No external modules required** — uses only .NET Framework / .NET classes and built-in cmdlets

**Elevation (Administrator):** Not required, but recommended. Without it, the following checks degrade gracefully with a warning:

- Windows Firewall rule inspection
- VPN connection detection
- Some network adapter details

**Cross-platform notes:**

| Feature | Windows | Linux/macOS |
|---------|---------|-------------|
| HOSTS file check | `%SystemRoot%\System32\drivers\etc\hosts` | `/etc/hosts` |
| Proxy/PAC detection | Full (registry + WinHTTP) | Skipped |
| Firewall inspection | Full (Windows Firewall) | Skipped |
| VPN detection | Full (`Get-VpnConnection`) | Skipped |
| DoH detection | Win11+ | Skipped |
| DNS resolution | Full | Full |
| All network phases | Full | Full |

---

## Quick Start

```powershell
# Basic diagnostic
.\NetDiag.ps1 -Target example.com

# Full detail with report
.\NetDiag.ps1 -Target example.com -Detailed -OutputHtml report.html

# Test specific ports and URL paths
.\NetDiag.ps1 -Target api.example.com -Ports 443,8443 -Paths '/','api/v2/health'
```

---

## Parameters

### Target & Scope

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Target` | String | *(required)* | Hostname or URL to diagnose. Protocols and paths are stripped to extract the hostname. |
| `-Ports` | Int[] | `80, 443` | TCP ports to test connectivity on |
| `-Paths` | String[] | `/` | URL paths to test during the HTTP phase |
| `-ControlTarget` | String | `1.1.1.1` | Known-good host for internet connectivity verification |
| `-DnsServers` | String[] | *(none)* | Additional DNS servers to query (system DNS + public DNS are always included) |

### Tuning

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-MaxHops` | Int | `30` | Maximum TTL for traceroute |
| `-Timeout` | Int | `3000` | Timeout in milliseconds for individual tests |

### Skip Flags

| Parameter | Description |
|-----------|-------------|
| `-SkipHttp` | Skip HTTP/HTTPS application layer tests |
| `-SkipTrace` | Skip traceroute (saves 30-60s on bad networks) |
| `-SkipMtu` | Skip MTU path discovery |
| `-SkipIPv6` | Skip all IPv6 testing (AAAA queries, IPv6 TCP, Happy Eyeballs) |

### Optional Features

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-TestBandwidth` | Switch | off | Run download speed estimation |
| `-Detailed` | Switch | off | Show every traceroute hop, DNS timing, and sub-test result |

### Repeat Mode

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-RepeatCount` | Int (1-100) | `1` | Number of full diagnostic runs |
| `-RepeatInterval` | Int (1-3600) | `10` | Seconds between runs |

### Export

| Parameter | Type | Description |
|-----------|------|-------------|
| `-OutputJson` | String | File path for structured JSON report |
| `-OutputHtml` | String | File path for interactive HTML report |
| `-SaveBaseline` | String | Save this run as a baseline JSON for future comparison |
| `-CompareBaseline` | String | Path to a baseline JSON to diff against current results |

### Remote Execution

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ComputerName` | String | Remote machine to run the diagnostic on (via PSRemoting) |
| `-Credential` | PSCredential | Credential for remote session authentication |

---

## Usage Examples

### Everyday Troubleshooting

```powershell
# "The website is down" — find out why
.\NetDiag.ps1 -Target app.contoso.com

# API endpoint returning errors — test the specific path
.\NetDiag.ps1 -Target api.contoso.com -Ports 443,8443 -Paths '/','api/v2/health','/.well-known/openid-configuration'

# Internal service on a non-standard port
.\NetDiag.ps1 -Target ldap.corp.local -Ports 389,636,88 -SkipHttp

# Test against your internal DNS servers specifically
.\NetDiag.ps1 -Target app.contoso.com -DnsServers "10.0.0.53","10.0.1.53"
```

### Intermittent Issues

```powershell
# Run 10 times over 5 minutes — catch flapping connections
.\NetDiag.ps1 -Target app.contoso.com -RepeatCount 10 -RepeatInterval 30

# Quick repeated test during a maintenance window
.\NetDiag.ps1 -Target app.contoso.com -RepeatCount 20 -RepeatInterval 5 -SkipTrace -SkipMtu
```

### Reporting & Handoff

```powershell
# Generate both report formats for a ticket
.\NetDiag.ps1 -Target app.contoso.com -Detailed -OutputHtml "ticket-12345.html" -OutputJson "ticket-12345.json"

# Full diagnostic with bandwidth for an escalation
.\NetDiag.ps1 -Target app.contoso.com -Detailed -TestBandwidth -OutputHtml "escalation.html"
```

### Baseline Workflow

```powershell
# Capture a known-good state
.\NetDiag.ps1 -Target app.contoso.com -SaveBaseline "app-baseline.json"

# Later, when something breaks — compare against the baseline
.\NetDiag.ps1 -Target app.contoso.com -CompareBaseline "app-baseline.json"

# Output:
#   NEW ISSUES (2):
#     [TLS] Certificate EXPIRED 3 days ago
#     [HTTP] HTTPS / returned 502
#   RESOLVED (1):
#     [DNS] DNS 10.0.0.53 slow (820ms)
#   ONGOING (1):
#     [MTU] Path MTU 1380 bytes
#   IP CHANGED: 203.0.113.42 -> 198.51.100.17
```

### Remote Execution

```powershell
# Run from a server's perspective
.\NetDiag.ps1 -Target database.internal -ComputerName APPSERVER01 -Credential (Get-Credential)

# Useful for: "it works from my machine but not from the server"
```

### Speed Optimized

```powershell
# Skip slow phases — just DNS + TCP + TLS + HTTP
.\NetDiag.ps1 -Target app.contoso.com -SkipTrace -SkipMtu -SkipIPv6

# Absolute minimum — DNS and TCP only
.\NetDiag.ps1 -Target app.contoso.com -SkipTrace -SkipMtu -SkipIPv6 -SkipHttp
```

---

## Understanding the Output

### Severity Levels

| Icon | Level | Meaning |
|------|-------|---------|
| `[OK]` | OK | Test passed |
| `[--]` | INFO | Informational — no action needed |
| `[!!]` | WARN | Potential issue or degradation — may or may not be the cause |
| `[XX]` | FAIL | Hard failure — something is definitively broken |

### Root Cause Analysis

The summary section identifies the **earliest failing layer** in the dependency chain. The logic: if DNS fails, there's no point blaming HTTP — DNS is the root cause. Layer order:

```
CONTROL → LOCAL → HOSTS → FIREWALL → VPN → PROXY → DOH →
DNS → IPV6 → ROUTE → MTU → TCP → TLS → HTTP → BANDWIDTH
```

The first layer with a `FAIL` finding is reported as the root cause. Everything downstream is considered a side effect.

### Reading the Traceroute

```
[OK] Hop 1: 192.168.1.1 (router.local) [2ms]
[OK] Hop 2: 10.0.0.1 (isp-gw.example.net) [8ms]
[!!] Hop 3: 172.16.0.1 (core-rtr.isp.net) [185ms]    ← latency spike
[!!] Spike: +177ms at hop 3
[OK] Hop 7: 203.0.113.42 — DESTINATION [45ms]
```

Silent hops (shown as `*`) are normal — many routers drop ICMP by policy. The TCP fallback will still detect if the destination is reachable. Only consecutive timeouts at the end of the trace indicate a real problem.

### Happy Eyeballs Detection

If the output shows:

```
[!!] IPv6 connectivity: AAAA record exists but IPv6 unreachable — browsers will delay 3s
```

This means the domain has an IPv6 address published in DNS, but the IPv6 network path is broken. Modern browsers try IPv6 first (the "Happy Eyeballs" algorithm) and wait up to 3 seconds before falling back to IPv4. This manifests as slow page loads that are hard to diagnose with traditional tools.

---

## Diagnostic Layers

### Phase 0: Local Overrides

Checks things that silently intercept or redirect traffic before it even hits the network.

**HOSTS file:** A stale entry like `127.0.0.1 api.production.com` from a developer's debugging session will completely bypass DNS resolution. The script checks for any entry matching the target hostname.

**Proxy / PAC:** Enterprise environments often use proxy auto-config (PAC) files that route traffic through inspection proxies. The script detects system proxy settings, fetches and parses PAC files to identify configured proxies, checks if the target hostname is in the proxy bypass list, and tests proxy reachability.

**WinHTTP:** Many Windows services (including PowerShell's `Invoke-WebRequest`) use WinHTTP settings independently from IE/Edge proxy settings. A mismatch between the two is a common source of "works in the browser but not in my script" issues.

**Firewall:** Checks outbound block rules in Windows Firewall that match the target ports. A blanket outbound block on port 443 will kill HTTPS but might leave ICMP (ping) working — leading to the classic "I can ping it but can't connect."

**VPN:** Detects active VPN connections and whether they use split tunneling. Full-tunnel VPNs route all traffic through the VPN gateway, which may not have a route to your target. Split-tunnel VPNs only route specific subnets.

**DNS-over-HTTPS (Win11+):** If the system is configured to use DoH, traditional DNS debugging (like `nslookup` or this script's DNS phase) may not reflect what the OS actually resolves, since DoH queries go over HTTPS to the DNS provider directly.

### Phase 1: Control Target

A simple but critical sanity check. Before investigating the target, the script tests connectivity to a known-good host (default `1.1.1.1`). If the control target is also unreachable, the problem is your internet connection — not the target server.

### Phase 2: Local Network

Verifies the machine has a working network stack: active adapter, IP address, default gateway, and that the gateway is reachable. Also checks IPv6 readiness (global IPv6 address + IPv6 default gateway).

### Phase 3: DNS Resolution

Queries multiple DNS servers **in parallel** and compares results.

**What it catches:**
- A specific DNS server being down or slow
- DNS poisoning or split-horizon inconsistencies (different servers returning different IPs)
- Missing AAAA records or IPv6 resolution failures
- DNSSEC validation status
- Forward-confirmed reverse DNS failures (relevant for mail servers and some APIs that check rDNS)
- Happy Eyeballs issues (AAAA exists but IPv6 TCP fails)

### Phase 4: Route Trace

ICMP TTL stepping with TCP fallback. For each hop, sends an ICMP packet with incrementing TTL. When a router decrements TTL to zero, it responds with "TTL Exceeded," revealing its IP. If ICMP is blocked at a hop, the script tries a direct TCP connection to verify destination reachability.

**Latency spike detection:** If the latency between consecutive hops jumps by more than 100ms, it flags the specific hop. This often indicates a geographic jump (US→Europe), congestion at a peering point, or a saturated link.

### Phase 5: MTU Path Discovery

Uses binary search to find the maximum packet size that can traverse the full path without fragmentation (DF bit set). Standard Ethernet MTU is 1500 bytes.

**Why this matters:** VPN tunnels add encapsulation overhead (typically 50-80 bytes), reducing the effective MTU to ~1420-1450. If path MTU discovery is broken (common when ICMP is blocked), large packets like TLS handshakes silently disappear. The connection appears to hang during the handshake. Small packets (pings, DNS) work fine — only large transfers fail.

### Phase 6: TCP Connectivity

Parallel TCP connection attempts to all specified ports on both IPv4 and IPv6 addresses. Reports open/closed/filtered status and connection latency.

### Phase 7: TLS/SSL

Full certificate inspection using a thread-safe `SslStream` approach with a synchronized hashtable for the validation callback.

**What it catches:** expired certificates, hostname/SAN mismatches, weak TLS protocol versions (below TLS 1.2), certificate chain validation errors, and cipher suite details.

### Phase 8: HTTP/HTTPS

Tests each combination of protocol (HTTP/HTTPS) × path (`/`, `/api/health`, etc.). Reports status codes, server headers, redirect chains, and detects proxy `Via` headers that indicate the request was intercepted by a transparent proxy.

**Multi-path testing** is critical for reverse proxy setups where `/` might return 200 but `/api/v2/` returns 502 because the backend pool for that path is down.

### Phase 9: Bandwidth (Optional)

Downloads test payloads from Cloudflare's speed test endpoint and calculates throughput in Mbps. Adaptive: if the 1MB test is fast, it runs 10MB for a more accurate measurement. If 1MB is slow, it skips 10MB to avoid wasting time.

---

## Export & Reporting

### JSON Report (`-OutputJson`)

Structured data containing every phase's raw results, all findings, metadata, and timing. Suitable for:
- Automated parsing and alerting
- Feeding into monitoring dashboards
- Programmatic comparison between runs
- Archiving diagnostic results

### HTML Report (`-OutputHtml`)

Interactive dark-themed report with:
- **Metadata grid** — target, machine, timestamp, ports, resolved IP
- **Findings table** — color-coded severity badges, layer, detail
- **Traceroute SVG chart** — horizontal bar chart showing per-hop latency with color coding (green = OK, yellow = slow, red = destination, gray = timeout)
- **DNS timing SVG chart** — per-server query time comparison
- **Collapsible phase details** — `<details>` elements with raw JSON for each phase
- **Print-friendly** — `@media print` CSS override for clean black-on-white printing

---

## Baseline Comparison

The baseline workflow lets you capture a known-good state and compare against it later.

```powershell
# Save baseline
.\NetDiag.ps1 -Target app.contoso.com -SaveBaseline baseline.json

# Compare (can also combine with -OutputHtml for a full report)
.\NetDiag.ps1 -Target app.contoso.com -CompareBaseline baseline.json -OutputHtml diff-report.html
```

The comparison categorizes every finding as:

| Category | Meaning |
|----------|---------|
| **NEW** | Failure/warning that wasn't in the baseline — something broke |
| **RESOLVED** | Was in the baseline but is now gone — something was fixed |
| **ONGOING** | Present in both — pre-existing issue |
| **IP CHANGED** | The resolved IP address is different from the baseline |

---

## Repeat Mode

For intermittent issues that don't reproduce on a single test.

```powershell
.\NetDiag.ps1 -Target app.contoso.com -RepeatCount 10 -RepeatInterval 30
```

After all runs complete, the script prints a frequency analysis:

```
    Failure frequency:
    [DNS] 3/10 (30%) — INTERMITTENT (rare)
    [TCP] 2/10 (20%) — INTERMITTENT (rare)
    [ROUTE] 10/10 (100%) — CONSISTENT
```

**CONSISTENT** (100%) failures point to a permanent misconfiguration. **INTERMITTENT** failures suggest flapping routes, overloaded DNS servers, or connection pool exhaustion.

---

## Remote Execution

Run the diagnostic from a different machine's perspective using PowerShell Remoting.

```powershell
.\NetDiag.ps1 -Target database.internal -ComputerName APPSERVER01 -Credential (Get-Credential)
```

**Prerequisites on the remote machine:**
- PowerShell Remoting enabled (`Enable-PSRemoting -Force`)
- WinRM service running
- Firewall allows WinRM (TCP 5985/5986)
- `C:\Temp` must be writable (script is copied there temporarily)

**Use case:** "It works from my workstation but not from the application server." Running from the server's perspective tests the actual network path the application uses, including any server-specific firewall rules, proxy settings, or VPN routes.

---

## Architecture

The script is organized into 8 sections:

```
Section 1: Compatibility Layer    — PS 5.1/7 abstraction, cross-platform detection
Section 2: Helpers                — Display, data collection, disposable tracking,
                                    progress, parallel execution (runspace pools)
Section 3: Phase Functions        — One function per diagnostic phase (10 phases)
Section 4: Summary & Diagnosis    — Root cause analysis engine
Section 5: Run Orchestrator       — Sequences phases with dependency checks
Section 6: Baseline Comparison    — Diff engine for before/after analysis
Section 7: HTML Report Generator  — Templated report with inline SVG charts
Section 8: Main Execution         — Parameter handling, repeat loop, export, remote wrapper
```

### Design Decisions

**Parallel execution via runspaces:** DNS queries and TCP port scans run in parallel using `[RunspaceFactory]::CreateRunspacePool`. Arguments are passed via `AddArgument()` — never string interpolation — so hostnames containing quotes, backticks, or other special characters won't break scriptblock compilation.

**Thread-safe TLS callback:** The SSL validation callback captures certificate info into a `[hashtable]::Synchronized(@{})` rather than `$script:` variables, avoiding race conditions if the callback runs on a thread pool thread.

**Disposable tracking:** Every `TcpClient`, `Ping`, `SslStream`, and `RunspacePool` is registered with a cleanup tracker. A `try/finally` around the main loop ensures everything is disposed on Ctrl+C.

**ICMP traceroute with TCP fallback:** Pure TCP traceroute (setting TTL on a SYN packet) is unreliable on Windows because the OS doesn't consistently honor socket TTL options on TCP. The script uses ICMP with TTL stepping (which reliably triggers "TTL Exceeded" from routers) and supplements with TCP connect attempts to catch cases where the destination is reachable but intermediate hops block ICMP.

**Root cause = earliest failing layer:** The summary doesn't just list failures — it identifies which layer failed first in the dependency chain. If DNS fails, TCP/TLS/HTTP failures are expected downstream effects, not independent problems.

---

## Troubleshooting the Tool Itself

**"Access denied" or "elevation required" warnings:**
Run as Administrator for full firewall and VPN inspection. The script still works without elevation — those specific checks just get skipped.

**Script takes a long time:**
Traceroute and MTU discovery are the slowest phases. Use `-SkipTrace -SkipMtu` for a fast run. On a bad network with many timeouts, consider reducing `-MaxHops 15` or `-Timeout 1500`.

**"Execution policy" error:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\NetDiag.ps1 -Target example.com
```

**Remote execution fails:**
Verify PSRemoting on the target: `Test-WSMan -ComputerName SERVERNAME`. If it fails, run `Enable-PSRemoting -Force` on the remote machine and ensure WinRM traffic (TCP 5985) isn't blocked.

**DNS phase shows all failures but the site works in a browser:**
Check the DoH finding in Phase 0. If DNS-over-HTTPS is active, the browser resolves names via HTTPS to the DNS provider directly, bypassing the traditional DNS path that this script (and `nslookup`) tests.

**MTU phase shows "ICMP blocked":**
The target or an intermediate device is dropping ICMP. The MTU phase can't function without ICMP. If you suspect a PMTU issue, try `.\NetDiag.ps1 -Target example.com -SkipMtu` and check whether TLS handshakes fail (large packets) while DNS/ping (small packets) succeed — that pattern strongly suggests a PMTU blackhole even without direct measurement.
