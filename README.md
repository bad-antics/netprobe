# NetProbe.jl 🔍

A comprehensive network reconnaissance and port scanning toolkit for Julia with service detection, host discovery, and stealth capabilities.

[![Julia](https://img.shields.io/badge/Julia-1.6+-blue.svg)](https://julialang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔌 **Port Scanning** - TCP connect scans with configurable timeouts
- 🔎 **Service Detection** - Automatic service identification from banners
- 🌐 **Network Discovery** - Host discovery and ping sweeps
- 📡 **Banner Grabbing** - Capture service banners
- 🥷 **Stealth Mode** - Randomized timing and port order
- 📊 **CIDR Support** - Scan entire network ranges
- 🖥️ **OS Detection** - Guess operating system from open ports

## Installation

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/netprobe")
```

## Quick Start

### Port Scanning

```julia
using NetProbe

# Quick scan of common ports
result = quick_scan("192.168.1.1")

# Scan specific ports
result = scan_ports("example.com", [22, 80, 443, 8080])

# Scan port range
result = scan_range("192.168.1.1", 1, 1024)

# Scan top 100 most common ports
result = scan_top_ports("target.com", 100)

# Full port scan (1-65535)
result = full_scan("192.168.1.1")
```

### Network Discovery

```julia
# Discover live hosts in a subnet
live_hosts = discover_hosts("192.168.1.0/24", verbose=true)

# Ping sweep
hosts = ping_sweep("10.0.0.0/24")

# Scan multiple targets
targets = parse_targets("192.168.1.1-50")
result = scan_network(targets, [22, 80, 443])
```

### Banner Grabbing

```julia
# Grab banner from specific port
banner = grab_banner("192.168.1.1", 22)
println(banner)  # SSH-2.0-OpenSSH_8.9

# Detect service from banner
service = detect_service(banner)
println(service)  # ssh
```

### Stealth Scanning

```julia
# Slow, randomized scan to avoid detection
result = stealth_scan("192.168.1.1", COMMON_PORTS)
```

## Target Specification

NetProbe supports flexible target specification:

```julia
# Single IP
targets = parse_targets("192.168.1.1")

# CIDR notation
targets = parse_targets("192.168.1.0/24")  # 254 hosts

# IP range
targets = parse_targets("192.168.1.1-50")  # 50 hosts

# Comma-separated
targets = parse_targets("192.168.1.1, 192.168.1.2, 192.168.1.3")

# Expand CIDR manually
ips = expand_cidr("10.0.0.0/24")
```

## Port Specification

```julia
# Parse port specs
ports = parse_ports("22,80,443")           # Specific ports
ports = parse_ports("1-1024")              # Range
ports = parse_ports("22,80,443,8000-8100") # Mixed
ports = parse_ports("common")              # Top 22 common ports
ports = parse_ports("top100")              # Top 100 ports
ports = parse_ports("-")                   # All ports (1-65535)
```

## Service Detection

NetProbe identifies services by:
1. **Banner analysis** - Pattern matching against known signatures
2. **Port mapping** - Well-known port to service mapping

Supported services include:
- SSH, FTP, Telnet, SMTP, POP3, IMAP
- HTTP/HTTPS (nginx, Apache, IIS detection)
- MySQL, PostgreSQL, MongoDB, Redis
- RDP, VNC, SMB
- DNS, LDAP, Kerberos
- And many more...

## Output Formats

```julia
# Get formatted report
result = scan_network(["192.168.1.1", "192.168.1.2"], COMMON_PORTS)
println(format_results(result))

# Example output:
# ============================================================
# NetProbe Scan Report
# ============================================================
# Start Time: 2024-01-15T10:30:00
# Targets:    2 hosts
# ------------------------------------------------------------
# 
# Host: 192.168.1.1
# OS Guess: Linux/Unix
# 
# PORT      STATE    SERVICE       BANNER
# --------------------------------------------------
# 22/tcp    open     ssh           SSH-2.0-OpenSSH_8.9
# 80/tcp    open     http/nginx    HTTP/1.1 200 OK
# 443/tcp   open     https        
# ============================================================
# Summary: 2 hosts up, 5 open ports
# ============================================================
```

## API Reference

### Scanning Functions

| Function | Description |
|----------|-------------|
| `quick_scan(host)` | Scan common ports |
| `scan_ports(host, ports)` | Scan specific ports |
| `scan_range(host, start, end)` | Scan port range |
| `scan_top_ports(host, n)` | Scan top N ports |
| `full_scan(host)` | Scan all 65535 ports |
| `stealth_scan(host, ports)` | Slow randomized scan |
| `scan_network(targets, ports)` | Scan multiple hosts |

### Discovery Functions

| Function | Description |
|----------|-------------|
| `discover_hosts(cidr)` | Find live hosts |
| `ping_sweep(cidr)` | TCP ping sweep |
| `is_host_up(host)` | Check if host responds |

### Utility Functions

| Function | Description |
|----------|-------------|
| `grab_banner(host, port)` | Get service banner |
| `detect_service(banner)` | Identify service |
| `parse_targets(spec)` | Parse target specification |
| `parse_ports(spec)` | Parse port specification |
| `expand_cidr(cidr)` | Expand CIDR to IP list |

## Security Notice

⚠️ **This tool is for authorized security testing only.**

- Only scan systems you own or have explicit permission to test
- Unauthorized port scanning may be illegal in your jurisdiction
- Respect rate limits and network policies
- Use stealth mode when appropriate

## Use Cases

- 🔐 **Penetration Testing** - Authorized security assessments
- 🔍 **Network Auditing** - Inventory open services
- 🛡️ **Security Monitoring** - Detect unauthorized services
- 🏗️ **Infrastructure Discovery** - Map network topology
- 🎓 **Education** - Learn about network protocols

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Created by [bad-antics](https://github.com/bad-antics)

Part of the [Awesome Julia Security](https://github.com/bad-antics/awesome-julia-security) collection.
