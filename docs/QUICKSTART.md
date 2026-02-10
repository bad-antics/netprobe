# NetProbe Quick Start

## Install
```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/netprobe")
```

## Usage
```julia
using NetProbe

# Scan a host
result = scan_ports("target.com", ports=[22,80,443])
println(format_host_result(result))

# Network discovery
hosts = discover_hosts("192.168.1.0/24")

# Banner grabbing
banner = grab_banner("target.com", 22)

# Service detection
svc = detect_service("target.com", 80)
```
