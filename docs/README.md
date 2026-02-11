# NetProbe Documentation

## Overview

NetProbe is an advanced network probe and service discovery tool. It combines port scanning, service fingerprinting, OS detection, and vulnerability checking into a single efficient tool.

## Features

- **Smart Scanning** — Adaptive scan timing based on network conditions
- **Service Fingerprinting** — Deep protocol analysis beyond banner grabbing
- **OS Detection** — TCP/IP stack fingerprinting
- **Vulnerability Hints** — Cross-reference services with known CVEs
- **Scriptable** — Lua scripting engine for custom probes
- **Output Formats** — JSON, XML, CSV, human-readable

## Scan Types

| Type | Flag | Description |
|------|------|-------------|
| TCP SYN | `-sS` | Stealth SYN scan (default) |
| TCP Connect | `-sT` | Full TCP handshake |
| UDP | `-sU` | UDP port scan |
| Service | `-sV` | Version detection |
| OS | `-O` | OS fingerprinting |
| Script | `--script` | Run Lua probes |

## Quick Start

```bash
# Basic scan
netprobe 192.168.1.0/24

# Comprehensive scan
netprobe -sV -O --script=vuln 10.0.0.1

# Fast scan, top 100 ports
netprobe --top-ports 100 -T4 target.com
```

## Scripting

```lua
-- Custom probe script
probe = {
    name = "http-title",
    port = {80, 443, 8080, 8443},
    protocol = "tcp"
}

function run(host, port)
    local response = http.get(host, port, "/")
    local title = response:match("<title>(.-)</title>")
    return {title = title or "No title"}
end
```
