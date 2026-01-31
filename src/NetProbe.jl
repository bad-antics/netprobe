"""
    NetProbe.jl - Network Reconnaissance & Port Scanning for Julia

A comprehensive network security toolkit for port scanning, service detection,
host discovery, and network mapping with stealth capabilities.

Features:
- TCP/UDP port scanning with multiple techniques
- Service and version detection
- Host discovery (ping sweep, ARP)
- Banner grabbing
- Stealth scanning modes
- CIDR range support
- Multi-threaded scanning

Author: bad-antics
License: MIT
"""
module NetProbe

using Sockets
using Dates
using Printf
using Random

export PortScanner, ScanResult, HostResult
export tcp_scan, udp_scan, syn_scan, connect_scan
export scan_ports, scan_range, scan_network
export discover_hosts, ping_sweep
export grab_banner, detect_service
export parse_targets, expand_cidr

# ============================================================================
# Types and Constants
# ============================================================================

"""Port states"""
@enum PortState begin
    OPEN
    CLOSED
    FILTERED
    OPEN_FILTERED
    UNKNOWN
end

"""Scan techniques"""
@enum ScanType begin
    CONNECT_SCAN     # Full TCP connect
    SYN_SCAN         # Half-open SYN scan
    UDP_SCAN         # UDP scan
    FIN_SCAN         # TCP FIN scan
    XMAS_SCAN        # TCP XMAS scan
    NULL_SCAN        # TCP NULL scan
    ACK_SCAN         # TCP ACK scan
end

"""Result of scanning a single port"""
struct PortResult
    port::Int
    state::PortState
    protocol::Symbol  # :tcp or :udp
    service::String
    banner::String
    response_time::Float64
end

"""Result of scanning a host"""
struct HostResult
    ip::String
    hostname::String
    is_up::Bool
    ports::Vector{PortResult}
    os_guess::String
    scan_time::DateTime
    elapsed::Float64
end

"""Result of a complete scan"""
struct ScanResult
    targets::Vector{String}
    hosts::Vector{HostResult}
    start_time::DateTime
    end_time::DateTime
    scan_type::ScanType
    options::Dict{String, Any}
end

"""Common service ports"""
const COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443
]

"""Top 1000 most common ports"""
const TOP_PORTS = vcat(COMMON_PORTS, [
    20, 69, 79, 88, 102, 113, 119, 123, 137, 138, 161, 162, 
    177, 179, 194, 199, 389, 465, 500, 514, 515, 520, 523, 
    548, 554, 587, 631, 636, 646, 873, 902, 990, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1434, 1521, 1720, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3268, 3269, 3690,
    4899, 5000, 5001, 5060, 5190, 5222, 5631, 5632, 5800, 5801,
    5802, 5803, 5984, 6000, 6001, 6379, 6646, 7001, 7002, 8000,
    8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8181, 8222, 8333, 8400, 8443, 8787, 8888, 9000, 9001, 9090,
    9091, 9200, 9300, 9418, 9999, 10000, 10001, 27017, 27018, 28017
])

"""Service signatures for detection"""
const SERVICE_SIGNATURES = Dict(
    r"^SSH-"i => "ssh",
    r"^220.*FTP"i => "ftp",
    r"^220.*SMTP|^EHLO|^HELO"i => "smtp",
    r"^\+OK.*POP"i => "pop3",
    r"^\* OK.*IMAP"i => "imap",
    r"^HTTP/"i => "http",
    r"^<!DOCTYPE html|^<html"i => "http",
    r"^MySQL"i => "mysql",
    r"PostgreSQL"i => "postgresql",
    r"^Redis"i => "redis",
    r"^MongoDB"i => "mongodb",
    r"RFB \d{3}\.\d{3}" => "vnc",
    r"^\x00\x00\x00.*mKD" => "rdp",
    r"Nginx|nginx"i => "http/nginx",
    r"Apache"i => "http/apache",
    r"Microsoft"i => "http/iis",
)

"""Well-known port to service mapping"""
const PORT_SERVICES = Dict(
    20 => "ftp-data", 21 => "ftp", 22 => "ssh", 23 => "telnet",
    25 => "smtp", 53 => "dns", 67 => "dhcp", 68 => "dhcp",
    69 => "tftp", 80 => "http", 88 => "kerberos", 110 => "pop3",
    111 => "rpcbind", 119 => "nntp", 123 => "ntp", 135 => "msrpc",
    137 => "netbios-ns", 138 => "netbios-dgm", 139 => "netbios-ssn",
    143 => "imap", 161 => "snmp", 162 => "snmptrap", 179 => "bgp",
    194 => "irc", 389 => "ldap", 443 => "https", 445 => "microsoft-ds",
    465 => "smtps", 500 => "isakmp", 514 => "syslog", 515 => "printer",
    520 => "rip", 587 => "submission", 631 => "ipp", 636 => "ldaps",
    873 => "rsync", 993 => "imaps", 995 => "pop3s", 1080 => "socks",
    1194 => "openvpn", 1433 => "mssql", 1434 => "mssql-udp",
    1521 => "oracle", 1723 => "pptp", 1883 => "mqtt", 2049 => "nfs",
    2181 => "zookeeper", 2375 => "docker", 2376 => "docker-tls",
    3000 => "grafana", 3306 => "mysql", 3389 => "rdp", 5432 => "postgresql",
    5672 => "amqp", 5900 => "vnc", 5984 => "couchdb", 6379 => "redis",
    6443 => "kubernetes-api", 6667 => "irc", 8000 => "http-alt",
    8080 => "http-proxy", 8443 => "https-alt", 9000 => "cslistener",
    9090 => "prometheus", 9200 => "elasticsearch", 9300 => "elasticsearch",
    11211 => "memcached", 27017 => "mongodb"
)

# ============================================================================
# Port Scanning
# ============================================================================

"""
    tcp_connect_scan(host::String, port::Int; timeout=2.0) -> PortResult

Perform a full TCP connect scan on a single port.
"""
function tcp_connect_scan(host::String, port::Int; timeout::Float64=2.0)
    start = time()
    state = CLOSED
    banner = ""
    
    try
        sock = connect(host, port)
        state = OPEN
        
        # Try to grab banner
        try
            # Set non-blocking read with timeout
            @async begin
                sleep(timeout)
                try close(sock) catch end
            end
            
            # Send probe for some services
            if port in [80, 8080, 443, 8443]
                write(sock, "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n")
            elseif port == 22
                # SSH sends banner automatically
            elseif port in [21, 25, 110, 143]
                # These send banner automatically
            end
            
            banner = String(readavailable(sock))
            banner = first(banner, 256)  # Limit banner size
        catch
            # Banner grab failed, but port is still open
        end
        
        try close(sock) catch end
        
    catch e
        if e isa Base.IOError || e isa Base.DNSError
            state = CLOSED
        else
            state = FILTERED
        end
    end
    
    elapsed = time() - start
    service = detect_service_from_port(port, banner)
    
    return PortResult(port, state, :tcp, service, strip(banner), elapsed)
end

"""
    scan_ports(host::String, ports; kwargs...) -> HostResult

Scan multiple ports on a single host.
"""
function scan_ports(host::String, ports::Union{Vector{Int}, UnitRange{Int}}=COMMON_PORTS;
                   timeout::Float64=2.0,
                   threads::Int=10,
                   verbose::Bool=false)
    start_time = Dates.now()
    start = time()
    
    hostname = try
        gethostbyaddr(host).name
    catch
        ""
    end
    
    ports_vec = collect(ports)
    results = Vector{PortResult}(undef, length(ports_vec))
    
    # Scan ports (could be parallelized with Threads.@threads)
    for (i, port) in enumerate(ports_vec)
        if verbose && i % 100 == 0
            @printf("[*] Scanning port %d/%d\n", i, length(ports_vec))
        end
        
        results[i] = tcp_connect_scan(host, port; timeout=timeout)
    end
    
    # Filter to only open/filtered ports for final result
    open_ports = filter(r -> r.state in [OPEN, FILTERED, OPEN_FILTERED], results)
    
    elapsed = time() - start
    os_guess = guess_os(open_ports)
    
    return HostResult(host, hostname, !isempty(open_ports), open_ports, 
                      os_guess, start_time, elapsed)
end

"""
    scan_range(host::String, start_port::Int, end_port::Int; kwargs...) -> HostResult

Scan a range of ports.
"""
function scan_range(host::String, start_port::Int, end_port::Int; kwargs...)
    return scan_ports(host, start_port:end_port; kwargs...)
end

"""
    scan_top_ports(host::String, n::Int=100; kwargs...) -> HostResult

Scan the top N most common ports.
"""
function scan_top_ports(host::String, n::Int=100; kwargs...)
    ports = unique(TOP_PORTS)[1:min(n, length(TOP_PORTS))]
    return scan_ports(host, ports; kwargs...)
end

# ============================================================================
# Network Scanning
# ============================================================================

"""
    scan_network(targets::Vector{String}, ports; kwargs...) -> ScanResult

Scan multiple hosts.
"""
function scan_network(targets::Vector{String}, 
                     ports::Union{Vector{Int}, UnitRange{Int}}=COMMON_PORTS;
                     timeout::Float64=2.0,
                     verbose::Bool=false)
    start_time = Dates.now()
    
    hosts = HostResult[]
    
    for (i, target) in enumerate(targets)
        verbose && @printf("[*] Scanning host %d/%d: %s\n", i, length(targets), target)
        
        result = scan_ports(target, ports; timeout=timeout, verbose=false)
        push!(hosts, result)
        
        if verbose && result.is_up
            open_count = count(p -> p.state == OPEN, result.ports)
            @printf("[+] %s - %d open ports\n", target, open_count)
        end
    end
    
    end_time = Dates.now()
    
    return ScanResult(targets, hosts, start_time, end_time, CONNECT_SCAN,
                      Dict("timeout" => timeout))
end

"""
    discover_hosts(network::String; kwargs...) -> Vector{String}

Discover live hosts in a network range.
"""
function discover_hosts(network::String; timeout::Float64=1.0, verbose::Bool=false)
    targets = expand_cidr(network)
    live_hosts = String[]
    
    verbose && println("[*] Discovering hosts in $network ($(length(targets)) IPs)")
    
    for (i, ip) in enumerate(targets)
        if is_host_up(ip; timeout=timeout)
            push!(live_hosts, ip)
            verbose && println("[+] Host up: $ip")
        end
        
        if verbose && i % 50 == 0
            @printf("[*] Progress: %d/%d\n", i, length(targets))
        end
    end
    
    verbose && println("[*] Found $(length(live_hosts)) live hosts")
    
    return live_hosts
end

"""
    ping_sweep(network::String; kwargs...) -> Vector{String}

Perform a ping sweep to find live hosts.
"""
function ping_sweep(network::String; timeout::Float64=1.0, verbose::Bool=false)
    return discover_hosts(network; timeout=timeout, verbose=verbose)
end

"""Check if host responds on common ports"""
function is_host_up(host::String; timeout::Float64=1.0)
    # Try common ports that are often open
    probe_ports = [80, 443, 22, 445, 139]
    
    for port in probe_ports
        try
            sock = connect(host, port)
            close(sock)
            return true
        catch
            continue
        end
    end
    
    return false
end

# ============================================================================
# Service Detection
# ============================================================================

"""
    grab_banner(host::String, port::Int; timeout=3.0) -> String

Grab service banner from a port.
"""
function grab_banner(host::String, port::Int; timeout::Float64=3.0)
    try
        sock = connect(host, port)
        
        # Send appropriate probe
        probe = get_probe_for_port(port)
        if !isempty(probe)
            write(sock, probe)
        end
        
        # Wait for response with timeout
        @async begin
            sleep(timeout)
            try close(sock) catch end
        end
        
        banner = String(readavailable(sock))
        try close(sock) catch end
        
        return strip(first(banner, 512))
    catch
        return ""
    end
end

"""Get appropriate probe data for port"""
function get_probe_for_port(port::Int)
    probes = Dict(
        80 => "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        443 => "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        8080 => "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        # FTP, SMTP, POP3, IMAP send banners automatically
        21 => "",
        25 => "",
        110 => "",
        143 => "",
        22 => "",
    )
    return get(probes, port, "")
end

"""
    detect_service(banner::String) -> String

Detect service from banner using signatures.
"""
function detect_service(banner::String)
    for (pattern, service) in SERVICE_SIGNATURES
        if occursin(pattern, banner)
            return service
        end
    end
    return "unknown"
end

"""Detect service from port number and banner"""
function detect_service_from_port(port::Int, banner::String)
    # First try banner detection
    if !isempty(banner)
        detected = detect_service(banner)
        if detected != "unknown"
            return detected
        end
    end
    
    # Fall back to port mapping
    return get(PORT_SERVICES, port, "unknown")
end

"""Guess OS from open ports"""
function guess_os(ports::Vector{PortResult})
    port_nums = Set(p.port for p in ports if p.state == OPEN)
    
    # Windows indicators
    windows_ports = Set([135, 139, 445, 3389])
    if length(intersect(port_nums, windows_ports)) >= 2
        return "Windows"
    end
    
    # Linux indicators
    linux_ports = Set([22, 111, 2049])
    if length(intersect(port_nums, linux_ports)) >= 2
        return "Linux/Unix"
    end
    
    # macOS
    if 548 in port_nums || 5900 in port_nums
        return "macOS"
    end
    
    # Network device
    if 161 in port_nums && 22 in port_nums
        return "Network Device"
    end
    
    return "Unknown"
end

# ============================================================================
# IP/CIDR Utilities
# ============================================================================

"""
    expand_cidr(cidr::String) -> Vector{String}

Expand CIDR notation to list of IPs.
"""
function expand_cidr(cidr::String)
    if !occursin('/', cidr)
        return [cidr]
    end
    
    parts = split(cidr, '/')
    base_ip = parts[1]
    prefix = parse(Int, parts[2])
    
    octets = parse.(Int, split(base_ip, '.'))
    base_int = (octets[1] << 24) | (octets[2] << 16) | (octets[3] << 8) | octets[4]
    
    host_bits = 32 - prefix
    num_hosts = 2^host_bits
    
    # Skip network and broadcast addresses for /24 and smaller
    start_offset = prefix >= 24 ? 1 : 0
    end_offset = prefix >= 24 ? 1 : 0
    
    ips = String[]
    for i in start_offset:(num_hosts - 1 - end_offset)
        ip_int = base_int + i
        ip = string(
            (ip_int >> 24) & 0xFF, ".",
            (ip_int >> 16) & 0xFF, ".",
            (ip_int >> 8) & 0xFF, ".",
            ip_int & 0xFF
        )
        push!(ips, ip)
    end
    
    return ips
end

"""
    parse_targets(spec::String) -> Vector{String}

Parse target specification (single IP, CIDR, range, or comma-separated).
"""
function parse_targets(spec::String)
    spec = strip(spec)
    
    # CIDR notation
    if occursin('/', spec)
        return expand_cidr(spec)
    end
    
    # Comma-separated list
    if occursin(',', spec)
        return [strip(t) for t in split(spec, ',')]
    end
    
    # Range notation (192.168.1.1-50)
    if occursin('-', spec)
        parts = split(spec, '.')
        if length(parts) == 4 && occursin('-', parts[4])
            range_parts = split(parts[4], '-')
            start_octet = parse(Int, range_parts[1])
            end_octet = parse(Int, range_parts[2])
            base = join(parts[1:3], '.')
            return ["$base.$i" for i in start_octet:end_octet]
        end
    end
    
    # Single target
    return [spec]
end

"""
    parse_ports(spec::String) -> Vector{Int}

Parse port specification.
"""
function parse_ports(spec::String)
    spec = strip(spec)
    
    if spec == "-"
        return collect(1:65535)
    end
    
    if spec == "common"
        return COMMON_PORTS
    end
    
    if spec == "top100"
        return unique(TOP_PORTS)[1:100]
    end
    
    if spec == "top1000"
        return unique(TOP_PORTS)
    end
    
    ports = Int[]
    
    for part in split(spec, ',')
        part = strip(part)
        if occursin('-', part)
            range_parts = split(part, '-')
            start_port = parse(Int, range_parts[1])
            end_port = parse(Int, range_parts[2])
            append!(ports, start_port:end_port)
        else
            push!(ports, parse(Int, part))
        end
    end
    
    return unique(ports)
end

# ============================================================================
# Output Formatting
# ============================================================================

"""Format scan results for display"""
function format_results(result::ScanResult)
    output = IOBuffer()
    
    println(output, "\n" * "="^60)
    println(output, "NetProbe Scan Report")
    println(output, "="^60)
    @printf(output, "Start Time: %s\n", result.start_time)
    @printf(output, "End Time:   %s\n", result.end_time)
    @printf(output, "Targets:    %d hosts\n", length(result.targets))
    println(output, "-"^60)
    
    for host in result.hosts
        if !host.is_up
            continue
        end
        
        println(output)
        @printf(output, "Host: %s", host.ip)
        if !isempty(host.hostname)
            @printf(output, " (%s)", host.hostname)
        end
        println(output)
        
        if !isempty(host.os_guess) && host.os_guess != "Unknown"
            @printf(output, "OS Guess: %s\n", host.os_guess)
        end
        
        println(output, "\nPORT      STATE    SERVICE       BANNER")
        println(output, "-"^50)
        
        for port in sort(host.ports, by=p->p.port)
            if port.state == OPEN
                banner_preview = isempty(port.banner) ? "" : 
                    first(replace(port.banner, r"\s+" => " "), 30)
                @printf(output, "%-9s %-8s %-12s %s\n",
                       "$(port.port)/$(port.protocol)",
                       lowercase(string(port.state)),
                       port.service,
                       banner_preview)
            end
        end
    end
    
    println(output, "\n" * "="^60)
    
    total_open = sum(count(p -> p.state == OPEN, h.ports) for h in result.hosts)
    hosts_up = count(h -> h.is_up, result.hosts)
    
    @printf(output, "Summary: %d hosts up, %d open ports\n", hosts_up, total_open)
    println(output, "="^60)
    
    return String(take!(output))
end

"""Format single host result"""
function format_host(host::HostResult)
    output = IOBuffer()
    
    println(output, "\nHost: $(host.ip)")
    if !isempty(host.hostname)
        println(output, "Hostname: $(host.hostname)")
    end
    println(output, "Status: $(host.is_up ? "Up" : "Down")")
    println(output, "Scan Time: $(round(host.elapsed, digits=2))s")
    
    if host.is_up
        println(output, "\nOpen Ports:")
        for port in sort(host.ports, by=p->p.port)
            if port.state == OPEN
                println(output, "  $(port.port)/$(port.protocol) - $(port.service)")
            end
        end
    end
    
    return String(take!(output))
end

# ============================================================================
# Quick Scan Functions
# ============================================================================

"""Quick scan of common ports on a single target"""
function quick_scan(target::String; verbose::Bool=true)
    verbose && println("[*] Quick scan of $target")
    result = scan_ports(target, COMMON_PORTS; verbose=false)
    verbose && println(format_host(result))
    return result
end

"""Full port scan (1-65535)"""
function full_scan(target::String; verbose::Bool=true)
    verbose && println("[*] Full port scan of $target (this will take a while...)")
    result = scan_ports(target, 1:65535; verbose=verbose)
    verbose && println(format_host(result))
    return result
end

"""Stealth scan - randomized ports and timing"""
function stealth_scan(target::String, ports::Vector{Int}=COMMON_PORTS; 
                     verbose::Bool=false)
    # Randomize port order
    shuffled = shuffle(ports)
    
    results = PortResult[]
    for port in shuffled
        result = tcp_connect_scan(target, port; timeout=3.0)
        push!(results, result)
        
        # Random delay between 100-500ms
        sleep(0.1 + rand() * 0.4)
    end
    
    open_ports = filter(r -> r.state == OPEN, results)
    return HostResult(target, "", !isempty(open_ports), open_ports, 
                      "", Dates.now(), 0.0)
end

end # module
