# Core types for NetProbe

struct PortResult
    port::Int
    state::Symbol      # :open, :closed, :filtered
    service::String
    banner::String
    version::String
    protocol::Symbol   # :tcp, :udp
    response_time::Float64
end

struct HostResult
    ip::String
    hostname::String
    ports::Vector{PortResult}
    os_guess::String
    os_confidence::Float64
    scan_time::Float64
    timestamp::DateTime
end

struct NetworkResult
    subnet::String
    hosts::Vector{HostResult}
    alive_count::Int
    total_scanned::Int
    duration::Float64
end

struct TraceHop
    hop::Int
    ip::String
    hostname::String
    rtt_ms::Float64
    ttl::Int
end

struct DNSRecord
    name::String
    record_type::String
    value::String
    ttl::Int
end

# Service signature database
const SERVICE_SIGNATURES = Dict{Int, String}(
    21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP",
    53 => "DNS", 80 => "HTTP", 110 => "POP3", 119 => "NNTP",
    123 => "NTP", 135 => "MSRPC", 139 => "NetBIOS", 143 => "IMAP",
    161 => "SNMP", 389 => "LDAP", 443 => "HTTPS", 445 => "SMB",
    465 => "SMTPS", 514 => "Syslog", 515 => "LPD", 548 => "AFP",
    554 => "RTSP", 587 => "Submission", 631 => "IPP", 636 => "LDAPS",
    993 => "IMAPS", 995 => "POP3S", 1080 => "SOCKS",
    1433 => "MSSQL", 1434 => "MSSQL-UDP", 1521 => "Oracle",
    2049 => "NFS", 2181 => "ZooKeeper", 3306 => "MySQL",
    3389 => "RDP", 5432 => "PostgreSQL", 5672 => "AMQP",
    5900 => "VNC", 6379 => "Redis", 6443 => "K8s-API",
    8080 => "HTTP-Proxy", 8443 => "HTTPS-Alt", 8888 => "HTTP-Alt",
    9090 => "Prometheus", 9200 => "Elasticsearch", 9300 => "ES-Transport",
    11211 => "Memcached", 27017 => "MongoDB", 50000 => "SAP",
)

const COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,161,389,
    443,445,465,514,548,554,587,993,995,1433,1521,2049,3306,3389,
    5432,5900,6379,8080,8443,9090,9200,27017]
