# Service and version detection

const SERVICE_PROBES = Dict(
    "HTTP" => "GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "SSH" => "",  # SSH sends banner first
    "FTP" => "",  # FTP sends banner first
    "SMTP" => "",  # SMTP sends banner first
    "MySQL" => "",  # MySQL sends greeting
)

const VERSION_PATTERNS = Dict(
    "SSH" => r"SSH-[\d.]+-(.+)",
    "HTTP" => r"Server: (.+)",
    "FTP" => r"220[- ](.+)",
    "SMTP" => r"220[- ](.+)",
    "MySQL" => r"([\d.]+)-",
    "Apache" => r"Apache/([\d.]+)",
    "nginx" => r"nginx/([\d.]+)",
    "OpenSSH" => r"OpenSSH_([\d.]+)",
)

function detect_service(ip::String, port::Int; timeout::Float64=3.0)
    service = get(SERVICE_SIGNATURES, port, "unknown")
    version = ""
    banner = grab_banner(ip, port, timeout=timeout)
    
    if !isempty(banner)
        for (name, pattern) in VERSION_PATTERNS
            m = match(pattern, banner)
            if m !== nothing
                service = name
                version = m.captures[1]
                break
            end
        end
    end
    
    return (service=service, version=version, banner=banner)
end
