# OS fingerprinting via TCP/IP stack analysis

const OS_SIGNATURES = Dict(
    "Linux" => Dict("ttl" => 64, "window" => 5840, "df" => true),
    "Windows" => Dict("ttl" => 128, "window" => 65535, "df" => true),
    "macOS" => Dict("ttl" => 64, "window" => 65535, "df" => true),
    "FreeBSD" => Dict("ttl" => 64, "window" => 65535, "df" => true),
    "Cisco IOS" => Dict("ttl" => 255, "window" => 4128, "df" => false),
    "Solaris" => Dict("ttl" => 255, "window" => 8760, "df" => true),
)

function fingerprint_os(ip::String; port::Int=80)
    # Connect and analyze TCP characteristics
    try
        sock = connect(ip, port)
        
        # Analyze open port patterns for OS hints
        open_ports = Int[]
        for test_port in [22, 80, 135, 139, 443, 445, 3389]
            try
                t = connect(ip, test_port)
                push!(open_ports, test_port)
                close(t)
            catch; end
        end
        
        close(sock)
        
        # Heuristic OS detection
        if 3389 in open_ports || 445 in open_ports
            return ("Windows", 0.75)
        elseif 22 in open_ports && !(135 in open_ports)
            return ("Linux/Unix", 0.65)
        else
            return ("Unknown", 0.1)
        end
    catch
        return ("Unreachable", 0.0)
    end
end
