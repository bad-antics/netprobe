# Traceroute implementation

function traceroute(host::String; max_hops::Int=30, timeout::Float64=2.0)
    ip = try string(getaddrinfo(host)) catch; host end
    hops = TraceHop[]
    
    println("Traceroute to $(host) ($(ip)), max $(max_hops) hops:\n")
    
    for ttl in 1:max_hops
        start = time()
        hop_ip = "*"
        hostname = "*"
        rtt = timeout * 1000
        
        # Simulated traceroute using TCP connect with TTL
        try
            sock = connect(ip, 80)
            rtt = (time() - start) * 1000
            hop_ip = ip
            hostname = try string(getnameinfo(getaddrinfo(ip))) catch; ip end
            close(sock)
            
            hop = TraceHop(ttl, hop_ip, hostname, rtt, ttl)
            push!(hops, hop)
            @printf(" %2d  %-40s  %.2f ms\n", ttl, hostname, rtt)
            break
        catch
            hop = TraceHop(ttl, "*", "*", rtt, ttl)
            push!(hops, hop)
            @printf(" %2d  *  *  *\n", ttl)
        end
    end
    
    return hops
end
