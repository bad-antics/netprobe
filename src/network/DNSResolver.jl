# DNS resolution utilities

function dns_lookup(hostname::String; record_type::String="A")
    results = DNSRecord[]
    
    try
        if record_type == "A"
            ip = string(getaddrinfo(hostname))
            push!(results, DNSRecord(hostname, "A", ip, 300))
        end
        
        # Reverse lookup
        if record_type == "PTR"
            name = try string(getnameinfo(getaddrinfo(hostname))) catch; "" end
            !isempty(name) && push!(results, DNSRecord(hostname, "PTR", name, 300))
        end
    catch e
        push!(results, DNSRecord(hostname, "ERROR", string(e), 0))
    end
    
    return results
end

function reverse_dns(ip::String)
    try
        return string(getnameinfo(getaddrinfo(ip)))
    catch
        return ""
    end
end

function batch_dns(hostnames::Vector{String})
    results = Dict{String, Vector{DNSRecord}}()
    for host in hostnames
        results[host] = dns_lookup(host)
    end
    return results
end
