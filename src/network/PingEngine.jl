# Ping / host discovery

function ping_host(host::String; count::Int=4, timeout::Float64=2.0)
    results = Float64[]
    ip = try string(getaddrinfo(host)) catch; host end
    
    println("PING $(host) ($(ip)):")
    
    for i in 1:count
        start = time()
        try
            sock = connect(ip, 80)
            rtt = (time() - start) * 1000
            close(sock)
            push!(results, rtt)
            @printf("  Reply from %s: time=%.2fms\n", ip, rtt)
        catch
            rtt = (time() - start) * 1000
            if rtt >= timeout * 1000
                println("  Request timed out")
            else
                push!(results, rtt)
                @printf("  Reply from %s: time=%.2fms\n", ip, rtt)
            end
        end
        i < count && sleep(1)
    end
    
    if !isempty(results)
        println("\n--- $(host) ping statistics ---")
        @printf("  min/avg/max = %.2f/%.2f/%.2f ms\n", minimum(results), sum(results)/length(results), maximum(results))
    end
    
    return results
end

function discover_hosts(subnet::String; timeout::Float64=1.0)
    alive = String[]
    parts = parse.(Int, split(split(subnet, "/")[1], "."))
    
    tasks = [@async begin
        ip = join([parts[1], parts[2], parts[3], i], ".")
        try
            sock = connect(ip, 80)
            close(sock)
            push!(alive, ip)
        catch; end
    end for i in 1:254]
    
    for t in tasks; wait(t); end
    return sort(alive)
end
