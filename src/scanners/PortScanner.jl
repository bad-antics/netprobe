# TCP/UDP port scanning engine

function scan_ports(host::String; ports=COMMON_PORTS, config::NetProbeConfig=DEFAULT_CONFIG)
    results = PortResult[]
    start_time = time()
    
    # Resolve hostname
    ip = try
        string(getaddrinfo(host))
    catch
        host
    end
    
    config.verbose && println("Scanning $(host) ($(ip))...")
    
    # Scan ports with concurrency control
    tasks = []
    semaphore = Base.Semaphore(config.max_concurrent)
    
    for port in ports
        t = @async begin
            Base.acquire(semaphore)
            try
                result = probe_port(ip, port, config.timeout)
                push!(results, result)
            finally
                Base.release(semaphore)
            end
        end
        push!(tasks, t)
    end
    
    for t in tasks
        wait(t)
    end
    
    sort!(results, by=r -> r.port)
    scan_time = time() - start_time
    
    hostname = try
        string(getnameinfo(getaddrinfo(host)))
    catch
        host
    end
    
    return HostResult(ip, hostname, results, "", 0.0, scan_time, now())
end

function probe_port(ip::String, port::Int, timeout::Float64)
    service = get(SERVICE_SIGNATURES, port, "unknown")
    start = time()
    
    try
        sock = connect(ip, port)
        rtt = time() - start
        
        # Try banner grab
        banner = ""
        try
            if bytesavailable(sock) > 0
                banner = String(read(sock, bytesavailable(sock)))
            end
        catch; end
        
        close(sock)
        return PortResult(port, :open, service, banner, "", :tcp, rtt)
    catch e
        rtt = time() - start
        if rtt >= timeout
            return PortResult(port, :filtered, service, "", "", :tcp, rtt)
        end
        return PortResult(port, :closed, service, "", "", :tcp, rtt)
    end
end

function scan_network(subnet::String; ports=COMMON_PORTS, config::NetProbeConfig=DEFAULT_CONFIG)
    # Parse CIDR notation (e.g., 192.168.1.0/24)
    parts = split(subnet, "/")
    base_ip = parts[1]
    prefix = length(parts) > 1 ? parse(Int, parts[2]) : 24
    
    hosts = HostResult[]
    alive = 0
    start_time = time()
    
    base_parts = parse.(Int, split(base_ip, "."))
    host_count = 2^(32 - prefix)
    
    config.verbose && println("Scanning $(subnet) ($(host_count) hosts)...")
    
    for i in 1:min(host_count-2, 254)
        ip = join([base_parts[1], base_parts[2], base_parts[3], i], ".")
        result = scan_host(ip, ports=ports, config=config)
        if any(p -> p.state == :open, result.ports)
            alive += 1
            push!(hosts, result)
        end
    end
    
    return NetworkResult(subnet, hosts, alive, host_count, time() - start_time)
end

scan_host = scan_ports  # alias
