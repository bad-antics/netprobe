# Banner grabbing engine

function grab_banner(ip::String, port::Int; timeout::Float64=3.0, probe::String="")
    try
        sock = connect(ip, port)
        
        # Send probe if specified
        if !isempty(probe)
            write(sock, probe)
        end
        
        # Wait for response
        banner = ""
        deadline = time() + timeout
        while time() < deadline
            if bytesavailable(sock) > 0
                banner *= String(read(sock, bytesavailable(sock)))
                if length(banner) > 1024
                    break
                end
            end
            sleep(0.1)
        end
        
        close(sock)
        return strip(banner)
    catch
        return ""
    end
end

function batch_banner_grab(ip::String, ports::Vector{Int}; timeout::Float64=2.0)
    results = Dict{Int, String}()
    tasks = [@async begin
        banner = grab_banner(ip, port, timeout=timeout)
        if !isempty(banner)
            results[port] = banner
        end
    end for port in ports]
    
    for t in tasks
        wait(t)
    end
    return results
end
