# REST API for NetProbe

function start_api_server(; port::Int=8089)
    server = listen(port)
    println("🌐 NetProbe API on http://localhost:\$port")
    println("  GET  /scan?host=X&ports=1-1024")
    println("  GET  /ping?host=X")
    println("  GET  /dns?host=X")
    println("  GET  /health")
    
    while true
        sock = accept(server)
        @async handle_request(sock)
    end
end

function handle_request(sock)
    try
        req = readline(sock)
        path = split(split(req)[2], "?")[1]
        
        resp = if path == "/health"
            "{\"status\":\"ok\",\"version\":\"2.0.0\"}"
        else
            "{\"error\":\"use /scan, /ping, or /dns\"}"
        end
        
        write(sock, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\$resp")
    catch; end
    close(sock)
end
