# Export scan results

function export_json(result::HostResult, filepath::String)
    open(filepath, "w") do f
        println(f, "{")
        println(f, "  \"ip\": \"$(result.ip)\",")
        println(f, "  \"hostname\": \"$(result.hostname)\",")
        println(f, "  \"os\": \"$(result.os_guess)\",")
        println(f, "  \"scan_time\": $(result.scan_time),")
        println(f, "  \"ports\": [")
        for (i, p) in enumerate(filter(p -> p.state == :open, result.ports))
            comma = i < length(result.ports) ? "," : ""
            println(f, "    {\"port\": $(p.port), \"service\": \"$(p.service)\", \"state\": \"$(p.state)\"}$(comma)")
        end
        println(f, "  ]")
        println(f, "}")
    end
end

function export_csv(result::HostResult, filepath::String)
    open(filepath, "w") do f
        println(f, "ip,port,protocol,state,service,version,response_time_ms")
        for p in result.ports
            println(f, "$(result.ip),$(p.port),$(p.protocol),$(p.state),$(p.service),$(p.version),$(round(p.response_time*1000, digits=2))")
        end
    end
end
