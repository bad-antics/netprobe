# Report generation

function generate_report(result::HostResult; format::Symbol=:text)
    if format == :text
        return format_host_result(result)
    elseif format == :json
        filepath = "netprobe_$(result.ip)_$(Dates.format(now(), "yyyymmdd_HHMMSS")).json"
        export_json(result, filepath)
        return "Report saved: \$filepath"
    elseif format == :csv
        filepath = "netprobe_$(result.ip)_$(Dates.format(now(), "yyyymmdd_HHMMSS")).csv"
        export_csv(result, filepath)
        return "Report saved: \$filepath"
    end
end

function summary_report(results::Vector{HostResult})
    total_open = sum(count(p -> p.state == :open, h.ports) for h in results)
    total_hosts = length(results)
    
    println("\n📊 Network Scan Summary")
    println("═" ^ 40)
    println("  Hosts scanned: \$total_hosts")
    println("  Open ports found: \$total_open")
    println("  Avg ports/host: \$(round(total_open/max(1,total_hosts), digits=1))")
    
    # Service distribution
    services = Dict{String,Int}()
    for h in results
        for p in filter(p -> p.state == :open, h.ports)
            services[p.service] = get(services, p.service, 0) + 1
        end
    end
    
    println("\n  Top Services:")
    for (svc, count) in sort(collect(services), by=x->x[2], rev=true)[1:min(10,length(services))]
        println("    \$svc: \$count")
    end
end
