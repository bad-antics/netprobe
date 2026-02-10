# Display and formatting

function print_banner()
    println(raw"""
    ╔═══════════════════════════════════════╗
    ║   🌐 NetProbe v2.0.0                 ║
    ║   Julia Security Suite - NullSec     ║
    ╚═══════════════════════════════════════╝
    """)
end

function format_port_result(p::PortResult)
    state_icon = p.state == :open ? "🟢" : p.state == :filtered ? "🟡" : "🔴"
    svc = isempty(p.service) ? "" : " ($(p.service))"
    ver = isempty(p.version) ? "" : " [$(p.version)]"
    return @sprintf("  %s %5d/%-3s %-12s%s  %.1fms", state_icon, p.port, p.protocol, p.service, ver, p.response_time * 1000)
end

function format_host_result(h::HostResult)
    lines = String[]
    push!(lines, "\n═══ $(h.ip) ($(h.hostname)) ═══")
    push!(lines, "OS: $(h.os_guess) ($(round(h.os_confidence*100, digits=1))%)")
    push!(lines, "Scan time: $(round(h.scan_time, digits=2))s")
    push!(lines, "\nPORT     STATE  SERVICE")
    push!(lines, "─" ^ 55)
    for p in filter(p -> p.state == :open, h.ports)
        push!(lines, format_port_result(p))
    end
    return join(lines, "\n")
end
