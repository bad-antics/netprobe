using NetProbe

# Quick port scan
println("=== Port Scan ===")
result = scan_ports("scanme.nmap.org", ports=[22,80,443,8080])
println(format_host_result(result))

# DNS lookup
println("\n=== DNS ===")
records = dns_lookup("github.com")
for r in records
    println("  \$(r.record_type): \$(r.value)")
end
