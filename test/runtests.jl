using Test
using NetProbe

@testset "NetProbe Tests" begin
    @testset "Types" begin
        p = PortResult(80, :open, "HTTP", "", "", :tcp, 0.01)
        @test p.port == 80
        @test p.state == :open
    end
    
    @testset "Service Signatures" begin
        @test SERVICE_SIGNATURES[22] == "SSH"
        @test SERVICE_SIGNATURES[80] == "HTTP"
        @test SERVICE_SIGNATURES[443] == "HTTPS"
        @test SERVICE_SIGNATURES[3306] == "MySQL"
        @test length(SERVICE_SIGNATURES) >= 40
    end
    
    @testset "DNS" begin
        results = dns_lookup("localhost")
        @test !isempty(results)
    end
    
    @testset "Config" begin
        cfg = load_config()
        @test cfg.timeout == 2.0
        @test cfg.max_concurrent == 100
    end
end
