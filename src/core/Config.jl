# NetProbe configuration

mutable struct NetProbeConfig
    timeout::Float64          # Connection timeout (seconds)
    max_concurrent::Int       # Max concurrent connections
    retries::Int              # Retry count for filtered ports
    port_range::UnitRange{Int}
    verbose::Bool
    output_format::Symbol     # :text, :json, :csv
    scan_type::Symbol         # :connect, :syn, :fin
end

const DEFAULT_CONFIG = NetProbeConfig(
    2.0,
    100,
    1,
    1:1024,
    false,
    :text,
    :connect
)

function load_config(path::String="")
    isempty(path) && return deepcopy(DEFAULT_CONFIG)
    cfg = deepcopy(DEFAULT_CONFIG)
    if isfile(path)
        for line in readlines(path)
            k, v = split(strip(line), "=", limit=2)
            k, v = strip(k), strip(v)
            k == "timeout" && (cfg.timeout = parse(Float64, v))
            k == "max_concurrent" && (cfg.max_concurrent = parse(Int, v))
            k == "verbose" && (cfg.verbose = v == "true")
        end
    end
    return cfg
end
