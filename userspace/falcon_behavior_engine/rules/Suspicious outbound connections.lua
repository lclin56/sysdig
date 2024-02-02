-- Chisel description
description = [[
    Detects suspicious outbound connections and datagram transmissions to non-local IP addresses,
    excluding specific filtered IPs. Monitors connect, sendto, and recvfrom syscalls. Each unique
    IP:Port combination is only monitored once, with a total monitoring limit.
]]
short_description = "Detect Suspicious Network Activities"
category = "suspicious"

local monitored_syscalls = {
    ["connect"] = true,
    ["sendto"] = true,
    ["recvfrom"] = true
}

local filtered_ips = {
    "10.10.0.*",  -- Example of an IP pattern to exclude from detection
}

local monitored_ip_ports = {}  -- Record of monitored IP:Port combinations
local trigger_count = 0
local trigger_max = 50

-- Function to check if an IP is local
function is_local_ip(ip)
    return ip:match("^10%.") or ip:match("^172%.(1[6-9]|2[0-9]|3[0-1])%.") or ip:match("^192%.168%.") or ip:match("^127%.")
end

-- Function to check if an IP matches any filtered pattern
function is_filtered_ip(ip)
    for _, pattern in ipairs(filtered_ips) do
        local escaped_pattern = pattern:gsub("%.", "%%."):gsub("%*", ".*")
        if ip:match("^" .. escaped_pattern) then
            return true
        end
    end
    return false
end

-- Chisel argument list
args = {}

local ftype, faddr, fevtnum, ftuple
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    faddr = chisel.request_field("evt.arg.addr")  -- IP and port involved in the syscall
    fevtnum = chisel.request_field("evt.num")  -- Event number
    ftuple = chisel.request_field("evt.arg.tuple")  -- IP and port tuple
    return true
end

-- Event parsing callback
function on_event()
    if trigger_count >= trigger_max then
        return false
    end

    if monitored_syscalls[evt.field(ftype)] then
        local addr = evt.field(faddr)
        local evtnum = evt.field(fevtnum)

        -- If addr is nil, try to get it from tuple
        if addr == nil then
            addr = evt.field(ftuple)
            if addr == nil then
                return false
            end
        end

        -- Extract and format destination IP:Port from addr or tuple
        local dest_ip_port = addr:match("->([^:]+:[^ ]+)$") or addr
        if dest_ip_port == nil then
            return false
        end

        -- Check if the IP:Port is non-local, not filtered, and not already monitored
        local ip = dest_ip_port:match("([^:]+):%d+")
        if ip and not is_local_ip(ip) and not is_filtered_ip(ip) and not monitored_ip_ports[dest_ip_port] then
            monitored_ip_ports[dest_ip_port] = true
            trigger_count = trigger_count + 1
            local formatter = string.format("{\"sig_id\":\"951\",\"marks\":[%d]}", evtnum)
            chisel.set_event_formatter(formatter)
            return true
        end
    end
    return false
end
