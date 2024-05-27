-- Chisel description
description = [[
    This script is designed to monitor network activities, focusing on system calls
    related to network connections, data transmission, and other network interactions.
    It aims to identify suspicious activities such as unusual connection patterns, data
    exfiltration attempts, and unauthorized access to network resources.
]]
short_description = "Monitor network activities and identify suspicious behaviors"
category = "security"

-- Chisel argument list
args = {}

local ftype, faddr, fevtnum, ftuple, ffdtype
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    faddr = chisel.request_field("evt.arg.addr")   -- IP and port of a connect call
    fevtnum = chisel.request_field("evt.num")      -- Event number
    ftuple = chisel.request_field("evt.arg.tuple") -- IP and port tuple
    ffdtype = chisel.request_field("fd.type")
    chisel.set_filter("evt.category=net")
    return true
end

local connect_syscall = {
    connect = true,
    sendto = true
}

-- Event parsing callback
function on_event()
    local sig = nil
    local addr = nil
    local evttype = evt.field(ftype)
    if connect_syscall[evttype] then
        sig, addr = handle_network_connect()
    elseif evttype == "bind" then
        sig, addr = handle_network_bind()
    end

    if sig then
        chisel.set_event_formatter(sig)
        return true
    end
    return false
end

local is_957_trigger = false 
local is_959_trigger = false 
local low_count, high_count = 10, 50
local ip_record = {}         -- Record of unique IPs and ports connected
function handle_network_connect()
    local sig = nil
    local addr = nil

    sig, addr = detect_suspicious_connect()
    if sig then
        return sig, addr
    end

    if is_957_trigger and is_958_trigger then
        return sig, addr
    end
    
    addr = evt.field(faddr)

    local evtnum = evt.field(fevtnum)

    -- If addr is nil, try to get it from tuple
    if addr == nil then
        addr = evt.field(ftuple)
        if addr then
            addr = addr:match("->([^:]+:[^ ]+)$") -- Extract destination IP:Port from tuple
        end
        if addr == nil then
            return sig, addr
        end
    end

    -- Split the addr into IP and port
    local ip, port = addr:match("([^:]+):(%d+)")
    if ip == nil or port == nil then
        return sig, addr
    end

    -- Ensure the record for this IP exists
    if not ip_record[ip] and #ip_record < 1000 then
        ip_record[ip] = { ports = {}, evtnums = {} }
    else
        return sig, addr
    end

    -- Add the port to the set of ports and the event number to the list for this IP
    if not ip_record[ip].ports[port] then
        ip_record[ip].ports[port] = true
        table.insert(ip_record[ip].evtnums, evtnum)

        -- Check the number of unique IPs connected
        local ip_count = 0
        for _ in pairs(ip_record) do ip_count = ip_count + 1 end
        if not is_959_trigger then
            local all_evtnums = {}

            for ip, record in pairs(ip_record) do
                if record.evtnums and #record.evtnums > 0 then
                    table.insert(all_evtnums, record.evtnums[1])
                end
            end

            if ip_count == low_count then
                -- Suspicious IP scanning behavior
                sig = string.format("{\"sig_id\":\"958\",\"marks\":[%s]}", table.concat(all_evtnums, ", "))
                return sig, addr
            elseif ip_count == high_count then
                is_959_trigger = true -- Corrected trigger flag for unique IPs
                -- Large-Scale Suspicious IP Scanning Activity
                sig = string.format("{\"sig_id\":\"959\",\"marks\":[%s]}", table.concat(all_evtnums, ", "))
                return sig, addr
            end
        end

        -- Check the number of unique ports connected to for this IP
        local port_count = 0
        for _ in pairs(ip_record[ip].ports) do port_count = port_count + 1 end
        if not is_957_trigger then
            if port_count==low_count then
                -- Suspicious Port scanning behavior
                sig = string.format("{\"sig_id\":\"956\",\"marks\":[%s]}", table.concat(ip_record[ip].evtnums, ", "))
                return sig, addr
            elseif port_count==high_count then
                is_957_trigger = true -- Corrected trigger flag for unique ports on a single IP
                -- Large-Scale Suspicious Port Scanning Activity
                sig = string.format("{\"sig_id\":\"957\",\"marks\":[%s]}", table.concat(ip_record[ip].evtnums, ", "))
                return sig, addr
            end
        end
    end
    return sig, addr
end

local filtered_ips = {
    "10.10.0.*",              -- Example of an IP pattern to exclude from detection
    "8.8.*.*",
    "114.114.*.*",
    "0.0.0.0"
}
local monitored_ip_ports = {} -- Record of monitored IP:Port combinations
local trigger_count = 0
local trigger_max = 50

-- Function to check if an IP is local
function is_local_ip(ip)
    return ip:match("^10%.") or ip:match("^172%.(1[6-9]|2[0-9]|3[0-1])%.") or ip:match("^192%.168%.") or
    ip:match("^127%.")
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

function detect_suspicious_connect()
    if trigger_count > trigger_max then
        return nil, nil
    end

    local addr = evt.field(faddr)
    local evtnum = evt.field(fevtnum)
    local sig = nil

    -- If addr is nil, try to get it from tuple
    if addr == nil then
        addr = evt.field(ftuple)
        if addr == nil then
            return sig, addr
        end
    end

    -- Extract and format destination IP:Port from addr or tuple
    local dest_ip_port = addr:match("->([^:]+:[^ ]+)$") or addr
    if dest_ip_port == nil then
        return sig, addr
    end

    -- Check if the IP:Port is non-local, not filtered, and not already monitored
    local ip = dest_ip_port:match("([^:]+):%d+")
    if ip and not is_local_ip(ip) and not is_filtered_ip(ip) and not monitored_ip_ports[dest_ip_port] then
        monitored_ip_ports[dest_ip_port] = true
        trigger_count = trigger_count + 1
        -- Suspicious network external connection behavior
        sig = string.format("{\"sig_id\":\"951\",\"marks\":[%d]}", evtnum)
        return sig, addr
    end
    return sig, addr
end

function handle_network_bind()
    local addr = evt.field(faddr)
    local evtnum = evt.field(fevtnum)
    local sig_id = "955" --Listens on port
    local type = evt.field(ffdtype)
    if type == "netlink" then
        sig_id = "953" -- Inter-Process Communication
        if addr then
            local pid = string.match(addr, "pid:(%d+)")
            if pid == 0 then
                sig_id = "954" --Kernel mode communication
            end
        end
    end
    local sig = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", sig_id, evtnum)
    return sig, addr
end
                                                                                                                                                                                                                                                                                                                                                                                                                                          
-- function on_capture_end()
--     for ip, info in pairs(ip_record) do
--         local port_count = 0
--         for _ in pairs(info.ports) do
--             port_count = port_count + 1
--         end
--     end
--     ip_record = {}
-- end
