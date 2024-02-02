-- Chisel description
description = [[
    Detects potential IP and Port scanning behavior by monitoring the number of unique IP connections 
    and unique ports per IP. Triggering when there are more than 10 unique IPs connected or more 
    than 10 unique ports for a single IP, and records the event numbers.
]]
short_description = "Detect IP and Port Scan"
category = "suspicious"

local connect_syscall = {
    ["connect"] = true,
    ["sendto"] = true,
    ["recvfrom"] = true
}

local ip_record = {}  -- Record of unique IPs and ports connected

-- Chisel argument list
args = {}

local is_207_trigger = false  -- Trigger for more than 10 unique IPs
local is_206_trigger = false  -- Trigger for more than 10 unique ports on a single IP

local ftype, faddr, fevtnum
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    faddr = chisel.request_field("evt.arg.addr")  -- IP and port of a connect call
    fevtnum = chisel.request_field("evt.num")  -- Event number
    return true
end

-- Event parsing callback
function on_event()
    if is_206_trigger and is_207_trigger then
        return false  -- Stop checking if both triggers have been activated
    end

    if connect_syscall[evt.field(ftype)] then
        local addr = evt.field(faddr)
        local evtnum = evt.field(fevtnum)

        -- If addr is nil, try to get it from tuple
        if addr == nil then
            addr = evt.field(ftuple)
            if addr then
                addr = addr:match("->([^:]+:[^ ]+)$")  -- Extract destination IP:Port from tuple
            end
            if addr == nil then
                return false
            end
        end

        -- Split the addr into IP and port
        local ip, port = addr:match("([^:]+):(%d+)")
        if ip == nil or port == nil then
            return false
        end

        -- Ensure the record for this IP exists
        if not ip_record[ip] then
            ip_record[ip] = {ports = {}, evtnums = {}}
        end

        -- Add the port to the set of ports and the event number to the list for this IP
        if not ip_record[ip].ports[port] then
            ip_record[ip].ports[port] = true
            table.insert(ip_record[ip].evtnums, evtnum)

            -- Check the number of unique IPs connected
            local ip_count = 0
            for _ in pairs(ip_record) do ip_count = ip_count + 1 end
            if not is_207_trigger and ip_count > 10 then
                is_207_trigger = true  -- Corrected trigger flag for unique IPs
                local formatter = string.format("{\"sig_id\":\"958\",\"marks\":[%s]}", table.concat(ip_record[ip].evtnums, ", "))
                chisel.set_event_formatter(formatter)
                return true
            end

            -- Check the number of unique ports connected to for this IP
            local port_count = 0
            for _ in pairs(ip_record[ip].ports) do port_count = port_count + 1 end
            if not is_206_trigger and port_count > 10 then
                is_206_trigger = true  -- Corrected trigger flag for unique ports on a single IP
                local formatter = string.format("{\"sig_id\":\"957\",\"marks\":[%s]}", table.concat(ip_record[ip].evtnums, ", "))
                chisel.set_event_formatter(formatter)
                return true
            end
        end
    end
    return false
end

function on_capture_end()
    for ip, info in pairs(ip_record) do
        local port_count = 0
        for _ in pairs(info.ports) do
            port_count = port_count + 1
        end

        -- print(string.format("IP: %s, Unique Ports: %d, Event Numbers: [%s]", ip, port_count, table.concat(info.evtnums, ", ")))
    end

    ip_record = {}
end
