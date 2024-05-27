-- Chisel description
description = [[
    This rule is designed to monitor read operations on /proc/net/route and attempts to connect to public IP addresses. 
    Reading /proc/net/route might indicate an attempt to gather network configuration for malicious use, 
    and connection attempts to the same public IP address and port multiple times are indicative of potential C2 communication 
    after suspicious read activity is detected.
]]
short_description = "Detect potential Gafgyt malware activity"
category = "suspicious"

-- Chisel argument list
args = {}

local fevttype, ffilename, faddr, fevtnum
local c2_attempts = {}
local is_read_route = false
local is_trigger = false

-- Initialization callback
function on_init()
    fevttype = chisel.request_field("evt.type")
    ffilename = chisel.request_field("fd.name")
    faddr = chisel.request_field("evt.arg.addr")
    fevtnum = chisel.request_field("evt.num")
    chisel.set_filter("evt.type in (read, connect) and evt.dir=>")
    return true
end

-- Event parsing callback
function on_event()
    local evtype = evt.field(fevttype)
    local filename = evt.field(ffilename)
    local addr = evt.field(faddr)
    local sig_id = nil

    -- Detect reading of /proc/net/route
    if starts_with(evtype, "read") and is_read_route == false and  filename == "/proc/net/route" then
        is_read_route = true
    elseif evtype == "connect" and is_trigger == false and addr and is_public_ip(addr) and is_read_route then
        local ip_port = addr
        c2_attempts[ip_port] = (c2_attempts[ip_port] or 0) + 1

        if c2_attempts[ip_port] > 3 then
            is_trigger = true
            sig_id = "5001" -- Multiple attempts to connect to the same public IP and port after suspicious read
        end
    end

    if sig_id then
        local formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[\"%s\"]}", sig_id, evt.field(fevtnum))
        chisel.set_event_formatter(formatter)
        return true
    end
    return false
end

function starts_with(str, prefix)
	return prefix == "" or str:sub(1, #prefix) == prefix
end

function is_public_ip(addr)
    -- Extract the IP part from "ip:port"
    local ip = addr:match("^(%d+%.%d+%.%d+%.%d+)")
    if not ip then
        return false  -- Return false if the address is not in expected format
    end

    -- Check if the IP is within the private ranges
    if ip:match("^10%.") then
        return false
    elseif ip:match("^172%.(1[6-9]|2[0-9]|3[0-1])%.") then
        return false
    elseif ip:match("^192%.168%.") then
        return false
    end

    return true  -- The IP is public if it doesn't match any private IP ranges
end

