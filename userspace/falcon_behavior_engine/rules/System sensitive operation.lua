-- Chisel description
description = [[
    This rule is designed to monitor specific system calls such as getrlimit, sysinfo, and getrandom, 
    which are often invoked by processes to query system resource limits, system information, and generate 
    random numbers, respectively. While these calls can be used for legitimate purposes, their usage might 
    also indicate reconnaissance activities by unauthorized or malicious software attempting to understand 
    the environment it is running in or gather information for further exploitation.
]]
short_description = "Detect potential reconnaissance activities via system calls"
category = "suspicious"

-- Chisel argument list
args = {}

local fevtnum, fevttype, foption
-- initialization callback
function on_init()
    fevtnum = chisel.request_field("evt.num")
    fevttype = chisel.request_field("evt.type")
    foption = chisel.request_field("evt.arg.option")
    chisel.set_filter("evt.type in (getrlimit, sysinfo, getrandom, prctl) and evt.dir=<")
    return true
end

-- Event parsing callback
function on_event()
    evtype = evt.field(fevttype)
    sig_id = nil
    if evtype == "getrlimit" then
        sig_id = "2101" -- Obtain the limits of system resources
    elseif evtype == "sysinfo" then
        sig_id = "2102" -- Obtaining system information
    elseif evtype == "getrandom" then
        sig_id = "2103" -- Potential generation of encryption seeds
    elseif evtype == "prctl" then
        local option = evt.field(foption)
        if option and string.find(option, "PR_SET_NAME") ~= nil then
            -- Change process name
            sig_id = "841"
        end
    end

    if sig_id then
        local formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", sig_id, evt.field(fevtnum))
        chisel.set_event_formatter(formatter)
        return true
    end
    return false
end
