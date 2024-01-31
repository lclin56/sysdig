-- Chisel description
description = [[
    This rule is used to detect the use of the getrlimit system call by processes to obtain the limits of system resources. 
    This might be used for benign purposes, but can also indicate reconnaissance activities by malicious software.
]]
short_description = "Obtain system resource limits"
category = "suspicious"

local syscalls = {
    ["getrlimit"] = true
}

local class = "02"
local score = 5
local severity = 1

-- Chisel argument list
args = {}

local ftype, fdir, fevtnum
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    fdir = chisel.request_field("evt.dir")
    fevtnum = chisel.request_field("evt.num")
    return true
end

-- Event parsing callback
function on_event()
    if evt.field(ftype) == "getrlimit" and evt.field(fdir) == "<" then
        local formatter = string.format("{\"sig_id\":\"100\",\"marks\":[%d]}", fevtnum)
        chisel.set_event_formatter(formatter)
        return true
    end
    return false
end
