-- Chisel description
description = [[
    This rule is used to detect the behavior of a process reading its own executable file.
]]
short_description = "Read self"
category = "suspicious"

local sig_record = {}  -- Record of processes that have triggered the rule

-- Chisel argument list
args = {}

local ftype, fdir, fexepath, fdname, fpid, fevtnum
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    fdir = chisel.request_field("evt.dir")
    fexepath = chisel.request_field("proc.exe")
    fdname = chisel.request_field("fd.name")
    fpid = chisel.request_field("proc.pid")  -- Requesting process ID
    fevtnum = chisel.request_field("evt.num")  -- Requesting event number
    chisel.set_filter("evt.type in ('read','readv','preadv')")
    return true
end

-- Event parsing callback
function on_event()
    local pid = evt.field(fpid)
    if sig_record[pid] then
        return false  -- Do not trigger the rule if this process has already done so
    end

    local filename = evt.field(fdname)
    local exepath = evt.field(fexepath)

    if filename and exepath == filename then
        sig_record[pid] = true  -- Mark this process as having triggered the rule
        local event_num = evt.field(fevtnum)  -- Retrieve the event number
        local formatter = string.format("{\"sig_id\":\"453\",\"marks\":[%d]}", event_num)
        chisel.set_event_formatter(formatter)
        return true
    end
    return false
end
