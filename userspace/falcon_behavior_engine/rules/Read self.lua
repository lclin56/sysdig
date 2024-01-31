-- Chisel description
description = [[
    This rule is used to detect the behavior of a process reading its own executable file.
]]
short_description = "Read self"
category = "suspicious"

local read_api_list = {
    ["read"] = true,
    ["pread"] = true,
    ["fread"] = true
}

local sig_record = {}  -- Record of processes that have triggered the rule

-- Chisel argument list
args = {}

local ftype, fdir, fexepath, fdname, fpid, fevtnum
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    fdir = chisel.request_field("evt.dir")
    fexepath = chisel.request_field("proc.exepath")
    fdname = chisel.request_field("fd.name")
    fpid = chisel.request_field("proc.pid")  -- Requesting process ID
    fevtnum = chisel.request_field("evt.num")  -- Requesting event number
    return true
end

-- Event parsing callback
function on_event()
    local pid = evt.field(fpid)
    if sig_record[pid] then
        return false  -- Do not trigger the rule if this process has already done so
    end

    if evt.field(fdir) == "<" and read_api_list[evt.field(ftype)] then
        local filename = evt.field(fdname)
        local exepath = evt.field(fexepath)

        if filename and exepath == filename then
            sig_record[pid] = true  -- Mark this process as having triggered the rule
            local event_num = evt.field(fevtnum)  -- Retrieve the event number
            local formatter = string.format("{\"sig_id\":\"003\",\"marks\":[%d]}", event_num)
            chisel.set_event_formatter(formatter)
            return true
        end
    end
    return false
end
