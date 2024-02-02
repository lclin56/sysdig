-- Chisel description
description = [[
    This rule is used to detect the behavior of processes dropping new files in the system, 
    which could indicate malicious activities or unauthorized changes.
]]
short_description = "Dropped new files"
category = "suspicious"

local sig_record = {}

-- Chisel argument list
args = {}

local ftype, fdir, fargname, fargflags, fpid, fevtnum
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    fdir = chisel.request_field("evt.dir")
    fargname = chisel.request_field("evt.arg.name")
    fargflags = chisel.request_field("evt.arg.flags")
    fpid = chisel.request_field("proc.pid")
    fevtnum = chisel.request_field("evt.num")
    chisel.set_filter("evt.dir='<' and evt.type in ('open','openat','openat2')")
    return true
end

-- Event parsing callback
function on_event()
    local pid = evt.field(fpid)
    local filename = evt.field(fargname)
    local flags = evt.field(fargflags)

    if filename and flags then
        local record_key = pid .. ":" .. filename
        if string.find(flags, "O_CREAT") and not sig_record[record_key] then
            sig_record[record_key] = true

            local formatter = string.format("{\"sig_id\":\"452\",\"marks\":[%d]}", evt.field(fevtnum))
            chisel.set_event_formatter(formatter)
            return true
        end
    end
    return false
end
