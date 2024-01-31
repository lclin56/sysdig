-- Chisel description
description = [[
    {
        "description" : "This rule is used to detect the behavior of a process deleting its own executable file.",
        "001": {"score": 20, "text": "Delete self", "class": "01", "severity": 1} 
    }
]]

short_description = "Delete self"
category = "suspicious"

local unlink_api_list = {
    ["unlink"] = true,
    ["unlinkat"] = true
}

local sig_record = {}

-- Chisel argument list
args = {}

local ftype, fdir, fexepath, fargname, fargpath, fpid
-- initialization callback
function on_init()
    ftype = chisel.request_field("evt.type")
    fdir = chisel.request_field("evt.dir")
    fexepath = chisel.request_field("proc.exepath")
    fargname = chisel.request_field("evt.arg.name")
    fargpath = chisel.request_field("evt.arg.path")
    fpid = chisel.request_field("proc.pid")
    fevtnm = chisel.request_field("evt.num")
    return true
end

-- Event parsing callback
function on_event()
    local pid = evt.field(fpid)
    if sig_record[pid] then
        return false
    end

    if evt.field(fdir) == "<" then
        if unlink_api_list[evt.field(ftype)] then
            local path = evt.field(fargname)
            local exepath = evt.field(fexepath)
            if not path then
                path = evt.field(fargpath)
            end

            if path and exepath == path then
                -- Mark this pid as having triggered the rule
                sig_record[pid] = true

                local formatter = string.format("{\"sig_id\":\"001\",\"marks\":[%d]}", evt.field(fevtnm))
                chisel.set_event_formatter(formatter)
                return true
            end
        end
    end
    return false
end
