-- Chisel description
description = "suspicious connect"
short_description = "connect"
category = "misc"

-- Chisel argument list
args = {}

-- initialization callback
function on_init()
    chisel.set_event_formatter("")
	ftype = chisel.request_field("evt.type")
	fdir = chisel.request_field("evt.dir")
	fdname = chisel.request_field("fd.name")
    return true
end

-- Event parsing callback
function on_event()
	if evt.field(ftype) == "connect" and evt.field(fdir) == "<" then
        chisel.set_event_formatter("%evt.num %proc.vpid %proc.name %evt.type(%evt.args)")
		return true
	end
    return false
end