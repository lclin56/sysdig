-- Chisel description
description = [[
	This rule is used to format output events. We only output events with the ">" direction, 
	including the fields: pid, process_name, api, args, return_code, and timestamp.
	]]
short_description = "format output events"
category = "INFO"

-- Chisel argument list
args = {}

read_write_list = {
    ["read"] = true,
    ["pread"] = true,
    ["readv"] = true,
    ["preadv"] = true,
    ["write"] = true,
	["pwrite"] = true,
	["writev"] = true,
	["pwritev"] = true
}

local ftype, fdir, argres, argfd
-- initialization callback
function on_init()
	ftype = chisel.request_field("evt.type")
	fdir = chisel.request_field("evt.dir")
	argres = chisel.request_field("evt.res")
	argfd = chisel.request_field("fd.num")
    return true
end

-- Event parsing callback
function on_event()
	-- if evt.field(fdir) == "<" then
	-- 	local formatter
	-- 	local evt_type = evt.field(ftype)
	-- 	if evt.field(argres) then
	-- 		formatter = "{\"pid\":%proc.vpid,\"process_name\":\"%proc.name\",\"api\":\"%evt.type\",\"args\":\"%evt.args\",\"return_code\":\"%evt.arg.res\",\"timestamp\":\"%evt.time\"}"
	-- 	elseif evt.field(argfd) then
	-- 		formatter = "{\"pid\":%proc.vpid,\"process_name\":\"%proc.name\",\"api\":\"%evt.type\",\"args\":\"%evt.args\",\"return_code\":\"%fd.num\",\"timestamp\":\"%evt.time\"}"
	-- 	else
	-- 		formatter = "{\"pid\":%proc.vpid,\"process_name\":\"%proc.name\",\"api\":\"%evt.type\",\"args\":\"%evt.args\",\"return_code\":\"%evt.arg[0]\",\"timestamp\":\"%evt.time\"}"
	-- 	end
	-- 	chisel.set_event_formatter(formatter)
	-- 	return true
	-- end
	return false
end