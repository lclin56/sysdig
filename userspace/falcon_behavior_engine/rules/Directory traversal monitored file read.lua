-- Chisel description
description = [[
    Web applications can be vulnerable to directory traversal attacks that allow accessing files outside of the web app's root directory 
    (e.g. Arbitrary File Read bugs). System directories like /etc are typically accessed via absolute paths. Access patterns outside of this 
    (here path traversal) can be regarded as suspicious. This rule includes failed file open attempts.
]]

short_description = "Detect directory traversal in sensitive file reads"
category = "filesystem"

args = {}

-- Function to check for open read conditions
function open_read(evt_type, is_open_read, fd_typechar, fd_num)
    return (evt_type == "open" or evt_type == "openat" or evt_type == "openat2") and 
           is_open_read and 
           fd_typechar == 'f' and 
           fd_num >= 0
end

-- Function to check for failed file open attempts
function open_file_failed(evt_type, fd_typechar, fd_num, evt_res)
    return (evt_type == "open" or evt_type == "openat" or evt_type == "openat2") and 
           fd_typechar == 'f' and 
           fd_num == -1 and 
           evt_res and string.sub(evt_res, 1, 1) == "E"
end

-- Function to check if access is to the /etc directory
function etc_dir(file_name)
    if not file_name then return false end
    return string.sub(file_name, 1, 5) == "/etc/"
end

-- Function to check for access to user SSH directories
function user_ssh_directory(file_name)
    if not file_name then return false end
    return string.find(file_name, "/.ssh/") and string.match(file_name, "^/home/.*/%.ssh/.*")
end

-- Function to check for directory traversal patterns
function directory_traversal(name_raw)
    return string.find(name_raw, "%.%./") and string.match(name_raw, ".*%..*/.*%..*/.*")
end

local ftype, fname, fnameraw, fnum, fres, fpname, fcmdline, fisopenread, ftypechar, fevtnum
-- Callback function for the initialization phase
function on_init()
    -- Requesting fields necessary for the conditions
    ftype = chisel.request_field("evt.type")
    fname = chisel.request_field("fd.name")
    fnameraw = chisel.request_field("fd.nameraw")
    fnum = chisel.request_field("fd.num")
    fres = chisel.request_field("evt.res")
    fpname = chisel.request_field("proc.pname")
    fcmdline = chisel.request_field("proc.cmdline")
    fisopenread = chisel.request_field("evt.is_open_read")
    ftypechar = chisel.request_field("fd.typechar")
    fevtnum = chisel.request_field("evt.num")

    -- Setting filter for open-related syscalls
    chisel.set_filter("evt.type in ('open','openat','openat2')")

    return true
end

-- Callback function for each event
function on_event()
    local evt_type = evt.field(ftype)
    local file_name = evt.field(fname)
    local name_raw = evt.field(fnameraw)
    local fd_num = evt.field(fnum)
    local evt_res = evt.field(fres)
    local proc_name = evt.field(fpname)
    local cmdline = evt.field(fcmdline)
    local is_open_read = evt.field(fisopenread) == "true"
    local fd_typechar = evt.field(ftypechar)
    local evtnum = evt.field(fevtnum)

    -- Applying conditions from macros as functions
    if (open_read(evt_type, is_open_read, fd_typechar, fd_num) or open_file_failed(evt_type, fd_typechar, fd_num, evt_res)) and
       (etc_dir(file_name) or user_ssh_directory(file_name) or string.sub(file_name, 1, 12) == "/root/.ssh/" or string.find(file_name, "id_rsa")) and
       directory_traversal(name_raw) and not shell_binaries[proc_name] then
        -- Setting event formatter with relevant information
        local formatter = string.format("{\"sig_id\":\"2126\",\"marks\":[%d]}", evtnum)
        chisel.set_event_formatter(formatter)
        return true
    end

    return false
end

-- Optional: Callback function at the end of capture
function on_capture_end()
end
