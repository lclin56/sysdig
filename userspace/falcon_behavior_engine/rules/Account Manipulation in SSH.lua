-- Chisel description
description = [[
    The given Falco rule is designed to detect any attempt to perform account manipulation using SSH.
    The rule is triggered when a process attempts to read or write files that are related to SSH.  
    The "condition" parameter of the rule uses the "open_read" and "open_write" system calls to monitor attempts to read from or write to files respectively.
    The "fd.name" parameter specifies the name of the files that should be monitored, which are related to SSH in this case.
    https://attack.mitre.org/techniques/T1098/
    Mitre Discovery: Account Manipulation subscenario
]]
short_description = "An attempt to do account manipulation using ssh"
category = "suspicious"

args = {}

ssh_file_list = {
    ["/etc/ssh/sshd_config"] = true, 
    ["/.ssh/authorized_keys"] = true
}

-- Table to keep track of files that have already triggered an alert
triggered_files = {}

local ftype, fname, fpid, fevtnum
-- Callback function for the initialization phase
function on_init()
    -- Requesting fields necessary for monitoring file operations
    ftype = chisel.request_field("evt.type")
    fname = chisel.request_field("fd.name")
    fpid = chisel.request_field("proc.pid")
    fevtnum = chisel.request_field("evt.num")

    -- Setting filter for open_read and open_write syscalls
    chisel.set_filter("evt.type=open or evt.type=openat")

    return true
end

-- Function to check if the file path matches one of the specified SSH files
function is_ssh_file(file_name)
    -- Direct match for specific files
    if ssh_file_list[file_name] then
        return true
    end

    -- Pattern match for authorized_keys in any user's .ssh directory
    if string.match(file_name, ".*/.ssh/authorized_keys") then
        return true
    end

    return false
end

-- Callback function for each event
function on_event()
    local evt_type = evt.field(ftype)
    local file_name = evt.field(fname)
    local pid = evt.field(fpid)
    local evtnum = evt.field(fevtnum)

    -- Check if the event is related to SSH files and syscalls using fuzzy matching
    -- And ensure the file has not already triggered an alert
    if is_ssh_file(file_name) and (evt_type == "open" or evt_type == "openat") and not triggered_files[file_name] then
        -- Reading the flags used in the open/openat syscall to determine read or write attempt
        local flags = evt.field("evt.arg.flags")
        
        -- Check for read or write flags in the open/openat syscall
        if string.find(flags, "O_RDONLY") or string.find(flags, "O_RDWR") or string.find(flags, "O_WRONLY") or string.find(flags, "O_CREAT") then
            -- Mark the file as having triggered an alert
            triggered_files[file_name] = true

            -- Alert message for detected account manipulation attempt
            local formatter = string.format("{\"sig_id\":\"2124\",\"marks\":[%d]}", evtnum)
            chisel.set_event_formatter(formatter)
            return true
        end
    end

    return false
end

-- Optional: Callback function at the end of capture
function on_capture_end()
end
