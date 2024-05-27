-- Chisel description
description = [[
    This chisel script is engineered to scrutinize system calls that pertain to file operations 
    across various critical areas of the system such as temporary directories, system libraries, 
    and more. It focuses on abstracting the interactions with 'objects' like file paths, and 
    meticulously applies tailored handling based on the nature of the operation—be it opening, 
    reading, writing, or executing files—and the specific attributes of the objects involved. 
    By doing so, it aims to offer insights into potentially suspicious activities that could indicate 
    unauthorized access or modifications, thereby serving as a tool for system security and integrity 
    monitoring.
]]
short_description = "Enhanced monitoring of file-related system calls in critical system areas with object-centric analysis."
category = "suspicious"

-- Chisel argument list
args = {}

function starts_with(str, prefix)
	return prefix == "" or str:sub(1, #prefix) == prefix
end

function ends_with(str, suffix)
	return suffix == "" or str:sub(-#suffix) == suffix
end


local fop, fpid, ffdname, fargname, fargpath, fevtnum, fevtdir, fflags, fprocexe, fprocname, fcmdline, fargargs, foldpath, fnewpath, ftarget, flinkpath, ffilename, fdir
-- initialization callback
function on_init()
    fop = chisel.request_field("evt.type")
    fpid = chisel.request_field("proc.pid")
    ffdname = chisel.request_field("fd.name")
    fargname = chisel.request_field("evt.arg.name")
    fargpath = chisel.request_field("evt.arg.path")
    fevtnum = chisel.request_field("evt.num")
    fevtdir = chisel.request_field("evt.dir")
    fflags = chisel.request_field("evt.arg.flags")
    fprocexe = chisel.request_field("proc.exe")
    fprocname = chisel.request_field("proc.name")
    fcmdline = chisel.request_field("proc.cmdline")
    fargargs = chisel.request_field("evt.arg.args")
    foldpath = chisel.request_field("evt.arg.oldpath")
    fnewpath = chisel.request_field("evt.arg.newpath")
    flinkpath = chisel.request_field("evt.arg.linkpath")
    ftarget = chisel.request_field("evt.arg.target")
    ffilename = chisel.request_field("evt.arg.filename")
    fexeline = chisel.request_field("proc.exeline")
    fdir = chisel.request_field("evt.arg.dir")
    chisel.set_filter("evt.category in (file, memory) or evt.type in (execve, execveat)")
    return true
end


local open_operations = {
    open = true,
    openat = true,
    openat2 = true,
    create = true,
    mkdir = true,
    mkdirat = true
}

local read_operations = {
    read = true,
    pread = true,
    preadv = true,
    preadv2 = true,
}

local write_operations = {
    write = true,
    pwrite = true,
    pwritev = true,
    pwritev2 = true
}

local control_operations = {
    fcntl = true,
    ioctl = true,
    dup = true,
    dup2 = true,
    dup3 = true,
    flock = true
}

local mmap_operations = {
    mmap = true,
    mmap2 = true,
    munmap = true
}

local exec_operations = {
    execve = true,
    execveat = true
}

local access_operations = {
    access = true,
    faccessat = true,
    faccessat2 = true,
    stat = true,
    fstat = true,
    lstat = true,
    stat64 = true,
    fstat64 = true,
    lstat64 = true
}

local permission_operations = {
    chmod = true,
    fchmod = true,
    fchmodat = true,
    fchmodat2 = true,
    chown = true,
    lchown = true,
    fchown = true,
    fchownat = true
}

local rename_operations = {
    rename = true,
    renameat = true,
    renameat2 = true
}

local link_operations = {
    link = true,
    linkat = true,
    symlink = true,
    symlinkat = true
}

local delete_operations = {
    unlink = true,
    unlinkat = true,
    rmdir = true
}

local change_dir_operations = {
    chdir = true,
    fchdir = true
}

local file_system_operations = {
    mount = true,
    umount = true,
    sync = true,
    fsync = true,
    fdatasync = true,
    chroot = true
}

local sensitive_path_record = {}

-- Event parsing callback
function on_event()
    local operation = evt.field(fop)

    local sig = nil
    local path = nil
    local path_ = nil
    if open_operations[operation] then
        sig,path,path_,_ = handle_file_open()
    elseif read_operations[operation] then
        sig,path,path_,_ = handle_file_read()
    elseif write_operations[operation] then
        sig,path,path_,_ = handle_file_write()
    elseif exec_operations[operation] then
        sig,path,path_,_ = handle_file_execve()
    elseif link_operations[operation] then
        sig,path,path_,_ = handle_file_link()
    elseif permission_operations[operation] then
        sig,path,path_,_ = handle_file_permission()
    elseif delete_operations[operation] then
        sig,path,path_,_ = handle_file_unlink()
    elseif control_operations[operation] then
        sig,path,path_,_ = handle_file_control()
    elseif mmap_operations[operation] then
        sig,path,path_,_ = handle_file_mmap()
    elseif access_operations[operation] then
        sig,path,path_,_ = handle_file_access()
    elseif rename_operations[operation] then
        sig,path,path_,_ = handle_file_rename()
    elseif change_dir_operations[operation] then
        sig,path,path_,_ = handle_file_change_dir()
    elseif file_system_operations[operation] then
        sig,path,path_,_ = handle_file_system()
    end

    if sig then
        chisel.set_event_formatter(sig)
        return true
    elseif path then
        local sig_id = nil
        if starts_with(path, "/tmp") then
            sig_id = "2112" -- Operate Temporary Directory
        elseif starts_with(path, "/proc/") then
            sig_id = pattern_proc_scan(path)
        elseif starts_with(path, "/etc/systemd/system/") then
            sig_id = "2113" -- Operating System Services Directory
        elseif starts_with(path, "/lib/modules/") then
            if not access_operations[operation] then
                sig_id = "2114" -- Modify or REL kernel object
            end
        elseif starts_with(path, "/var/log") or starts_with(path, "/var/crash") then
           sig_id = "842" -- Operate Special Log Directory
        elseif starts_with(path, "/proc/mounts") or starts_with(path, "/sys/devices/system/node") then
            sig_id = "2120" -- Access system mount information.
        elseif is_sensitive_path(path) then
            local key = operation .. path
            if not sensitive_path_record[key] then
                sensitive_path_record[key] = true
                sig_id = "2126" -- Detect directory traversal in sensitive file reads
            end
        end

        if sig_id then
            sig = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", sig_id, evt.field(fevtnum))           
            chisel.set_event_formatter(sig)
            return true
        end
    end
    return false
end

local open_sig_record = {}
-- Handler function for 'open' operations
function handle_file_open()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end
    local evt_type = evt.field(fop)
    local path = nil
    local formatter = nil
    if starts_with(evt_type, "mkdir") then
        path = evt.field(fargpath)
    else
        path = evt.field(fargname)
        flags = evt.field(fflags)
        if path and flags then
            local pid = evt.field(fpid)
            local record_key = pid .. ":" .. path
            if string.find(flags, "O_CREAT") and not open_sig_record[record_key] then
                open_sig_record[record_key] = true
                -- Dropped new files
                formatter = string.format("{\"sig_id\":\"452\",\"marks\":[%d]}", evt.field(fevtnum))
            end
        end
    end
    return formatter, path, nil, nil
end

local read_sig_record = {}
-- Handler function for 'read' operations
function handle_file_read()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local path = nil
    local formatter = nil
    path = evt.field(ffdname)
    local procname = evt.field(fprocexe)

    if starts_with(procname, "/usr/bin/qemu-") then
        procname = evt.field(fprocname)
    end

    if path then
        local pid = evt.field(fpid)
        local record_key = pid .. ":" .. path
        if not read_sig_record[record_key] then
            if path == procname or ends_with(path, procname) then
                -- Read self
                formatter = string.format("{\"sig_id\":\"453\",\"marks\":[%d]}", evt.field(fevtnum))
            elseif starts_with(path, "/etc/passwd") or starts_with(path, "/etc/shadow") then
                -- View configuration and password
                formatter = string.format("{\"sig_id\":\"2109\",\"marks\":[%d]}", evt.field(fevtnum))
            elseif path == "/proc/cpuinfo" or string.find(path, "/sys/devices/system/cpu") or string.find(path, "/sys/devices/virtual/dmi")then
                -- Attempts to detect sandbox information
                formatter = string.format("{\"sig_id\":\"173\",\"marks\":[%d]}", evt.field(fevtnum))
            elseif path == "/proc/net/route" then
                -- Potential reconnaissance of network routing information
                formatter = string.format("{\"sig_id\":\"969\",\"marks\":[%d]}", evt.field(fevtnum))
            elseif path == "/proc/sys/vm/mmap_min_addr" then
                formatter = string.format("{\"sig_id\":\"2101\",\"marks\":[%d]}", evt.field(fevtnum))
            elseif path == "/dev/urandom" then
                -- Potential generation of encryption seeds
                formatter = string.format("{\"sig_id\":\"2103\",\"marks\":[%d]}", evt.field(fevtnum))
            end
            read_sig_record[record_key] = true
        end
    end
    return formatter, path, nil, nil
end

local WRITE_PREFIX_MAPPING = {
    -- Add scheduled tasks to achieve auto-startup
    ["/etc/init.d/"] = "261",
    ["/etc/cron"] = "261",
    ["/etc/rc.local"] = "261",
    ["/etc/rc.d/rc.local"] = "261",
    ["/var/spool/at"] = "261",
    ["/etc/at.allow"] = "261",
    ["/etc/at.deny"] = "261",
    -- Modify system library files
    ["/lib"] = "2111",
    ["/usr/lib"] = "2111",
    ["/usr/local/lib"] = "2111",
    -- Write executable files
    ["/bin/"] = "2110",
    ["/sbin/"] = "2110",
    ["/usr/sbin/"] = "2110",
    ["/usr/bin/"] = "2110",
    ["/usr/local/bin"] = "2110",
    ["/usr/local/sbin"] = "2110",
    -- Injects shared library
    ["/etc/ld.so.conf"] = "2116",
    ["/etc/ld.so.preload"] = "2116",
}

function pattern_dir_scan(file_path)
    for prefix, prefix_sig_id in pairs(WRITE_PREFIX_MAPPING) do
        if string.sub(file_path, 1, string.len(prefix)) == prefix then
            return prefix_sig_id
        end
    end
    return nil
end

function pattern_virt(exe, args)
    if string.match(exe, ".+/systemd%-detect%-virt$") then
        return true
    end

    if args and string.match(exe, ".+/grep$") then
        local args_patterns = { "Oracle", "VirtualBox", "VMWare", "Parallels", "vbox", "virtual", "vmxnet", "virtio_net",
            "hv_vmbus", "hv_netvsc" }
        for _, pattern in ipairs(args_patterns) do
            if string.find(string.lower(args), string.lower(pattern)) then
                return true
            end
        end
    end

    return false
end

local first_execve_evt = nil
function handle_file_execve()
    local dir = evt.field(fevtdir)
    local formatter = nil
    local sig_id = nil
    local args = evt.field(fargargs)
    if dir == ">" then
        local path = evt.field(ffilename)
        if path then
            if starts_with(path, "/tmp/") then
                sig_id = "2106" -- The sample self-starts via Shell
            elseif pattern_virt(path, args) then
                sig_id = "172" -- Detect virtualization environment
            end
            
            if sig_id then
                formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", sig_id, evt.field(fevtnum))
                return formatter, path, nil, nil
            end
        end
        return nil, nil, nil, nil
    end
    
    local cmdline = evt.field(fcmdline)

    if not first_execve_evt then
        first_execve_evt = true
        return nil, nil, nil, nil
    end

    sig_id = "2107" -- Start shell command

    if string.find(args, "LD_PRELOAD") ~= nil then
        sig_id = "2115" -- Attempts to detect preload so information
    elseif cmdline and (cmdline:find("curl%s") or cmdline:find("wget%s")) and (cmdline:find("http://") or cmdline:find("https://")) then
        -- Check if the command line contains typical download commands and patterns
        sig_id = "2105" -- Start the shell command to perform remote download
    end

    -- if evt.field(fprocname) == "sed" then
    --     print(cmdline)
    --     sig_id = pattern_dir_scan(cmdline)
    -- end

    formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", sig_id, evt.field(fevtnum))
    return formatter, nil, nil, nil
end

function handle_file_unlink()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local sig_id = nil
    local path = evt.field(fargpath)
    if path == nil then
        path = evt.field(fargname)
    end

    if path then
        local procexe = evt.field(fprocexe)
        if path == procexe then
            sig_id = "451"  -- Delete self
        elseif ends_with(path, ".vi324.tmp") then
            sig_id = "2119" -- Remove known family-infected files
        else
            sig_id = "2104" -- Using unlink delete files
        end
    end

    if sig_id then
        formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", sig_id, evt.field(fevtnum))
    end
    return formatter, path, nil, nil
end

function pattern_ko(args_list)
    local ko_pattern = "%.ko$"
    for _, link_args in ipairs(args_list) do
        if string.match(link_args, ko_pattern) then
            return true
        end
    end
    return false
end

function handle_file_link()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(fnewpath)
    if path == nil then
        path = evt.field(ftarget)
        if path == nil then
            return formatter, path, nil, nil
        end
    end
    local path_ = evt.field(foldpath)
    if path_ == nil then
        path_ = evt.field(flinkpath)
    end

    local args_list = { path, path_ }
    if pattern_ko(args_list) then
        -- Modify or REL kernel object
        formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", "2114", evt.field(fevtnum))
    end
    return formatter, path, path_, nil
end

local account_files = {
    ["/etc/login.defs"] = true,
    ["/etc/securetty"] = true,
    ["/var/log/faillog"] = true,
    ["/var/log/lastlog"] = true,
    ["/var/log/tallylog"] = true,
    ["/var/log/secure"] = true,
}

function pattern_ssh(file_path)
    local patterns = {
        ".+id_rsa$",
        ".+authorized_keys$",
        "^/etc/ssh/sshd_config$"
    }

    for _, pattern in ipairs(patterns) do
        if string.match(file_path, pattern) then
            return true
        end
    end

    return false
end

function pattern_shell_config(file_path)
    local patterns = {
        "^/etc/profile/",
        "^/etc/profile%.d/",
        ".+%.bash_profile$",
        ".+%.bash_login$",
        ".+%.profile$",
        ".+%.bashrc$",
        ".+%.bash_logout$"
    }

    for _, pattern in ipairs(patterns) do
        if string.match(file_path, pattern) then
            return true
        end
    end

    return false
end

local write_sig_record = {}
function handle_file_write()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local sig = nil
    local path = evt.field(ffdname)
    if path then
        local pid = evt.field(fpid)
        local record_key = pid .. ":" .. path
        if write_sig_record[record_key] then
            return formatter, path, nil, nil
        end

        local args_list = { path }
        if pattern_ko(args_list) then
            sig = "2114" -- Modify or REL kernel object
        elseif account_files[path] then
            sig = "2121" -- Account information related files were modified
        elseif pattern_ssh(path) then
            sig = "2109" -- View configuration and password
        elseif pattern_shell_config(path) then
            sig = "2122" -- Unix shell configuration modification
        else
            sig = pattern_dir_scan(path)
        end

        if sig then
            formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", sig, evt.field(fevtnum))
        end
        write_sig_record[record_key] = true
    end
    return formatter, path, nil, nil
end

function handle_file_permission()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(ffilename)
    if path == nil then
        path = evt.field(ffdname)
    end

    if path then
        -- Modify file permissions
        formatter = string.format("{\"sig_id\":\"%s\",\"marks\":[%d]}", "2108", evt.field(fevtnum))
    end

    return formatter, path, nil, nil
end

function handle_file_control()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(ffdname)

    return formatter, path, nil, nil
end

function handle_file_mmap()
    local dir = evt.field(fevtdir)
    if dir == "<" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(ffdname)

    return formatter, path, nil, nil
end

function handle_file_access()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(fargname)
    if path == nil then
        path = evt.field(fargpath)
        if path == nil then
            path = evt.field(ffdname)
        end
    end

    return formatter, path, nil, nil
end

function handle_file_rename()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(fnewpath)
    local path_ = evt.field(foldpath)

    return formatter, path, path_, nil
end

function handle_file_change_dir()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(fargpath)
    if path == nil then
        path = evt.field(ffdname)
    end
    return formatter, path, nil, nil
end

function handle_file_system()
    local dir = evt.field(fevtdir)
    if dir == ">" then
        return nil, nil, nil, nil
    end

    local formatter = nil
    local path = evt.field(fdir)
    if path == nil then
        path = evt.field(fargname)
        if path == nil then
            path = evt.field(fargpath)
        end
    end
    return formatter, path, nil, nil
end

local proc_list = {}
local high_count, low_count = 20, 10

function pattern_proc_scan(file_path)
    local match = string.match(file_path, "^/proc/(%d+/.*)")
    if #proc_list > high_count then
        return nil
    end
    if match then
        if proc_list[match] == nil then
            proc_list[match] = true
            if #proc_list == low_count then
                -- Local process scanning
                return "2117"
            elseif #proc_list == high_count then
                -- Bulk Scanning of Local Processes
                return "2118"
            end
        end
    end
    return nil
end

local sensitive_path_pattern = {
    "/home/.sec/*",
    "/home/tools*",
    "/home/yyu*",
    "/home/*/access_logs.txt",
    "/home/*/apt_tool",
    "/home/*/bitcoin_wallet.dat",
    "/home/*/database_dump.sql",
    "/home/*/family_photo.jpg",
    "/home/*/passwords.docx",
    "/home/*/passwords.txt",
    "/home/*/project.tar.gz",
    "/home/*/source_code.zip"
}

function is_sensitive_path(path)
    if not path then
        return false
    end
    for _, pattern in ipairs(sensitive_path_pattern) do
        local escaped_pattern = pattern:gsub("%.", "%%."):gsub("%*", ".*")
        if path:match("^" .. escaped_pattern) then
            return true
        end
    end
    return false
end