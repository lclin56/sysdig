import json
import os
import time
from pyfbeng.fbeng import FBEngine, FBE_LOG_DEBUG
import logging
from multiprocessing import Pool, cpu_count

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

NO_LOG_FILE = -1
CORE_DUMP = -2
SEGMENTATION_DEFAULT = -3
BUS_ERROR = -4
FORMAT_ERROR = -5
REPORT_ERROR = -6
ENV_ERROR = -7
NOT_SUPPORT = -8
NO_PROCESS_LOG = -9
DYNAMIC_LIB_MISSING = -10
UNKNOWN_ERROR = -100 

def get_analysis_dir(base_dir, sha256):
    if not os.path.exists(base_dir):
        return None
    
    for dir in os.listdir(base_dir):
        if dir.startswith(sha256):
            return os.path.join(base_dir, dir)
    
def get_err_code(evt_log):
    code = 0
    if not os.path.exists(evt_log):
        log.error("process_log file not exists")
        code = NO_PROCESS_LOG
        return code
    with open(evt_log, "r") as fd:
        count = 0
        for line in fd:
            if count > 500:
                break
            count += 1
            try:
                event = json.loads(line)
                if "write" in event.get("api", ""):
                    args = event.get("args")
                    args_dict = {}
                    parts = args.split()
                    current_key = None
                    for part in parts:
                        if '=' in part:
                            current_key, value = part.split('=', 1)
                            args_dict[current_key] = value
                        else:
                            if current_key:
                                args_dict[current_key] += ' ' + part
                            else:
                                raise ValueError("Invalid input format")
                            
                    fds = args_dict.get("fd", "")
                    data_s = args_dict.get("data", "")
                    if fds.startswith("1") or fds.startswith("2"):
                        if data_s:
                            if data_s.find('core dumped') >= 0:
                                code = CORE_DUMP
                            if data_s.find('Segmentation fault') >= 0:
                                code = SEGMENTATION_DEFAULT
                            if data_s.find('Exec format error') >= 0:
                                code = FORMAT_ERROR
                            elif data_s.find('Bus error') >= 0:
                                code = BUS_ERROR
                            elif data_s.find('Could not open \'/lib/ld-uClibc.so.0\'') >= 0:
                                code = ENV_ERROR
                            elif data_s.find('requires more than reserved v') >= 0:
                                code = NOT_SUPPORT
                            if data_s.find('error while loading shared libraries') >= 0:
                                code = DYNAMIC_LIB_MISSING
                                
            except Exception as e:
                pass
        
        if count < 10:
            code = NO_PROCESS_LOG
            
    return code
      
def _sig_cup_usage(cpu_usage_file):
    if not os.path.exists(cpu_usage_file):
        log.error("cpu_usage_file %s not exists", cpu_usage_file)
        return None
    
    cpu_usage = 0.0
    with open(cpu_usage_file, "r") as f:
        raw = json.load(f)
        cpu_usage = raw.get("cpu_usage")
    
    # os.remove(cpu_usage_file)

    if cpu_usage < 85:
        return None
    
    sig = {
            "class": "System sensitive operation",
            "classid": "21",
            "markcount": 1,
            "marks": [
                {
                    "logs_index": [],
                    "score": 40,
                    "severity": 2,
                    "sig_id": "2123",
                    "text": "High CPU usage"
                }
            ],
            "severity": 1
            }
    
    return sig

def add_sig_to_sigs(sigs, sig):
    is_added = False
    for s in sigs:
        if s.get("classid") and s.get("classid") == sig.get("classid"):
            s["markcount"] = s["markcount"] + sig["markcount"]
            s["marks"] += sig["marks"]
            is_added = True
            
    if not is_added:
        sigs.append(sig)  

def process_file(args):
    sha256, base_dir, pattern, temp_dir, token = args
    ana_dir = get_analysis_dir(base_dir, sha256)
    if not ana_dir:
        log.error("#%s get analysis dir failed!", sha256)
        return None
    
    logs_dir = os.path.join(ana_dir, "logs")
    scap_file = os.path.join(logs_dir, "sysdig0.scap0")
    cpu_file = os.path.join(logs_dir, "cpu_usage.json")
    log_file = os.path.join(logs_dir, "evt_log.json")
    
    if not os.path.exists(logs_dir) or not os.path.exists(scap_file):
        log.error("#%s scap file is not exists!", sha256)
        return None
    
    log.info("#%s Start Scan... ", sha256)
    engine = FBEngine(pattern, temp_dir, token)
    t_start = time.time()
    report = engine.scan(scap_file, timeout=60, max_events=100000, evt_log_file=log_file)
    err = get_err_code(log_file)
    if err != 0:
        log.error("#%s Analysys failed! err: %d", sha256, err)
        
    cpu_sig = _sig_cup_usage(cpu_file)
    if cpu_sig:
        add_sig_to_sigs(report["signatures"], cpu_sig)
        
    score = engine.calculate_dynamic_score(report)
    
    log.info("#%s Score: %d", sha256, score)
    log.info("#%s Report: %s", sha256, json.dumps(report))
    
    log.info("#%s End Scan... ", sha256)


def main():
    pattern = "/home/activesbox/sysdig/build/userspace/falcon_behavior_engine/fbeptn.100"
    temp_dir = "./tmp"
    token = "FBE:NFJSIKULBIHSL"

    engine = FBEngine(pattern, temp_dir, token)
    version = engine.get_version()
    version_str = engine.get_version_str()
    print("Engine version: %d, Version string: %s" % (version, version_str))

    pattern_version = engine.get_pattern_version()
    print("Pattern version: %d" % pattern_version)

    # scaps_dir = "/tmp/scaps"
    # files = [os.path.join(scaps_dir, f) for f in os.listdir(scaps_dir)]
    
    # files = files[:100]
    
    files = []
    with open("./cl_black.list", 'r') as fp:
        for line in fp:
            files.append(line.strip())

    # 设定进程池中的进程数量，通常为CPU核心数
    pool = Pool(cpu_count())
    pool.map(process_file, [(file, pattern, temp_dir, token) for file in files])
    pool.close()
    pool.join()

if __name__ == "__main__":
    main()
