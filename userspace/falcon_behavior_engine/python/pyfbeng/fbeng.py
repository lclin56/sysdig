import ctypes
from ctypes import c_char_p, c_void_p, c_uint, c_int, c_size_t, c_bool, CFUNCTYPE, POINTER, py_object
import functools
import json
import logging
import os
import re
import threading
# from cuckoo.common.config import config
# from cuckoo.misc import cwd

log = logging.getLogger()

FBE_LOG_DEBUG = 0
FBE_LOG_INFO = 1
FBE_LOG_WARN = 2
FBE_LOG_ERROR = 3
    
def handle_usage(func):
    @functools.wraps(func)
    def wrapper(engine_instance, *args, **kwargs):
        with engine_instance._handle_lock:
            engine_instance._handle_usage_count += 1
        try:
            result = func(engine_instance, *args, **kwargs)
            return result
        finally:
            with engine_instance._handle_lock:
                engine_instance._handle_usage_count -= 1
                if engine_instance._handle_usage_count == 0:
                    engine_instance._handle_usage_cv.notify_all()
    return wrapper

class FBEngine:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(FBEngine, cls).__new__(cls)
        return cls._instance

    def __init__(self, 
                      pattern=None, 
                      patterns_dir=None,
                      temp_dir=None, 
                      token=None, 
                      log_level=FBE_LOG_ERROR, 
                      log_func=None):
        
        if not hasattr(self, 'initialized'):
            self._handle_lock = threading.Lock()
            self._handle_usage_cv = threading.Condition(self._handle_lock)
            self._handle_usage_count = 0
            
            current_dir = os.path.dirname(__file__)
            lib_path = os.path.join(current_dir, "libfbeng.so")
            self.lib = ctypes.CDLL(lib_path)

            self._setup_prototypes()

            self.log_func = self.log_callback
            if log_func:
                self.log_func = log_func
            self.set_log_callback(self.log_func)

            self.log_level = FBE_LOG_ERROR
            if log_level >= FBE_LOG_DEBUG and log_level <= FBE_LOG_ERROR:
                self.log_level = log_level
            self.set_log_level(log_level)

            if temp_dir is None:
                # temp_dir = config("processing:falcon:temp_dir")
                temp_dir = "/tmp/tempfbeng"
            if patterns_dir is None:
                # patterns_dir = config("processing:falcon:patterns_dir")
                patterns_dir = "extern/fbeng/patterns"
            if token is None:
                # token = config("processing:falcon:token")
                token = "FBE:NFJSIKULBIHSL"

            # cwd_dir = cwd(root=True)
            cwd_dir = "/home/activesbox/sandbox/Cuckoo/data"
            if pattern and not pattern.startswith("/"):
                pattern = os.path.join(cwd_dir, pattern)
            if patterns_dir and not patterns_dir.startswith("/"):
                patterns_dir = os.path.join(cwd_dir, patterns_dir)
            if temp_dir and not temp_dir.startswith("/"):
                temp_dir = os.path.join(cwd_dir, temp_dir)
                
            self.pattern_dir = None
            if pattern and os.path.exists(pattern):
                self.pattern_dir = os.path.dirname(pattern)
            elif patterns_dir and os.path.exists(patterns_dir):
                pattern = self.get_latest_pattern(patterns_dir)
                if pattern and os.path.exists(pattern):
                    self.pattern_dir = patterns_dir
            
            if not self.pattern_dir:
                raise Exception("Invalid pattern %s or patterns_dir %s parameter" % (pattern, patterns_dir))
            
            self.temp_dir = temp_dir
            self.token = token
            
            if not pattern or not token or not temp_dir:
                raise Exception("Invalid pattern %s or token %s or temp_dir %s parameter" % (pattern, token, temp_dir))
            
            self.handle = self.lib.fbe_create(pattern.encode('utf-8'), temp_dir.encode('utf-8'), token.encode('utf-8'))

            if not self.handle:
                raise Exception("Failed to create FBE Engine instance")
            
            self.initialized = True

    @staticmethod
    def get_latest_pattern(ptn_dir):
        if not os.path.exists(ptn_dir):
            log.error("Path '%s' does not exist.", ptn_dir)
            return None

        highest_version = -1
        latest_pattern = None

        for filename in os.listdir(ptn_dir):
            match = re.search(r'\.(\d+)$', filename)
            if match:
                version = int(match.group(1))
                if version > highest_version:
                    highest_version = version
                    latest_pattern = filename

        if latest_pattern is None:
            log.debug("No pattern files found.")
        else:
            log.debug("The latest pattern is: %s", latest_pattern)
            latest_pattern = os.path.join(ptn_dir, latest_pattern)

        return latest_pattern

    def _setup_prototypes(self):
        self.FBEReportCallFunc = CFUNCTYPE(None, c_char_p, c_void_p)
        self.LogCxxCallback = CFUNCTYPE(None, c_char_p)

        self.lib.fbe_create.argtypes = [c_char_p, c_char_p, c_char_p]
        self.lib.fbe_create.restype = c_void_p

        self.lib.fbe_drop.argtypes = [c_void_p]
        self.lib.fbe_drop.restype = None

        self.lib.fbe_scan.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_uint, c_size_t, self.FBEReportCallFunc, c_void_p]
        self.lib.fbe_scan.restype = c_int

        self.lib.fbe_rscan.argtypes = [c_void_p, c_char_p, c_char_p, c_bool, c_char_p, c_uint, c_size_t, self.FBEReportCallFunc, c_void_p]
        self.lib.fbe_rscan.restype = c_int

        self.lib.fbe_cal_dynamic_score.argtypes = [c_void_p, c_char_p]
        self.lib.fbe_cal_dynamic_score.restype = c_int

        self.lib.fbe_set_temp_dir.argtypes = [c_void_p, c_char_p]
        self.lib.fbe_set_temp_dir.restype = c_int

        self.lib.fbe_set_log_level.argtypes = [c_int]
        self.lib.fbe_set_log_level.restype = None

        self.lib.fbe_set_log_callback.argtypes = [self.LogCxxCallback]
        self.lib.fbe_set_log_callback.restype = None

        self.lib.get_version.argtypes = []
        self.lib.get_version.restype = c_uint

        self.lib.get_version_str.argtypes = [c_char_p, POINTER(c_uint)]
        self.lib.get_version_str.restype = None

        self.lib.get_pattern_version.argtypes = [c_void_p]
        self.lib.get_pattern_version.restype = c_uint

    @staticmethod
    def report_callback(report, userdata):
        try:
            report_dict = json.loads(ctypes.string_at(report).decode('utf-8'))
            user_dict = ctypes.cast(userdata, POINTER(py_object)).contents.value
            user_dict.update(report_dict)
        except Exception as e:
            log.exception(e)

    @staticmethod
    def log_callback(msg):
        log_str = ctypes.string_at(msg).decode('utf-8')
        log.info(log_str)

    @handle_usage
    def scan(self, 
             scap_file, 
             evt_log_file = "./evt_log.json", 
             filter_string = None, 
             timeout = 180, 
             max_events = 5000000):
        report = {}
        userdata = ctypes.py_object(report)
        userdata_ptr = ctypes.pointer(userdata)
        c_report_callback = self.FBEReportCallFunc(self.report_callback)
        
        if not os.path.exists(scap_file):
            log.error("The scap file %s is not exists!", scap_file)
            return None
        
        s_scap_file = scap_file.encode('utf-8')
        s_evt_log_file = None if not evt_log_file else evt_log_file.encode('utf-8')
        s_filter_string = None if not filter_string else filter_string.encode('utf-8')
        
        result = self.lib.fbe_scan(self.handle,
                                   s_scap_file,
                                   s_evt_log_file,
                                   s_filter_string,
                                   timeout, max_events,
                                   c_report_callback,
                                   ctypes.cast(userdata_ptr, ctypes.c_void_p))
        if result < 0:
            report = None
            
        return report

    @handle_usage
    def rscan(self, 
             scap_file, 
             rule = None, 
             is_file = True,
             filter_string = None, 
             timeout = 180, 
             max_events = 5000000):
        if not rule or (is_file and not os.path.exists(rule)):
            log.error("please input a rule!")
            return None
        
        report = {}
        userdata = ctypes.py_object(report)
        userdata_ptr = ctypes.pointer(userdata)
        c_report_callback = self.FBEReportCallFunc(self.report_callback)
        
        if not os.path.exists(scap_file):
            log.error("The scap file %s is not exists!", scap_file)
            return None
        
        s_scap_file = scap_file.encode('utf-8')
        s_rule = rule.encode('utf-8')
        s_filter_string = None if not filter_string else filter_string.encode('utf-8')
        
        result = self.lib.fbe_rscan(self.handle,
                                   s_scap_file,
                                   s_rule,
                                   is_file,
                                   s_filter_string,
                                   timeout, max_events,
                                   c_report_callback,
                                   ctypes.cast(userdata_ptr, ctypes.c_void_p))
        if result < 0:
            report = None
            
        return report

    @handle_usage
    def calculate_dynamic_score(self, signatures):
        result = self.lib.fbe_cal_dynamic_score(self.handle, signatures.encode('utf-8'))
        return result

    def set_temp_dir(self, dir):
        result = self.lib.fbe_set_temp_dir(self.handle, dir.encode('utf-8'))
        return result

    def set_log_level(self, level):
        self.lib.fbe_set_log_level(level)

    def set_log_callback(self, func):
        c_log_callback = self.LogCxxCallback(func)
        self.lib.fbe_set_log_callback(c_log_callback)

    def get_version(self):
        return self.lib.get_version()

    def get_version_str(self):
        buffer = ctypes.create_string_buffer(64)  
        len = c_uint(64)
        self.lib.get_version_str(buffer, ctypes.byref(len))
        return buffer.value.decode('utf-8')

    def get_pattern_version(self):
        return self.lib.get_pattern_version(self.handle)

    def update(self, 
               pattern=None, 
               temp_dir=None, 
               token=None, 
               log_level=-1, 
               log_func=None):
        
        handle_ = self.handle
        
        pattern_dir_ = self.pattern_dir
        if not pattern:
            pattern = self.get_latest_pattern(pattern_dir_)
            
        if not pattern or not os.path.exists(pattern):
            log.error("Find pattern from default pattern_dir %s failed, or pattern file %s not exists", pattern_dir_, pattern)
            return False
        
        pattern_dir = os.path.dirname(pattern)
    
        log_func_ = self.log_func                
        if log_func and log_func != log_func_:
            self.set_log_callback(log_func)
        else:
            log_func = log_func_

        log_level_ = self.log_level
        if log_level >= FBE_LOG_DEBUG and log_level <= FBE_LOG_ERROR:
            if log_level != log_level_:
                self.set_log_level(log_level)
        else:
            log_level = log_level_
                
        temp_dir_ = self.temp_dir
        if not temp_dir or not os.path.exists(temp_dir):
            temp_dir = temp_dir_

        token_ = self.token
        if not token:
            token = token_
        
        _handle = self.lib.fbe_create(pattern.encode('utf-8'), temp_dir.encode('utf-8'), token.encode('utf-8'))
        if not _handle:
            log.error("Failed to create FBE Engine instance")
            
            if log_func != log_func_:
                self.set_log_callback(log_func_)
                
            if log_level != log_level_:
                self.set_log_level(log_level_)
                
            return False
        
        with self._handle_lock:
            while self._handle_usage_count > 0:
                self._handle_usage_cv.wait()

                self.handle = _handle
        
        if handle_:
            self.lib.fbe_drop(handle_)
 
        self.log_func = log_func
        self.log_level = log_level
        self.temp_dir = temp_dir
        self.pattern_dir = pattern_dir
        self.token = token
        
        log.debug("Update fbeng success!")
        return True
                