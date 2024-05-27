#include "fbeng.h"
#include "ifbeng.h"
#include <string>
#include <cstring>

static int log_level = FBE_LOG_LEVEL_INFO;
static LogCxxCallback log_callback = nullptr;

FBEHandle fbe_create(const char *pattern, const char *temp_dir, const char *token)
{
    // Convert C strings to std::string and create an instance of FBEngine
    FBConf conf = {
        .pattern_path = pattern,
        .temp_dir = temp_dir,
        .token = token,
        .log_level = log_level,
        .log_callback = (void *)log_callback};
    FBEngine *engine = new FBEngine();

    if (engine->init(conf) < 0)
    {
        delete engine;
        return nullptr;
    }

    return static_cast<FBEHandle>(engine);
}

void fbe_drop(FBEHandle handle)
{
    if (!handle)
    {
        return;
    }

    // Cast the handle back to FBEngine* and delete it
    FBEngine *engine = static_cast<FBEngine *>(handle);
    delete engine;
}

int fbe_scan(FBEHandle handle, const char *scap_file, const char *evt_log_file, const char *filter_string, unsigned int timeout, size_t max_events, FBEReportCallFunc report_func, void *userdata)
{
    if (!handle)
    {
        return -1;
    }

    FBEngine *engine = static_cast<FBEngine *>(handle);

    std::string s_scap_file = scap_file ? scap_file : "";
    std::string s_evt_log_file = evt_log_file ? evt_log_file : "";
    std::string s_filter_string = filter_string ? filter_string : "";

    // Call the scan method and capture the result
    std::string result = engine->scan(s_scap_file, s_evt_log_file, s_filter_string, timeout, max_events);
    // Convert the result to a C-style string
    char *c_result = strdup(result.c_str());
    // If a report callback is provided, call it
    if (report_func && !result.empty())
    {
        report_func(c_result, userdata);
    }
    // Return the result (note: the caller is responsible for freeing this memory)
    return 0;
}

int fbe_rscan(FBEHandle handle, const char *scap_file, const char *rule, bool is_file, const char *filter_string, unsigned int timeout, size_t max_events, FBEReportCallFunc report_func, void *userdata)
{
    if (!handle)
    {
        return -1;
    }

    FBEngine *engine = static_cast<FBEngine *>(handle);

    std::string s_scap_file = scap_file ? scap_file : "";
    std::string s_rule = rule ? rule : "";
    std::string s_filter_string = filter_string ? filter_string : "";

    // Call the scan method and capture the result
    std::string result = engine->rscan(s_scap_file, s_rule, is_file,  s_filter_string, timeout, max_events);
    // Convert the result to a C-style string
    char *c_result = strdup(result.c_str());
    // If a report callback is provided, call it
    if (report_func && !result.empty())
    {
        report_func(c_result, userdata);
    }
    // Return the result (note: the caller is responsible for freeing this memory)
    return 0;
}

int fbe_cal_dynamic_score(FBEHandle handle, const char *signatures)
{
    if (!handle)
    {
        return -1;
    }

    FBEngine *engine = static_cast<FBEngine *>(handle);
    return engine->cal_dynamic_score(signatures);
}

int fbe_set_temp_dir(FBEHandle handle, const char *dir)
{
    if (!handle)
    {
        return -1;
    }

    FBEngine *engine = static_cast<FBEngine *>(handle);
    return engine->set_temp_dir(dir);
}

void fbe_set_log_level(int level)
{
    log_level = level;
}

void fbe_set_log_callback(LogCxxCallback func)
{
    log_callback = func;
}

uint32_t get_version()
{
    return FBEngine::get_version();
}

void get_version_str(char *buffer, uint32_t *len)
{
    std::string version_s = FBEngine::get_version_str();

    uint32_t copy_len = std::min(*len - 1, static_cast<uint32_t>(version_s.length()));

    strncpy(buffer, version_s.c_str(), copy_len);

    buffer[copy_len] = '\0';

    *len = copy_len;
}

uint32_t get_pattern_version(FBEHandle handle)
{
    if (!handle)
    {
        return -1;
    }

    FBEngine *engine = static_cast<FBEngine *>(handle);
    return engine->get_pattern_version();
}