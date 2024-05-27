#ifndef I_FB_ENG_H
#define I_FB_ENG_H

// Check if the header file is already included
#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

    // Defines an opaque pointer type to represent an instance of the behavior engine
    typedef void *FBEHandle;

    // Creates an instance of the behavior engine, requiring a pattern, temporary directory, and a token for initialization
    FBEHandle fbe_create(const char *pattern, const char *temp_dir, const char *token);

    // Destroys an instance of the behavior engine, releasing its resources
    void fbe_drop(FBEHandle handle);

    // Callback function type for receiving scan reports
    typedef void (*FBEReportCallFunc)(const char *report, void *userdata);

    // Scans a file, potentially generating a report via the provided callback function
    // The report is related to the scanned content, adhering to specified filters, within a given timeout and event limit
    int fbe_scan(FBEHandle handle, const char *scap_file, const char *evt_log_file, const char *filter_string, unsigned int timeout, size_t max_events, FBEReportCallFunc report_func, void *userdata);
    
    int fbe_rscan(FBEHandle handle, const char *scap_file, const char *rule, bool is_file, const char *filter_string, unsigned int timeout, size_t max_events, FBEReportCallFunc report_func, void *userdata);

    // Calculates a dynamic score based on provided signatures
    int fbe_cal_dynamic_score(FBEHandle handle, const char *signatures);

    // Sets the temporary directory for the behavior engine's use
    int fbe_set_temp_dir(FBEHandle handle, const char *dir);

    // Sets the log level for global
    void fbe_set_log_level(int level);

    // Callback function type for logging
    typedef void (*LogCxxCallback)(const char *log);

    // Sets a logging callback function for global
    void fbe_set_log_callback(LogCxxCallback func);

    // Retrieves the version of the behavior engine
    uint32_t get_version();

    // Retrieves the version of the behavior engine with string
    void get_version_str(char *buffer, uint32_t *len);

    // Retrieves the version of the pattern used by the behavior engine
    uint32_t get_pattern_version(FBEHandle handle);


#ifdef __cplusplus
}
#endif

#define FBE_LOG_LEVEL_DEBUG 0
#define FBE_LOG_LEVEL_INFO 1
#define FBE_LOG_LEVEL_WARN 2
#define FBE_LOG_LEVEL_ERROR 3

#endif // I_FB_ENG_H
