#ifndef LOGGER_H

#include <functional>
#include <string>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3

#define LOG_MODE_PRINT 1
#define LOG_MODE_WRITE_TO_FILE 2
#define LOG_MODE_CALLBACK 3

typedef void (*LogCxxCallback)(const char *log);

class LogCxx
{
public:
    LogCxx();
    void setMode(int newMode);
    void setLevel(int newLevel);
    void setCallback(LogCxxCallback newCallback);
    void setLogFile(const std::string &newPath, size_t newSize, int newCount);
    void setTimeFlag(bool flag);
    void log(int msgLevel, const char *file, int line, const char *func, const char *format, va_list args);

private:
    int mode;
    int level;
    std::string logFilePath;
    size_t maxFileSize;
    int maxFileCount;
    LogCxxCallback logCallback;
    bool time_flag;
    void rotateLogFile();
    std::string get_time();
};

#ifdef __cplusplus
extern "C"
{
#endif

    void *logcxx_create();
    void logcxx_destroy(void *logger);
    void logcxx_set_mode(void *logger, int mode);
    void logcxx_set_level(void *logger, int level);
    void logcxx_set_callback(void *logger, LogCxxCallback callback);
    void logcxx_set_log_file(void *logger, const char *path, size_t size, int count);
    void logcxx_set_time_flag(void *logger, bool flag);
    void logcxx_log(void *logger, int level, const char *file, int line, const char *func, const char *format, ...);

#ifdef __cplusplus
}
#endif

#define LOG_DEBUG(logger, format, ...) logcxx_log(logger, LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_INFO(logger, format, ...) logcxx_log(logger, LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_WARN(logger, format, ...) logcxx_log(logger, LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_ERROR(logger, format, ...) logcxx_log(logger, LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_CREATE() logcxx_create()
#define LOG_DESTROY(logger) logcxx_destroy(logger)
#define LOG_SET_MODE(logger, mode) logcxx_set_mode(logger, mode)
#define LOG_SET_LEVEL(logger, level) logcxx_set_level(logger, level)
#define LOG_SET_CALLBACK(logger, callback) logcxx_set_callback(logger, callback)
#define LOG_SET_FILE(logger, path, size, count) logcxx_set_log_file(logger, path, size, count)
#define LOG_SET_TIME_FLAG(logger, flag) logcxx_set_time_flag(logger, flag)

#endif // LOGGER_H
