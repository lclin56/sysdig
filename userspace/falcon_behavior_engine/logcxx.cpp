#include "logcxx.h"
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <chrono>
#include <sstream>

LogCxx::LogCxx() : mode(LOG_MODE_PRINT), level(LOG_LEVEL_DEBUG), maxFileSize(10 * 1024 * 1024), maxFileCount(5), logCallback(nullptr), time_flag(false) {}

void LogCxx::setMode(int newMode)
{
    if (newMode >= LOG_MODE_PRINT && newMode <= LOG_MODE_WRITE_TO_FILE)
    {
        mode = newMode;
    }
}

void LogCxx::setLevel(int newLevel)
{
    if (newLevel >= LOG_LEVEL_DEBUG && newLevel <= LOG_LEVEL_ERROR)
    {
        level = newLevel;
    }
}

void LogCxx::setCallback(LogCxxCallback newCallback)
{
    if (newCallback)
    {
        setMode(LOG_MODE_CALLBACK);
        logCallback = newCallback;
    }
}

void LogCxx::setLogFile(const std::string &newPath, size_t newSize, int newCount)
{
    setMode(LOG_MODE_WRITE_TO_FILE);
    logFilePath = newPath;
    maxFileSize = newSize;
    maxFileCount = newCount;
}

void LogCxx::setTimeFlag(bool flag)
{
    time_flag = flag;
}

void LogCxx::log(int msgLevel, const char *file, int line, const char *func, const char *format, va_list args)
{
    if (msgLevel < level)
        return;

    char *buffer = nullptr;

    char buffer_s[128];
    va_list args_c;
    va_copy(args_c, args);
    const size_t requiredLength = vsnprintf(buffer_s, sizeof(buffer_s), format, args_c);
    va_end(args_c);

    if (requiredLength < sizeof(buffer_s))
    {
        buffer = buffer_s;
    }
    else
    {
        buffer = new char[requiredLength + 1];
        vsnprintf(buffer, requiredLength + 1, format, args);
    }

    switch (mode)
    {
    case LOG_MODE_PRINT:
        if (time_flag)
        {
            printf("[%s:%d %s %s] %s\n", file, line, func, get_time().c_str(), buffer);
        }
        else
        {
            printf("[%s:%d %s] %s\n", file, line, func, buffer);
        }
        break;
    case LOG_MODE_WRITE_TO_FILE:
    {
        std::fstream logFile;
        logFile.open(logFilePath, std::fstream::in | std::fstream::out | std::fstream::app);

        if (!logFile.is_open())
        {
            printf("Failed to open log file: %s\n", logFilePath.c_str());
            break;
        }
        if (time_flag)
        {
            logFile << "[" << file << ":" << line << " " << func << " " << get_time() << "] " << buffer << std::endl;
        }
        else
        {
            logFile << "[" << file << ":" << line << " " << func << "] " << buffer << std::endl;
        }

        logFile.seekg(0, std::ios::end);
        size_t size = logFile.tellg();
        if (size > maxFileSize)
        {
            logFile.close();
            rotateLogFile();
        }
        else
        {
            logFile.close();
        }
    }
    break;
    case LOG_MODE_CALLBACK:
        if (logCallback)
        {
            std::stringstream ss;
            if (time_flag)
            {
                ss << "[" << file << ":" << line << " " << func << " " << get_time() << "] " << buffer << std::endl;
            }
            else
            {
                ss << "[" << file << ":" << line << " " << func << "] " << buffer << std::endl;
            }
            logCallback(ss.str().c_str());
        }
        break;
    }

    if (buffer != buffer_s)
    {
        delete[] buffer;
    }
}

void LogCxx::rotateLogFile()
{
    std::stringstream newLogFileName;
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    newLogFileName << logFilePath << "." << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S");
    std::rename(logFilePath.c_str(), newLogFileName.str().c_str());

    std::vector<std::filesystem::path> logFiles;
    std::string logFilePrefix = logFilePath.substr(0, logFilePath.find_last_of('.'));
    for (const auto &entry : std::filesystem::directory_iterator(std::filesystem::path(logFilePath).parent_path()))
    {
        if (entry.path().filename().string().find(logFilePrefix) != std::string::npos)
        {
            logFiles.push_back(entry.path());
        }
    }

    std::sort(logFiles.begin(), logFiles.end(), [](const std::filesystem::path &a, const std::filesystem::path &b)
              { return a.filename().string() > b.filename().string(); });

    while (int(logFiles.size()) > maxFileCount)
    {
        std::filesystem::remove(logFiles.back());
        logFiles.pop_back();
    }
}

std::string LogCxx::get_time()
{
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_tm = *std::localtime(&now_time_t);

    std::stringstream ss;
    ss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void *logcxx_create()
{
    return new LogCxx();
}

void logcxx_destroy(void *logger)
{
    if (!logger)
        return;
    delete static_cast<LogCxx *>(logger);
}

void logcxx_set_mode(void *logger, int mode)
{
    if (!logger)
        return;
    static_cast<LogCxx *>(logger)->setMode(mode);
}

void logcxx_set_level(void *logger, int level)
{
    if (!logger)
        return;
    static_cast<LogCxx *>(logger)->setLevel(level);
}

void logcxx_set_callback(void *logger, LogCxxCallback callback)
{
    if (!logger)
        return;

    static_cast<LogCxx *>(logger)->setCallback(callback);
}

void logcxx_set_log_file(void *logger, const char *path, size_t size, int count)
{
    if (!logger)
        return;
    static_cast<LogCxx *>(logger)->setLogFile(std::string(path), size, count);
}

void logcxx_set_time_flag(void *logger, bool flag)
{
    if (!logger)
        return;

    static_cast<LogCxx *>(logger)->setTimeFlag(flag);
}

void logcxx_log(void *logger, int level, const char *file, int line, const char *func, const char *format, ...)
{
    if (!logger)
        return;

    va_list args;
    va_start(args, format);
    static_cast<LogCxx *>(logger)->log(level, file, line, func, format, args);
    va_end(args);
}