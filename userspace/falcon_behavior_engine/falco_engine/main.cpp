#include "falco_engine.h"

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include "falco_engine.h"
#include <memory>
#include <getopt.h>
#include <filesystem>

#define LOG_DEBUG(logger, format, ...) printf("DEBUG [%s:%d %s] " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define LOG_WARN(logger, format, ...) printf("WARN [%s:%d %s] " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define LOG_ERROR(logger, format, ...) printf("ERROR [%s:%d %s] " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define LOG_SET_MODE(logger, mode)
void *logger = nullptr;

namespace fs = std::filesystem;
std::string rule_set = "TEST_RULE_SET";

bool load_rules_files(falco_engine &engine, const std::vector<std::string> &rules_filenames)
{
    if (rules_filenames.empty())
    {
        LOG_ERROR(logger, "No rules file provided.");
        return false;
    }

    for (const auto &filename : rules_filenames)
    {
        try
        {
            std::string rules_content;
            engine.read_file(filename, rules_content);

            falco::load_result::rules_contents_t rc = {{filename, rules_content}};
            auto load_result = engine.load_rules(rules_content, filename);
            
            if (!load_result->successful())
            {
                LOG_ERROR(logger, "Successed to load rules from file %s: %s", filename.c_str(), load_result->as_string(true, rc).c_str());
                return false;
            }

            if (load_result->has_warnings())
            {
                // LOG_WARN(logger, "Warnings while loading rules from file %s: %s", filename.c_str(), load_result->as_string(true, rc).c_str());
            }

            engine.enable_rule("", true);

            LOG_DEBUG(logger, "Loaded rules from file %s", filename.c_str());
        }
        catch (const std::exception &e)
        {
            LOG_ERROR(logger, "Error loading rules from file %s: %s", filename.c_str(), e.what());
            return false;
        }
    }

    return true;
}

void load_rules_filenames_from_directory(const std::string &directory_path, std::vector<std::string> &rules_filenames)
{
    if (!fs::is_directory(directory_path))
    {
        std::cerr << directory_path << " is not a valid directory." << std::endl;
        return;
    }

    // 遍历目录中的所有条目
    for (const auto &entry : fs::directory_iterator(directory_path))
    {
        std::string path = entry.path();
        // 检查当前条目是否为文件
        if (entry.is_regular_file() && path.substr(path.length() - 5) == ".yaml")
        {
            // 获取文件的完整路径并添加到向量中
            rules_filenames.push_back(entry.path().string());
        }
    }
}

int main(int argc, char **argv)
{
    falco_engine engine;
    std::string rules_directory;
    std::string savefile_path;

    int opt;
    while ((opt = getopt(argc, argv, "r:s:")) != -1)
    {
        switch (opt)
        {
        case 'r':
            rules_directory = optarg;
            break;
        case 's':
            savefile_path = optarg;
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s -r rules_directory -s savefile_path\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // 确保-r和-s参数都被提供了
    if (rules_directory.empty() || savefile_path.empty())
    {
        std::cerr << "Both -r (rules directory) and -s (savefile) parameters are required." << std::endl;
        return 1;
    }

    // 添加事件源
    auto inspector = std::make_unique<sinsp>();
    inspector->open_savefile(savefile_path);

    auto filter_factory = std::make_shared<sinsp_filter_factory>(inspector.get());
    auto formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(inspector.get());

    falco_source syscall_source;
	syscall_source.name = "syscall";
	syscall_source.filter_factory = filter_factory;
	syscall_source.formatter_factory = formatter_factory;

    size_t source_idx = engine.add_source(syscall_source.name, filter_factory, formatter_factory);
    
    // 从指定的规则目录加载规则文件
    std::vector<std::string> rules_filenames;
    load_rules_filenames_from_directory(rules_directory, rules_filenames);

    if (!load_rules_files(engine, rules_filenames))
    {
        LOG_ERROR(logger, "Failed to load one or more rules files.");
        return 1;
    }

    LOG_DEBUG(logger, "Successfully loaded all rules files.");

    engine.complete_rule_loading();

    LOG_DEBUG(logger, "complete_rule_loading... ");

    inspector->start_capture();

    LOG_DEBUG(logger, "start_capture... ");
    std::vector<sinsp_evt *> events;
    while (true)
    {
        sinsp_evt *evt = nullptr;
        inspector->next(&evt);
        if (!evt)
        {
            break;
        }

        falco_common::rule_matching strategy(falco_common::rule_matching::ALL);
        auto result = engine.process_event(source_idx, evt, strategy);
        if (result)
        {
            for (auto it = result->begin(); it < result->end(); it++)
            {
                events.push_back(evt);
                sinsp_evt_formatter fmt(inspector.get(), it->format);
                std::string output;
                fmt.tostring(evt, output);
                LOG_DEBUG(logger, "%s", output.c_str());
            }
        }
    }

    inspector->stop_capture();

    for(auto &evt: events)
    {
        sinsp_evt_formatter fmt(inspector.get(), "%evt.num %evt.type(%evt.args)");
        std::string output;
        fmt.tostring(evt, output);
        LOG_DEBUG(logger, "evt %s", output.c_str());
    }
    LOG_DEBUG(logger, "end_capture... ");

    return 0;
}