#include "fbeng.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <chrono>
#include <csignal>
#include <sinsp.h>
#include <functional>
#include <filesystem>
#include "filter/ppm_codes.h"
#include <unordered_set>
#include <memory>
#include <cstdio>
#include "chisel.h"
#include "chisel_utils.h"
#include "chisel_fields_info.h"
#include "zlib.h"
#include "falco_engine.h"
#include "logcxx.h"
#include <random>

using std::endl;
using std::ifstream;
using std::map;
using std::ofstream;
using std::string;
using std::stringstream;
using std::vector;

struct EventFmtInfo
{
    uint64_t evt_num;
    uint64_t pre_evt_num;
    string evt_s;
};

struct ArgsCatchInfo
{
    uint64_t evt_num;
    map<string, string> args;
};

class Runscore
{
public:
    Runscore()
    {
        ScoreScale["DYNAMIC_SCALE"] = 0.75;
        ScoreScale["STATIC_SCALE"] = 0.2;
        ScoreScale["FEATURE_SCALE"] = 0.05;

        RiskLevel["UNKNOWN_RISK"] = -1;
        RiskLevel["NO_RISK"] = 0;
        RiskLevel["LOW_RISK"] = 1;
        RiskLevel["MID_RISK"] = 2;
        RiskLevel["HIGH_RISK"] = 4;

        ScoreRange["UNKNOWN_RISK"] = -1;
        ScoreRange["NO_RISK"] = 0;
        ScoreRange["LOW_RISK_B"] = 0;
        ScoreRange["LOW_RISK_T"] = 19;
        ScoreRange["LOW_RISK_M"] = 44;
        ScoreRange["MID_RISK_B"] = 20;
        ScoreRange["MID_RISK_T"] = 69;
        ScoreRange["MID_RISK_M"] = 84;
        ScoreRange["HIGH_RISK_B"] = 70;
        ScoreRange["HIGH_RISK_T"] = 100;
    }

    int cal_dynamic_score(const Json::Value &signatures)
    {
        if (signatures.empty())
        {
            return ScoreRange["UNKNOWN_RISK"];
        }
        int high_score = 0, mid_score = 0, low_score = 0, dynamic_score = 0;

        for (const auto &sig : signatures)
        {
            // int severity = sig["severity"].asInt();
            // int count = sig["markcount"].asInt();
            for (auto &mark : sig["marks"])
            {
                int count = mark["count"].asInt();
                int severity = mark["severity"].asInt();
                int score = count * severity;
                if (severity == RiskLevel["HIGH_RISK"])
                {
                    if (high_score + score >= ScoreRange["HIGH_RISK_T"])
                    {
                        high_score = ScoreRange["HIGH_RISK_T"];
                        continue;
                    }
                    high_score += score;
                }
                else if (severity > RiskLevel["LOW_RISK"])
                {
                    if (mid_score + score > ScoreRange["MID_RISK_M"])
                    {
                        mid_score = ScoreRange["MID_RISK_M"];
                        continue;
                    }
                    mid_score += score;
                }
                else
                {
                    if (low_score + score > ScoreRange["LOW_RISK_M"])
                    {
                        low_score = ScoreRange["LOW_RISK_M"];
                        continue;
                    }
                    low_score += score;
                }
            }
        }

        dynamic_score = high_score + mid_score + low_score;

        if (high_score)
        {
            dynamic_score += ScoreRange["HIGH_RISK_B"];
            dynamic_score = std::min(dynamic_score, ScoreRange["HIGH_RISK_T"]);
        }
        else if (mid_score)
        {
            dynamic_score += ScoreRange["MID_RISK_B"];
            dynamic_score = std::min(dynamic_score, ScoreRange["MID_RISK_M"]);
        }
        else
        {
            dynamic_score += ScoreRange["LOW_RISK_B"];
            dynamic_score = std::min(dynamic_score, ScoreRange["LOW_RISK_M"]);
        }

        return dynamic_score;
    }

    int cal_static_score(int static_severity = -1)
    {
        int static_score = ScoreRange["UNKNOWN_RISK"];
        if (static_severity == RiskLevel["UNKNOWN_RISK"])
        {
            static_score = ScoreRange["UNKNOWN_RISK"];
        }
        else if (static_severity == RiskLevel["NO_RISK"])
        {
            static_score = ScoreRange["NO_RISK"];
        }
        else if (static_severity == RiskLevel["LOW_RISK"])
        {
            static_score = ScoreRange["LOW_RISK_T"];
        }
        else if (static_severity < RiskLevel["HIGH_RISK"])
        {
            static_score = ScoreRange["MID_RISK_T"];
        }
        else
        {
            static_score = ScoreRange["HIGH_RISK_T"];
        }

        return static_score;
    }

    int cal_feature_score(int feature_severity = -1)
    {
        int feature_score = ScoreRange["UNKNOWN_RISK"];
        if (feature_severity == RiskLevel["UNKNOWN_RISK"])
        {
            feature_score = ScoreRange["UNKNOWN_RISK"];
        }
        else if (feature_severity == RiskLevel["NO_RISK"])
        {
            feature_score = ScoreRange["NO_RISK"];
        }
        else if (feature_severity == RiskLevel["LOW_RISK"])
        {
            feature_score = ScoreRange["LOW_RISK_T"];
        }
        else if (feature_severity < RiskLevel["HIGH_RISK"])
        {
            feature_score = ScoreRange["MID_RISK_T"];
        }
        else
        {
            feature_score = ScoreRange["HIGH_RISK_T"];
        }

        return feature_score;
    }

    int cal_severity(int score)
    {
        if (score == ScoreRange["UNKNOWN_RISK"])
        {
            return RiskLevel["UNKNOWN_RISK"];
        }
        else if (score <= ScoreRange["LOW_RISK_T"])
        {
            return RiskLevel["LOW_RISK"];
        }
        else if (score < ScoreRange["HIGH_RISK_B"])
        {
            return RiskLevel["MID_RISK"];
        }
        else
        {
            return RiskLevel["HIGH_RISK"];
        }
    }

    int cal_total_score(int dynamic_score = -1, int static_score = -1, int feature_score = -1)
    {
        int severity = RiskLevel["UNKNOWN_RISK"];
        double scale = 0.0, dynamic_scale = 0.0, static_scale = 0.0, feature_scale = 0.0;

        if (dynamic_score == ScoreRange["UNKNOWN_RISK"])
        {
            if (static_score != ScoreRange["UNKNOWN_RISK"])
            {
                static_scale = ScoreScale["DYNAMIC_SCALE"] + ScoreScale["STATIC_SCALE"];
                if (feature_score != ScoreRange["UNKNOWN_RISK"])
                {
                    feature_scale = ScoreScale["FEATURE_SCALE"];
                }
                else
                {
                    return static_score;
                }
                scale = static_scale;
                severity = cal_severity(static_score);
            }
            else
            {
                return feature_score;
            }
        }
        else
        {
            dynamic_scale = ScoreScale["DYNAMIC_SCALE"];
            if (static_score != ScoreRange["UNKNOWN_RISK"])
            {
                static_scale = ScoreScale["STATIC_SCALE"];
                if (feature_score != ScoreRange["UNKNOWN_RISK"])
                {
                    feature_scale = ScoreScale["FEATURE_SCALE"];
                }
                else
                {
                    static_scale += ScoreScale["FEATURE_SCALE"];
                }
            }
            else
            {
                dynamic_scale += ScoreScale["STATIC_SCALE"];
                if (feature_score != ScoreRange["UNKNOWN_RISK"])
                {
                    feature_scale = ScoreScale["FEATURE_SCALE"];
                }
                else
                {
                    return dynamic_score;
                }
            }
            scale = dynamic_scale + static_scale;
            severity = cal_severity(dynamic_score);
        }

        int total_score = static_cast<int>((dynamic_score * dynamic_scale + static_score * static_scale + feature_score * feature_scale) / scale);
        if (severity < RiskLevel["HIGH_RISK"])
        {
            return std::min(ScoreRange["MID_RISK_T"], total_score);
        }
        else
        {
            return std::min(ScoreRange["HIGH_RISK_T"], total_score);
        }
    }

private:
    map<string, double> ScoreScale;
    map<string, int> RiskLevel;
    map<string, int> ScoreRange;
};

FBEngine::FBEngine()
{
    pattern = nullptr;
    logger = nullptr;
    temp_dir = "./";
    token = 123;
}

FBEngine::~FBEngine()
{
    if (!logger)
    {
        LOG_DESTROY(logger);
        logger = nullptr;
    }
}

uint32_t FBEngine::get_version()
{
    uint8_t major = 1;
    uint8_t minor = 0;

    uint8_t yy = 24;
    uint8_t mm = 3;
    uint8_t dd = 1;

    u_int16_t patch = (static_cast<uint32_t>(yy) << 9) | (static_cast<uint32_t>(mm) << 5) | dd;

    uint32_t version = 0;
    version |= static_cast<uint32_t>(major) << 24;
    version |= static_cast<uint32_t>(minor) << 16;
    version |= patch;

    return version;
}

string FBEngine::get_version_str()
{
    uint32_t version = get_version();

    uint8_t major = (version >> 24) & 0xFF;
    uint8_t minor = (version >> 16) & 0xFF;
    uint16_t patch = version & 0xFFFF;

    uint8_t yy = (patch >> 9) & 0x7F;
    uint8_t mm = (patch >> 5) & 0x0F;
    uint8_t dd = patch & 0x1F;

    std::stringstream ss;
    ss << static_cast<int>(major) << '.'
       << static_cast<int>(minor) << '.'
       << std::setfill('0') << std::setw(2) << static_cast<int>(yy)
       << std::setw(2) << static_cast<int>(mm)
       << std::setw(2) << static_cast<int>(dd);

    return ss.str();
}

uint32_t FBEngine::get_pattern_version()
{
    if (!pattern)
    {
        return -1;
    }

    return pattern->version;
}

int FBEngine::init(FBConf &conf)
{
    logger = LOG_CREATE();
    LOG_SET_LEVEL(logger, conf.log_level);
    LOG_SET_CALLBACK(logger, (LogCxxCallback)conf.log_callback);

    if (!ensure_dir_exists(conf.temp_dir))
    {
        LOG_ERROR(logger, "set temp_dir %s failed", conf.temp_dir.c_str());
    }
    else
    {
        temp_dir = conf.temp_dir;
    }

    if (!conf.token.empty())
    {
        std::hash<std::string> hash_fn;
        token = hash_fn(conf.token);
    }

    return load_pattern(conf.pattern_path);
}

int FBEngine::load_pattern(const string &patternFile)
{
    if (pattern)
    {
        unload_pattern();
    }
    pattern = new FBPattern();

    if (!load_pattern_file(patternFile, pattern))
    {
        LOG_ERROR(logger, "load_pattern_file %s failed!", patternFile.c_str());
        return -1;
    }
    return 0;
}

string FBEngine::scan(const string &file_path, const string &report_file, const string &filter_string, int timeout, size_t max_events)
{
    vector<sinsp_chisel *> chisels;
    ifstream file(file_path);
    if (!file.good())
    {
        return string();
    }

    sinsp *inspector = new sinsp();
    if (!filter_string.empty())
    {
        try
        {
            inspector->set_filter(filter_string);
        }
        catch (const sinsp_exception &e)
        {
            LOG_ERROR(logger, "[ERROR] Unable to set filter: %s", e.what());
        }
    }

    inspector->open_savefile(file_path);

    load_chisels(*inspector, chisels);
    for (auto &chisel : chisels)
    {
        chisel->on_capture_start();
    }

    falco_engine *engine = new falco_engine();
    size_t source_idx = 0;

    if (load_yaml_rules(*inspector, *engine, source_idx) != 0)
    {
        delete engine;
        engine = nullptr;
        LOG_ERROR(logger, "load yaml rules failed!");
    }

    LOG_INFO(logger, "-- Start capture");

    inspector->start_capture();

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    uint64_t num_events = 0;
    map<uint64_t, Json::Value> raw_sigs;
    map<uint64_t, ArgsCatchInfo> args_catch;
    map<uint64_t, uint64_t> pre_evt_pool;
    map<string, uint64_t> sig_counter;

    std::filesystem::path temp_file_path = temp_dir;
    temp_file_path = temp_file_path / get_random_str(8);

    ofstream temp_file(temp_file_path);
    if (!temp_file.is_open())
    {
        LOG_ERROR(logger, "Failed to create temporary file: %s", temp_file_path.c_str());
        if (inspector)
        {
            delete inspector;
        }
        if (engine)
        {
            delete engine;
        }
        return string();
    }

    while (num_events < max_events)
    {
        void *logger_ = logger;
        auto err_func = [&logger_](const string &error_msg)
        {
            LOG_ERROR(logger_, "%s", error_msg.c_str());
        };
        sinsp_evt *ev = get_event(*inspector, err_func);

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - begin).count();
        if (duration > timeout)
        {
            LOG_ERROR(logger, "scan timeout, events num %d", num_events);
            // for (vector<sinsp_chisel *>::iterator it = chisels.begin(); it != chisels.end(); ++it)
            // {
            //     (*it)->do_timeout(ev);
            // }

            break;
        }

        if (ev != nullptr)
        {
            num_events++;

            auto it = std::find(pattern->ignore_events.begin(), pattern->ignore_events.end(), string(ev->get_name()));
            if (it != pattern->ignore_events.end())
            {
                // LOG_DEBUG(logger, "ignore_event");
                continue;
            }
            EventFmtInfo evt_fmt = {0, 0};
            if (format_evt(*inspector, ev, args_catch, evt_fmt) < 0)
            {
                LOG_WARN(logger, "format_evt err");
                continue;
            }
            if (evt_fmt.pre_evt_num > 0)
            {
                pre_evt_pool[evt_fmt.pre_evt_num] = evt_fmt.evt_num;
            }

            // LOG_DEBUG(logger, "%s", raw_log.c_str());
            temp_file << evt_fmt.evt_num << ":" << evt_fmt.evt_s;

            bool is_detected = false;
            if (engine)
            {
                std::unique_ptr<std::vector<falco_engine::rule_result>> result;
                try
                {
                    result = engine->process_event(source_idx, ev, falco_common::rule_matching::FIRST);
                }
                catch (const std::exception &e)
                {
                    LOG_ERROR(logger, "engine.process_event failed! \n%s", e.what());
                }

                if (result)
                {
                    for (auto it = result->begin(); !is_detected && it < result->end(); it++)
                    {
                        sinsp_evt_formatter fmt(inspector, it->format);
                        string output;
                        fmt.tostring(ev, output);
                        // LOG_DEBUG(logger, "Rule: %s \n%s", it->rule.c_str(), output.c_str());

                        Json::Value root;
                        Json::CharReaderBuilder builder;
                        std::istringstream jsonStream(output);

                        string errs;
                        Json::parseFromStream(builder, jsonStream, &root, &errs);

                        if (!errs.empty())
                        {
                            // LOG_ERROR(logger, "JSON parsing errors: %s", errs.c_str());
                            continue;
                        }
                        
                        if(sig_counter.find(it->rule) == sig_counter.end())
                        {
                            sig_counter[it->rule] = 0;
                        }

                        if(sig_counter[it->rule] < 500)
                        {
                            sig_counter[it->rule] += 1;
                            raw_sigs[ev->get_num()] = root;
                        }

                        is_detected = true;
                    }
                }
            }

            for (vector<sinsp_chisel *>::iterator it = chisels.begin(); !is_detected && it != chisels.end(); ++it)
            {
                string res;
                bool ret = false;
                try
                {
                    ret = (*it)->run(ev, res);
                }
                catch (const std::exception &e)
                {
                    LOG_ERROR(logger, "chisel run failed! \n%s", e.what());
                }

                if (ret == false)
                {
                    continue;
                }
                else
                {
                    Json::Value root;
                    Json::CharReaderBuilder builder;
                    std::istringstream jsonStream(res);

                    string errs;
                    Json::parseFromStream(builder, jsonStream, &root, &errs);

                    if (!errs.empty())
                    {
                        LOG_ERROR(logger, "JSON parsing errors: %s", errs.c_str());
                        continue;
                    }

                    // LOG_DEBUG(logger, "SIG: %s", res.c_str());
                    string sig_id = root["sig_id"].asString();
                    if(sig_counter.find(sig_id) == sig_counter.end())
                    {
                        sig_counter[sig_id] = 0;
                    }
                    if(sig_counter[sig_id] < 500)
                    {
                        sig_counter[sig_id] += 1;
                        raw_sigs[ev->get_num()] = root;
                    }
                    is_detected = true;
                }
            }
        }
        else
        {
            break;
        }
    }

    temp_file.close();

    string report_s = format_report(pre_evt_pool, temp_file_path, report_file, raw_sigs);
    if (report_s.empty())
    {
        LOG_ERROR(logger, "format_report failed!");
    }

    LOG_DEBUG(logger, "report_file %s", report_file.c_str());

    std::remove(temp_file_path.c_str());

    for (vector<sinsp_chisel *>::iterator it = chisels.begin(); it != chisels.end(); ++it)
    {
        (*it)->on_capture_end();
    }

    inspector->stop_capture();

    for (auto &chisel : chisels)
    {
        delete chisel;
        chisel = nullptr;
    }
    chisels.clear();

    if (engine)
    {
        delete engine;
        engine = nullptr;
    }

    if (inspector)
    {
        delete inspector;
        inspector = nullptr;
    }

    return report_s;
}

std::string FBEngine::rscan(const std::string &scap_file, const std::string rule, bool is_file, const std::string &filter_string, int timeout, size_t max_events)
{
    sinsp_chisel *chisel = nullptr;
    ifstream file(scap_file);
    if (!file.good())
    {
        return string();
    }

    sinsp *inspector = new sinsp();
    if (!filter_string.empty())
    {
        try
        {
            inspector->set_filter(filter_string);
        }
        catch (const sinsp_exception &e)
        {
            LOG_ERROR(logger, "[ERROR] Unable to set filter: %s", e.what());
        }
    }

    inspector->open_savefile(scap_file);

    try
    {
        chisel = new sinsp_chisel(inspector, rule, is_file);
        chisel->on_init();
        chisel->on_capture_start();
    }
    catch (const std::exception &e)
    {
        if (chisel)
        {
            delete chisel;
            chisel = nullptr;
        }
        LOG_ERROR(logger, "load chisel failed!");
    }

    falco_engine *engine = nullptr;
    size_t source_idx = 0;
    if (!chisel)
    {
        engine = new falco_engine();
        auto filter_factory = std::make_shared<sinsp_filter_factory>(inspector);
        auto formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(inspector);

        falco_source syscall_source;
        syscall_source.name = "syscall";
        syscall_source.filter_factory = filter_factory;
        syscall_source.formatter_factory = formatter_factory;

        source_idx = engine->add_source(syscall_source.name, filter_factory, formatter_factory);

        string name = "test_rule";
        string content = rule;
        if (is_file)
        {
            name = (string)std::filesystem::path(rule).filename();
            ifstream f_rule(rule);
            if (!f_rule.is_open())
            {
                content = string();
            }
            else
            {
                content = string((std::istreambuf_iterator<char>(f_rule)), (std::istreambuf_iterator<char>()));
            }
            f_rule.close();
        }

        int is_loaded = -1;
        falco::load_result::rules_contents_t rc = {{name, content}};
        try
        {
            auto load_result = engine->load_rules(content, name);

            if (!load_result->successful())
            {
                LOG_ERROR(logger, "Failed to load rules %s: %s", name.c_str(), load_result->as_string(true, rc).c_str());
                throw load_result->as_string(true, rc);
            }

            if (load_result->has_warnings())
            {
                LOG_DEBUG(logger, "Warnings while loading rules from file %s: %s", name.c_str(), load_result->as_string(true, rc).c_str());
            }

            engine->enable_rule("", true);
            is_loaded = 0;

            LOG_DEBUG(logger, "Loaded rules %s", name.c_str());
        }
        catch (const std::exception &e)
        {
            LOG_ERROR(logger, "Error loading rules %s \n%s", rule, e.what());
        }

        if (is_loaded == 0)
        {
            engine->complete_rule_loading();
            LOG_DEBUG(logger, "Successfully loaded all rules files.");
        }
        else
        {
            LOG_ERROR(logger, "No YAML rules have been loaded.");
            if (engine)
            {
                delete engine;
                engine = nullptr;
            }
        }
    }

    string ret;
    size_t num_events = 0;
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    while (num_events < max_events)
    {
        void *logger_ = logger;
        auto err_func = [&logger_](const string &error_msg)
        {
            LOG_ERROR(logger_, "%s", error_msg.c_str());
        };
        sinsp_evt *ev = get_event(*inspector, err_func);
        if (!ev)
        {
            break;
        }

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - begin).count();
        if (duration > timeout)
        {
            LOG_ERROR(logger, "scan timeout, events num %d", num_events);
            break;
        }

        if (chisel)
        {
            string res;
            if (chisel->run(ev, res) == true)
            {
                // Json::Value root;
                // Json::CharReaderBuilder builder;
                // std::istringstream jsonStream(res);

                // string errs;
                // Json::parseFromStream(builder, jsonStream, &root, &errs);

                // if (!errs.empty())
                // {
                //     LOG_ERROR(logger, "JSON parsing errors: %s", errs.c_str());
                //     continue;
                // }

                LOG_DEBUG(logger, "SIG: %s", res.c_str());
                ret = res;
            }
        }

        if (engine)
        {
            std::unique_ptr<std::vector<falco_engine::rule_result>> result;
            try
            {
                result = engine->process_event(source_idx, ev, falco_common::rule_matching::FIRST);
            }
            catch (const std::exception &e)
            {
                LOG_ERROR(logger, "engine->process_event failed! \n%s", e.what());
            }

            if (result)
            {
                for (auto it = result->begin(); it < result->end(); it++)
                {
                    sinsp_evt_formatter fmt(inspector, it->format);
                    string output;
                    fmt.tostring(ev, output);
                    LOG_DEBUG(logger, "Rule: %s \n%s", it->rule.c_str(), output.c_str());
                    ret = output;
                    // Json::Value root;
                    // Json::CharReaderBuilder builder;
                    // std::istringstream jsonStream(output);

                    // string errs;
                    // Json::parseFromStream(builder, jsonStream, &root, &errs);

                    // if (!errs.empty())
                    // {
                    //     // LOG_ERROR(logger, "JSON parsing errors: %s", errs.c_str());
                    //     continue;
                    // }
                }
            }
        }
    }

    if (engine)
    {
        delete engine;
        engine = nullptr;
    }

    if (chisel)
    {
        chisel->on_capture_end();
        delete chisel;
        chisel = nullptr;
    }

    if (inspector)
    {
        inspector->stop_capture();
        delete inspector;
        inspector = nullptr;
    }
    return ret;
}

int FBEngine::cal_dynamic_score(const string &signatures_s)
{
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::istringstream jsonStream(signatures_s);

    string errs;
    Json::parseFromStream(builder, jsonStream, &root, &errs);

    if (!errs.empty())
    {
        LOG_ERROR(logger, "JSON parsing errors: %s", errs.c_str());
        return -1;
    }

    // Check if "signatures" field exists in the root JSON object
    if (root.isMember("signatures"))
    {
        // Extract the "signatures" JSON object or array
        Json::Value signatures = root["signatures"];

        return Runscore().cal_dynamic_score(signatures);
    }
    else
    {
        LOG_ERROR(logger, "Missing 'signatures' field in JSON");
        return -1;
    }
}

int FBEngine::set_temp_dir(string dir)
{

    if (!ensure_dir_exists(dir))
    {
        return -1;
    }

    temp_dir = dir;
    return 0;
}

bool FBEngine::ensure_dir_exists(string &dir)
{
    if (dir.empty())
    {
        dir = "./";
    }

    if (std::filesystem::exists(dir))
    {
        if (std::filesystem::is_directory(dir))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        try
        {
            if (std::filesystem::create_directories(dir))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        catch (const std::filesystem::filesystem_error &e)
        {
            LOG_ERROR(logger, "Error creating directory: %s", e.what());
            return false;
        }
    }
}

int FBEngine::unload_pattern()
{
    if (pattern)
    {
        delete pattern;
        pattern = nullptr;
    }
    return 0;
}

void FBEngine::uninit() {}

bool FBEngine::load_pattern_file(const string &pattern_file, FBPattern *pattern)
{
    ifstream file(pattern_file, std::ios::binary | std::ios::in);
    if (!file.is_open())
    {
        LOG_ERROR(logger, "Failed to open file for reading: %s", pattern_file.c_str());
        return false;
    }

    // file.read(reinterpret_cast<char *>(&pattern), sizeof(FBPattern) - sizeof(pattern->rules));
    uint64_t rules_size, sig_map_size;
    file.read(reinterpret_cast<char *>(&pattern->version), sizeof(pattern->version));
    file.read(reinterpret_cast<char *>(&pattern->crc), sizeof(pattern->crc));
    file.read(reinterpret_cast<char *>(&pattern->rule_num), sizeof(pattern->rule_num));
    file.read(reinterpret_cast<char *>(&pattern->build_time), sizeof(pattern->build_time));
    file.read(reinterpret_cast<char *>(&pattern->size), sizeof(pattern->size));
    file.read(reinterpret_cast<char *>(&rules_size), sizeof(rules_size));
    file.read(reinterpret_cast<char *>(&sig_map_size), sizeof(sig_map_size));
    file.read(reinterpret_cast<char *>(&pattern->name), sizeof(pattern->name));

    vector<uint8_t> compressed_rules(rules_size);
    file.read(reinterpret_cast<char *>(compressed_rules.data()), rules_size);

    vector<uint8_t> compressed_sig_map(sig_map_size);
    file.read(reinterpret_cast<char *>(compressed_sig_map.data()), sig_map_size);

    if (!file)
    {
        LOG_ERROR(logger, "Error occurred during file read: %s", pattern_file.c_str());
        return false;
    }

    vector<uint8_t> decompressed_rules = decrypt_and_decompress(compressed_rules, token);
    if (decompressed_rules.empty())
    {
        file.close();
        return false;
    }
    std::istringstream iss(string(decompressed_rules.begin(), decompressed_rules.end()), std::ios::binary);

    for (size_t i = 0; i < pattern->rule_num; ++i)
    {
        FBRule rule;
        iss.read(reinterpret_cast<char *>(&rule.id), sizeof(rule.id));
        iss.read(reinterpret_cast<char *>(&rule.crc), sizeof(rule.crc));
        iss.read(reinterpret_cast<char *>(&rule.size), sizeof(rule.size));
        iss.read(reinterpret_cast<char *>(&rule.type), sizeof(rule.type));
        iss.read(reinterpret_cast<char *>(&rule.build_time), sizeof(rule.build_time));

        vector<uint8_t> encrypted_script(rule.size);
        iss.read(reinterpret_cast<char *>(encrypted_script.data()), rule.size);
        if (!iss)
        {
            LOG_ERROR(logger, "Error occurred during rule data read.");
            file.close();
            return false;
        }

        rule.text = decrypt_rule_text(encrypted_script, token);
        pattern->rules.push_back(rule);
    }

    vector<uint8_t> decompressed_sig_map = decrypt_and_decompress(compressed_sig_map, token);
    if (decompressed_sig_map.empty())
    {
        return false;
    }

    string sig_map_str = string(decompressed_sig_map.begin(), decompressed_sig_map.end());
    if (parse_sig_map(sig_map_str, pattern->sig_class, pattern->sig_settings, pattern->ignore_events) < 0)
    {
        return false;
    }

    return true;
}

int FBEngine::parse_sig_map(const string &json_string, map<string, string> &sig_class_map, map<string, FBSig> &sig_settings_map, vector<string> &ignore_events)
{
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::istringstream jsonStream(json_string);

    string errs;
    Json::parseFromStream(builder, jsonStream, &root, &errs);

    if (!errs.empty())
    {
        LOG_ERROR(logger, "JSON parsing errors: %s", errs);
        return -1;
    }

    Json::Value sig_class = root["sig_class"];
    for (const auto &key : sig_class.getMemberNames())
    {
        sig_class_map[key] = sig_class[key].asString();
    }

    Json::Value sig_settings = root["sig_settings"];
    for (const auto &key : sig_settings.getMemberNames())
    {
        FBSig sig;
        sig.score = sig_settings[key]["score"].asInt();
        sig.text = sig_settings[key]["text"].asString();
        sig.class_id = sig_settings[key]["class"].asString();
        sig.severity = sig_settings[key]["severity"].asInt();
        sig_settings_map[key] = sig;
    }

    Json::Value ignore_events_ = root["ignore_events"];
    for (int i = 0; i < int(ignore_events_.size()); ++i)
    {
        string element = ignore_events_[i].asString();
        ignore_events.push_back(element);
    }

    return 0;
}

vector<uint8_t> FBEngine::decrypt_and_decompress(const vector<uint8_t> &encrypted_data, const int key)
{
    vector<uint8_t> decrypted_data = encrypted_data;
    for (size_t i = 0; i < decrypted_data.size(); ++i)
    {
        decrypted_data[i] ^= static_cast<char>(key);
    }

    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (inflateInit(&zs) != Z_OK)
    {
        LOG_ERROR(logger, "inflateInit failed while decompressing.");
        return vector<uint8_t>();
    }

    zs.next_in = reinterpret_cast<Bytef *>(decrypted_data.data());
    zs.avail_in = decrypted_data.size();

    int ret;
    char outbuffer[1024];
    vector<uint8_t> decompressed_data;

    do
    {
        zs.next_out = reinterpret_cast<Bytef *>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);
        if (ret == Z_STREAM_ERROR)
        {
            inflateEnd(&zs);
            return decompressed_data;
        }

        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
        {
            inflateEnd(&zs);
            return decompressed_data;
        }

        if (decompressed_data.size() < zs.total_out)
        {
            decompressed_data.insert(decompressed_data.end(), outbuffer,
                                     outbuffer + zs.total_out - decompressed_data.size());
        }
    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END)
    {

        LOG_ERROR(logger, "Exception during zlib decompression: (%d) %s", ret, zs.msg);
        return vector<uint8_t>();
    }

    return decompressed_data;
}

string FBEngine::decrypt_rule_text(const vector<uint8_t> &encrypted_text, uint8_t key)
{
    vector<uint8_t> decrypted_text(encrypted_text.size());
    const size_t step = key % 5 + 1;

    for (size_t i = 0; i < encrypted_text.size(); ++i)
    {
        size_t new_pos = (i + encrypted_text.size() - step) % encrypted_text.size();
        decrypted_text[new_pos] = encrypted_text[i];
    }

    for (size_t i = 0; i < decrypted_text.size(); ++i)
    {
        decrypted_text[i] = decrypted_text[i] ^ key;
    }

    return string(decrypted_text.begin(), decrypted_text.end());
}

int FBEngine::load_chisels(sinsp &inspector, vector<sinsp_chisel *> &chisels)
{
    for (auto &rule : pattern->rules)
    {
        if (rule.text.empty() || rule.type != FB_Rule_Type_Lua)
        {
            continue;
        }

        sinsp_chisel *ch = new sinsp_chisel(&inspector, rule.text, false);

        ch->on_init();

        chisels.push_back(ch);
    }

    return true;
}

int FBEngine::load_yaml_rules(sinsp &inspector, falco_engine &engine, size_t &source_idx)
{
    auto filter_factory = std::make_shared<sinsp_filter_factory>(&inspector);
    auto formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(&inspector);

    falco_source syscall_source;
    syscall_source.name = "syscall";
    syscall_source.filter_factory = filter_factory;
    syscall_source.formatter_factory = formatter_factory;

    source_idx = engine.add_source(syscall_source.name, filter_factory, formatter_factory);
    int ret = -1;
    for (auto &rule : pattern->rules)
    {
        if (rule.text.empty() || rule.type != FB_Rule_Type_Yaml)
        {
            continue;
        }
        string name = std::to_string(rule.id);

        falco::load_result::rules_contents_t rc = {{name, rule.text}};
        try
        {
            auto load_result = engine.load_rules(rule.text, name);

            if (!load_result->successful())
            {
                LOG_ERROR(logger, "Failed to load rules %s: %s", name.c_str(), load_result->as_string(true, rc).c_str());
                continue;
            }

            if (load_result->has_warnings())
            {
                LOG_DEBUG(logger, "Warnings while loading rules from file %s: %s", name.c_str(), load_result->as_string(true, rc).c_str());
            }

            engine.enable_rule("", true);
            ret = 0;

            LOG_DEBUG(logger, "Loaded rules %s", name.c_str());
        }
        catch (const std::exception &e)
        {
            LOG_ERROR(logger, "Error loading rules %d: %s", rule.id, e.what());
        }
    }

    if (ret < 0)
    {
        LOG_ERROR(logger, "No YAML rules have been loaded.");
        return ret;
    }

    engine.complete_rule_loading();

    LOG_DEBUG(logger, "Successfully loaded all rules files.");

    return ret;
}

sinsp_evt *FBEngine::get_event(sinsp &inspector, std::function<void(const string &)> handle_error)
{
    sinsp_evt *ev = nullptr;

    try
    {
        int32_t res = inspector.next(&ev);

        if (res == SCAP_SUCCESS)
        {
            return ev;
        }
        if (res == SCAP_EOF)
        {
            LOG_INFO(logger, "-- EOF");
            return nullptr;
        }

        if (res != SCAP_TIMEOUT && res != SCAP_FILTERED_EVENT)
        {
            handle_error(inspector.getlasterr());
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    catch (const std::exception &e)
    {
        LOG_ERROR(logger, "inspector next failed!\n%s", e.what());
    }

    return nullptr;
}

int FBEngine::format_evt(sinsp &inspector, sinsp_evt *evt, map<uint64_t, ArgsCatchInfo> &args_catch, EventFmtInfo &evt_fmt)
{
    if (!evt)
    {
        return -1;
    }

    event_direction evt_dir = evt->get_direction();
    sinsp_threadinfo *th = evt->get_thread_info();
    if (!th)
    {
        return -1;
    }

    map<string, string> args_map;
    for (uint32_t i = 0; i < evt->get_num_params(); i++)
    {
        string name = evt->get_param_name(i);
        string value;

        if (name == "cgroups")
        {
            continue;
        }

        char fmt_str[32] = {0};
        if (name == "fd")
        {
            snprintf(fmt_str, 32, "%%evt.arg.fd");
        }
        else
        {
            snprintf(fmt_str, 32, "%%evt.arg[%d]", i);
        }
        try
        {
            sinsp_evt_formatter fmt(&inspector, fmt_str);
            fmt.tostring(evt, value);
        }
        catch (const std::exception &e)
        {
            LOG_ERROR(logger, "sinsp_evt_formatter failed! \n%s", e.what());
        }

        if (name == "fd")
        {
            if (value.front() == '<')
            {
                value = std::to_string(evt->get_fd_num()) + value;
            }
        }
        args_map[name] = value;
    }

    uint16_t evt_type = evt->get_type();
    evt_type = evt_dir == SCAP_ED_IN ? evt_type : evt_type - 1;
    uint64_t tid = th->m_tid;
    uint64_t key = evt_type;
    key = (key << 32) + tid;
    string return_code;

    auto it = args_catch.find(key);
    if (it != args_catch.end())
    {
        for (auto &arg : it->second.args)
        {
            if (args_map.find(arg.first) == args_map.end())
            {
                args_map[arg.first] = arg.second;
            }
        }

        evt_fmt.pre_evt_num = it->second.evt_num;
        args_catch.erase(key);
    }

    if (evt_dir == SCAP_ED_IN)
    {
        args_catch[key] = {evt->get_num(), args_map};
    }

    string args_s = "";
    for (auto &arg : args_map)
    {
        if (arg.first == "res")
        {
            return_code = arg.second;
            continue;
        }
        args_s += arg.first + "=" + arg.second + " ";
    }

    if (evt_dir == SCAP_ED_OUT && return_code.empty())
    {
        if (args_map.find("fd") != args_map.end())
        {
            return_code = args_map["fd"];
        }
    }

    if (args_s.back() == ' ')
    {
        args_s.pop_back();
    }

    Json::Value root;
    root["pid"] = th->m_vpid;
    root["process_name"] = th->get_comm();
    root["api"] = evt->get_name();
    root["args"] = args_s;
    root["return_code"] = return_code;
    sinsp_evt_formatter fmt(&inspector, "%evt.time");
    string ts_str;
    fmt.tostring(evt, ts_str);
    root["timestamp"] = ts_str;
    Json::FastWriter writer;

    evt_fmt.evt_num = evt->get_num();
    evt_fmt.evt_s = writer.write(root);
    return 0;
}

string FBEngine::format_report(map<uint64_t, uint64_t> &pre_evt_pool, const string &log_path, const string &report_path, const map<uint64_t, Json::Value> &raw_sigs)
{
    ifstream log_file(log_path);
    if (!log_file.is_open())
    {
        LOG_ERROR(logger, "open log file %s failed!", log_path.c_str());
        return "";
    }

    ofstream report_file(report_path);
    if (!report_file.is_open())
    {
        LOG_ERROR(logger, "open report file %s failed!", report_path.c_str());
        return "";
    }

    size_t log_num = 0;
    map<uint64_t, size_t> index_map;
    string line;

    while (std::getline(log_file, line))
    {
        size_t pos = line.find_first_of(":");
        if (pos != string::npos)
        {
            uint64_t evt_num = std::stoull(line.substr(0, pos));
            if (pre_evt_pool.find(evt_num) != pre_evt_pool.end())
            {
                continue;
            }
            index_map[evt_num] = log_num++;
            report_file << line.substr(pos + 1) << endl;
        }
    }

    log_file.close();

    Json::Value root;

    Json::Value signatures = Json::Value();
    signatures = Json::arrayValue;

    map<string, Json::Value> sigs_map;
    for (auto &sig : raw_sigs)
    {
        Json::Value sig_j = sig.second;
        string sig_id = sig_j["sig_id"].asString();
        auto sig_set_it = pattern->sig_settings.find(sig_id);
        if (sig_set_it != pattern->sig_settings.end())
        {
            auto class_it = pattern->sig_class.find(sig_set_it->second.class_id);
            if (class_it == pattern->sig_class.end())
            {
                LOG_ERROR(logger, "there is not class_id %s in the pattern", sig_set_it->second.class_id.c_str());
                continue;
            }

            Json::Value mark = Json::Value();
            mark["sig_id"] = sig_id;
            mark["text"] = sig_set_it->second.text;
            mark["score"] = sig_set_it->second.score;
            mark["severity"] = sig_set_it->second.severity;
            mark["count"] = 1;

            Json::Value logs_index = Json::Value();
            logs_index = Json::arrayValue;
            for (auto &m : sig_j["marks"])
            {
                uint64_t evtnum = m.asLargestUInt();
                auto index_it = pre_evt_pool.find(evtnum);
                if (index_it != pre_evt_pool.end())
                {
                    evtnum = index_it->second;
                }

                index_it = index_map.find(evtnum);
                if (index_it != index_map.end())
                {
                    logs_index.append(index_it->second);
                }
                else
                {
                    LOG_ERROR(logger, "the envnum %ld not found!", evtnum);
                }
            }
            mark["logs_index"] = logs_index;

            auto [it, inserted] = sigs_map.emplace(sig_set_it->second.class_id, Json::Value{});
            Json::Value &sig_res = it->second;

            if (inserted)
            {
                sig_res["classid"] = sig_set_it->second.class_id;
                sig_res["class"] = class_it->second;
                sig_res["severity"] = 0;
                sig_res["marks"] = Json::arrayValue;
                sig_res["markcount"] = 0;
            }

            bool is_old_mark = false;
            for (auto &m : sig_res["marks"])
            {
                if (m["sig_id"] == sig_id)
                {
                    is_old_mark = true;
                    auto &logs_index_ = m["logs_index"];
                    for (auto &l : mark["logs_index"])
                    {
                        logs_index_.append(l);
                    }
                    sig_res["markcount"] = sig_res["markcount"].asInt() + 1;
                    m["count"] = m["count"].asInt() + 1;
                    break;
                }
            }

            if (!is_old_mark)
            {
                sig_res["marks"].append(mark);
                sig_res["markcount"] = sig_res["markcount"].asInt() + 1;
            }
        }
        else
        {
            LOG_ERROR(logger, "there is not sig_id %s in the pattern", sig_id.c_str());
        }
    }

    for (auto &sig : sigs_map)
    {
        int severity = 0;
        for (auto &mark : sig.second["marks"])
        {
            int m_severity = mark["severity"].asInt();
            severity = m_severity > severity ? m_severity : severity;
        }

        sig.second["severity"] = severity;
        signatures.append(sig.second);
    }

    root["signatures"] = signatures;

    root["EngineVersion"] = get_version_str();

    root["PatternVersion"] = get_pattern_version();

    // root["risk_score"] = Runscore().cal_dynamic_score(signatures);

    Json::FastWriter writer;
    string dynam_s = writer.write(root);
    // report_file << dynam_s << endl;

    return dynam_s;
}

std::string FBEngine::get_random_str(int length)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis('a', 'z');

    std::string random_str;
    for (int i = 0; i < length; ++i)
    {
        random_str += static_cast<char>(dis(gen));
    }

    return random_str;
}

// int main(int argc, char *argv[])
// {
//     if (argc != 2)
//     {
//         printf("Usage: %s <filename>\n", argv[0]);
//         return 1;
//     }

//     FBEngine engine;
//     FBConf conf = {
//         .pattern_path = "fbe_ptn.bin"};
//     engine.init(conf);

//     const char *filename = argv[1];

//     engine.scan(filename);

//     return 0;
// }
