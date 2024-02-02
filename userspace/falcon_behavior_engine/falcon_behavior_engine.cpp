#include "falcon_behavior_engine.h"
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
#include "filter/ppm_codes.h"
#include <unordered_set>
#include <memory>
#include "chisel.h"
#include "chisel_utils.h"
#include "chisel_fields_info.h"
#include "zlib.h"
#include "falco_engine.h"

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::map;
using std::string;
using std::vector;

#define EVENT_HEADER \
    "%evt.num %evt.time cat=%evt.category container=%container.id proc=%proc.name(%proc.pid.%thread.tid) "
#define EVENT_TRAILER "%evt.dir %evt.type %evt.args"

#define EVENT_DEFAULTS EVENT_HEADER EVENT_TRAILER
#define PROCESS_DEFAULTS EVENT_HEADER "ppid=%proc.ppid exe=%proc.exe args=[%proc.cmdline] " EVENT_TRAILER

#define JSON_PROCESS_DEFAULTS                                                                                 \
    "*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe %proc.cmdline " \
    "%evt.args"

#define LOG_DEBUG(logger, format, ...) printf("[%s:%d %s] " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define LOG_WARN(logger, format, ...)
#define LOG_ERROR(logger, format, ...) LOG_DEBUG(logger, format, ##__VA_ARGS__)
#define LOG_SET_MODE(logger, mode)

static std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;

FalconBehaviorEngine::FalconBehaviorEngine()
{
    pattern = nullptr;
}

FalconBehaviorEngine::~FalconBehaviorEngine()
{
}

int FalconBehaviorEngine::init(const FBConf &conf)
{
    default_output = EVENT_DEFAULTS;
    process_output = PROCESS_DEFAULTS;
    net_output = PROCESS_DEFAULTS " %fd.name";
    return load_pattern(conf.pattern_path);
}

int FalconBehaviorEngine::load_pattern(const std::string &patternFile)
{
    if (pattern)
    {
        unload_pattern();
    }
    pattern = new FBPattern();

    return load_pattern_file(patternFile, pattern);
}

std::string FalconBehaviorEngine::scan(const std::string &file_path, const string &filter_string, int timeout, size_t max_events)
{
    sinsp inspector;
    vector<sinsp_chisel *> chisels;
    std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
    std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
    std::unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;
    ifstream file(file_path);
    if (!file.good())
    {
        return string();
    }

    if (enable_glogger)
    {
        cout << "-- Enabled g_logger.'" << endl;
        g_logger.set_severity(sinsp_logger::SEV_DEBUG);
        g_logger.add_stdout_log();
    }

    if (!filter_string.empty())
    {
        try
        {
            inspector.set_filter(filter_string);
        }
        catch (const sinsp_exception &e)
        {
            cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
        }
    }

    inspector.open_savefile(file_path);

    load_chisels(inspector, chisels);
    for (auto &chisel : chisels)
    {
        chisel->on_capture_start();
    }

    falco_engine engine;
    size_t source_idx = 0;
    bool use_falco_engine = false;

    if (load_yaml_rules(inspector, engine, source_idx) == 0)
    {
        use_falco_engine = true;
    }

    std::cout << "-- Start capture" << std::endl;

    inspector.start_capture();

    default_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, default_output);
    process_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, process_output);
    net_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, net_output);

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    uint64_t num_events = 0;
    map<uint64_t, string> raw_logs;
    map<uint64_t, Json::Value> raw_sigs;
    std::map<uint64_t, std::map<std::string, std::string>> args_catch;

    while (num_events < max_events)
    {
        sinsp_evt *ev = get_event(inspector, [](const std::string &error_msg)
                                  { LOG_ERROR(logger, "%s", error_msg.c_str()); });

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - begin).count();
        if (duration > timeout)
        {
            LOG_ERROR(logger, "scan timeout");
            for (std::vector<sinsp_chisel *>::iterator it = chisels.begin(); it != chisels.end(); ++it)
            {
                (*it)->do_timeout(ev);
            }
        }

        if (ev != nullptr)
        {
            auto it = std::find(pattern->ignore_events.begin(), pattern->ignore_events.end(), string(ev->get_name()));
            if (it != pattern->ignore_events.end())
            {
                LOG_WARN(logger, "ignore_event");
                continue;
            }
            string raw_log;
            if (format_evt(inspector, ev, args_catch, raw_log) < 0)
            {
                LOG_WARN(logger, "format_evt err");
                continue;
            }
            // LOG_DEBUG(logger, "%s", raw_log.c_str());
            raw_logs[ev->get_num()] = raw_log;

            for (std::vector<sinsp_chisel *>::iterator it = chisels.begin(); it != chisels.end(); ++it)
            {
                string res;
                if ((*it)->run(ev, res) == false)
                {
                    continue;
                }
                else
                {
                    Json::Value root;
                    Json::CharReaderBuilder builder;
                    std::istringstream jsonStream(res);

                    std::string errs;
                    Json::parseFromStream(builder, jsonStream, &root, &errs);

                    if (!errs.empty())
                    {
                        LOG_ERROR(logger, "JSON parsing errors: %s", errs.c_str());
                        continue;
                    }

                    // LOG_DEBUG(logger, "SIG: %s", res.c_str());
                    raw_sigs[ev->get_num()] = root;
                }
            }

            if (use_falco_engine)
            {
                auto result = engine.process_event(source_idx, ev, falco_common::rule_matching::ALL);
                if (result)
                {
                    for (auto it = result->begin(); it < result->end(); it++)
                    {
                        sinsp_evt_formatter fmt(&inspector, it->format);
                        std::string output;
                        fmt.tostring(ev, output);
                        LOG_DEBUG(logger, "EVT: %ld Rule: %s\n%s", ev->get_num(), it->rule.c_str(), raw_logs[ev->get_num()].c_str());
                        // LOG_DEBUG(logger, "Rule: %s \n%s", it->rule.c_str(), output.c_str());
                    }
                }
            }
        }
        else
        {
            break;
        }
    }

    string report_s;
    if (format_report(raw_logs, raw_sigs, report_s) < 0)
    {
        LOG_ERROR(logger, "format_report failed!");
    }
    LOG_DEBUG(logger, "Report: %s", report_s.c_str());

    for (std::vector<sinsp_chisel *>::iterator it = chisels.begin(); it != chisels.end(); ++it)
    {
        (*it)->on_capture_end();
    }

    inspector.stop_capture();

    for (auto &chisel : chisels)
    {
        delete chisel;
    }

    chisels.clear();

    return "";
}

int FalconBehaviorEngine::unload_pattern()
{
    if (pattern)
    {
        delete pattern;
        pattern = nullptr;
    }
    return 0;
}

void FalconBehaviorEngine::uninit() {}

bool FalconBehaviorEngine::load_pattern_file(const std::string &pattern_file, FBPattern *pattern)
{
    std::ifstream file(pattern_file, std::ios::binary | std::ios::in);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file for reading: " << pattern_file << std::endl;
        throw std::runtime_error("File opening failed");
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

    std::vector<uint8_t> compressed_rules(rules_size);
    file.read(reinterpret_cast<char *>(compressed_rules.data()), rules_size);

    std::vector<uint8_t> compressed_sig_map(sig_map_size);
    file.read(reinterpret_cast<char *>(compressed_sig_map.data()), sig_map_size);

    if (!file)
    {
        std::cerr << "Error occurred during file read: " << pattern_file << std::endl;
        throw std::runtime_error("File read failed");
    }

    std::vector<uint8_t> decompressed_rules = decrypt_and_decompress(compressed_rules);
    std::istringstream iss(std::string(decompressed_rules.begin(), decompressed_rules.end()), std::ios::binary);

    for (size_t i = 0; i < pattern->rule_num; ++i)
    {
        FBRule rule;
        iss.read(reinterpret_cast<char *>(&rule.id), sizeof(rule.id));
        iss.read(reinterpret_cast<char *>(&rule.crc), sizeof(rule.crc));
        iss.read(reinterpret_cast<char *>(&rule.size), sizeof(rule.size));
        iss.read(reinterpret_cast<char *>(&rule.type), sizeof(rule.type));
        iss.read(reinterpret_cast<char *>(&rule.build_time), sizeof(rule.build_time));

        std::vector<uint8_t> encrypted_script(rule.size);
        iss.read(reinterpret_cast<char *>(encrypted_script.data()), rule.size);
        if (!iss)
        {
            std::cerr << "Error occurred during rule data read." << std::endl;
            throw std::runtime_error("Rule data read failed");
        }

        rule.text = decrypt_rule_text(encrypted_script);
        pattern->rules.push_back(rule);
    }

    std::vector<uint8_t> decompressed_sig_map = decrypt_and_decompress(compressed_sig_map);
    string sig_map_str = std::string(decompressed_sig_map.begin(), decompressed_sig_map.end());
    if (parse_sig_map(sig_map_str, pattern->sig_class, pattern->sig_settings, pattern->ignore_events) < 0)
    {
        return false;
    }

    return true;
}

int FalconBehaviorEngine::parse_sig_map(const std::string &json_string, std::map<std::string, std::string> &sig_class_map, std::map<std::string, FBSig> &sig_settings_map, std::vector<std::string> &ignore_events)
{
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::istringstream jsonStream(json_string);

    std::string errs;
    Json::parseFromStream(builder, jsonStream, &root, &errs);

    if (!errs.empty())
    {
        std::cerr << "JSON parsing errors: " << errs << std::endl;
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
        std::string element = ignore_events_[i].asString();
        ignore_events.push_back(element);
    }

    return 0;
}

std::vector<uint8_t> FalconBehaviorEngine::decrypt_and_decompress(const std::vector<uint8_t> &encrypted_data, const int key)
{
    std::vector<uint8_t> decrypted_data = encrypted_data;
    for (size_t i = 0; i < decrypted_data.size(); ++i)
    {
        decrypted_data[i] ^= static_cast<char>(key);
    }

    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (inflateInit(&zs) != Z_OK)
        throw std::runtime_error("inflateInit failed while decompressing.");

    zs.next_in = reinterpret_cast<Bytef *>(decrypted_data.data());
    zs.avail_in = decrypted_data.size();

    int ret;
    char outbuffer[1024];
    std::vector<uint8_t> decompressed_data;

    do
    {
        zs.next_out = reinterpret_cast<Bytef *>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);

        if (decompressed_data.size() < zs.total_out)
        {
            decompressed_data.insert(decompressed_data.end(), outbuffer,
                                     outbuffer + zs.total_out - decompressed_data.size());
        }
    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END)
    {
        throw std::runtime_error("Exception during zlib decompression: (" + std::to_string(ret) + ") " +
                                 zs.msg);
    }

    return decompressed_data;
}

std::string FalconBehaviorEngine::decrypt_rule_text(const std::vector<uint8_t> &encrypted_text, uint8_t key)
{
    std::vector<uint8_t> decrypted_text(encrypted_text.size());
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

    return std::string(decrypted_text.begin(), decrypted_text.end());
}

int FalconBehaviorEngine::load_chisels(sinsp &inspector, vector<sinsp_chisel *> &chisels)
{
    for (auto &rule : pattern->rules)
    {
        if (rule.text.empty() || rule.type != FB_Rule_Type_Lua)
        {
            continue;
        }

        sinsp_chisel *ch = new sinsp_chisel(&inspector, rule.text, false);

        // parse_chisel_args(ch, filter_factory, optind, argc, argv, &n_filterargs);

        ch->on_init();

        chisels.push_back(ch);
    }

    return true;
}

int FalconBehaviorEngine::load_yaml_rules(sinsp &inspector, falco_engine &engine, size_t &source_idx)
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
                LOG_WARN(logger, "Warnings while loading rules from file %s: %s", filename.c_str(), load_result->as_string(true, rc).c_str());
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

sinsp_evt *FalconBehaviorEngine::get_event(sinsp &inspector, std::function<void(const std::string &)> handle_error)
{
    sinsp_evt *ev = nullptr;

    int32_t res = inspector.next(&ev);

    if (res == SCAP_SUCCESS)
    {
        return ev;
    }
    if (res == SCAP_EOF)
    {
        std::cout << "-- EOF" << std::endl;
        interrupted = true;
        return nullptr;
    }

    if (res != SCAP_TIMEOUT && res != SCAP_FILTERED_EVENT)
    {
        handle_error(inspector.getlasterr());
        std::this_thread::sleep_for(std::chrono::seconds(g_backoff_timeout_secs));
    }

    return nullptr;
}

void FalconBehaviorEngine::parse_chisel_args(sinsp_chisel *ch, string args)
{
    uint32_t nreqargs = ch->get_n_required_args();
    if (nreqargs != 0)
    {
        ch->set_args(args);
    }
}

int FalconBehaviorEngine::format_evt(sinsp &inspector, sinsp_evt *evt, std::map<uint64_t, std::map<std::string, std::string>> &args_catch, std::string &evt_s)
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
        sinsp_evt_formatter fmt(&inspector, fmt_str);
        fmt.tostring(evt, value);

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
        for (auto &arg : it->second)
        {
            if (args_map.find(arg.first) == args_map.end())
            {
                args_map[arg.first] = arg.second;
            }
        }

        args_catch.erase(key);
    }

    if (evt_dir == SCAP_ED_IN)
    {
        args_catch[key] = args_map;
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
    evt_s = writer.write(root);
    return 0;
}

int FalconBehaviorEngine::format_report(std::map<uint64_t, std::string> &raw_logs, std::map<uint64_t, Json::Value> &raw_sigs, std::string &report_s)
{
    size_t log_num = 0;
    map<uint64_t, size_t> index_map;

    std::ostringstream oss;
    oss << "\"RawLogs\":[";
    for (auto &log : raw_logs)
    {
        index_map[log.first] = log_num++;
        oss << log.second << ",";
    }
    string raw_log_s = oss.str();
    if (raw_log_s.back() == ',')
    {
        raw_log_s.pop_back();
    }
    raw_log_s.push_back(']');

    Json::Value root;
    root["VirusName"] = Json::arrayValue;

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

            Json::Value logs_index = Json::Value();
            logs_index = Json::arrayValue;
            for (auto &m : sig_j["marks"])
            {
                uint64_t evtnum = m.asLargestUInt();
                auto index_it = index_map.find(evtnum);
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
                }
            }

            if (!is_old_mark)
            {
                sig_res["marks"].append(mark);
            }
        }
        else
        {
            LOG_ERROR(logger, "there is not sig_id %s in the pattern", sig_id.c_str());
        }
    }

    int score = 0;
    for (auto &sig : sigs_map)
    {
        int severity = 0;
        int mark_count = 0;
        for (auto &mark : sig.second["marks"])
        {
            int m_severity = mark["severity"].asInt();
            severity = m_severity > severity ? m_severity : severity;
            score += mark["score"].asInt();
            mark_count++;
        }

        sig.second["severity"] = severity;
        signatures.append(sig.second);
    }

    root["signatures"] = signatures;
    root["risk_score"] = score;

    Json::FastWriter writer;
    string dynam_s = writer.write(root);

    report_s = string("{") + raw_log_s + "," + "\"DynamicResult\":" + dynam_s + "}";

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FalconBehaviorEngine engine;
    FBConf conf = {.pattern_path = "fbe_ptn.bin"};
    engine.init(conf);

    const char *filename = argv[1];

    engine.scan(filename, "");

    return 0;
}
