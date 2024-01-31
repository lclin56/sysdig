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

                    raw_sigs[ev->get_num()] = root;
                    // LOG_DEBUG(logger, "SIG: %s", res.c_str());
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

    uint64_t rules_size, sig_map_size;
    // file.read(reinterpret_cast<char *>(&pattern), sizeof(FBPattern) - sizeof(pattern->rules));
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
        iss.read(reinterpret_cast<char *>(&rule.build_time), sizeof(rule.build_time));

        std::vector<uint8_t> encrypted_script(rule.size);
        iss.read(reinterpret_cast<char *>(encrypted_script.data()), rule.size);
        if (!iss)
        {
            std::cerr << "Error occurred during rule data read." << std::endl;
            throw std::runtime_error("Rule data read failed");
        }

        rule.lua_script = decrypt_lua_script(encrypted_script);
        pattern->rules.push_back(rule);
    }

    std::vector<uint8_t> decompressed_sig_map = decrypt_and_decompress(compressed_sig_map);
    std::string sig_map_str = std::string(decompressed_sig_map.begin(), decompressed_sig_map.end());
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
    for (int i = 0; i < ignore_events_.size(); ++i)
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

std::string FalconBehaviorEngine::decrypt_lua_script(const std::vector<uint8_t> &encrypted_script, uint8_t key)
{
    std::vector<uint8_t> decrypted_script(encrypted_script.size());
    const size_t step = key % 5 + 1;

    for (size_t i = 0; i < encrypted_script.size(); ++i)
    {
        size_t new_pos = (i + encrypted_script.size() - step) % encrypted_script.size();
        decrypted_script[new_pos] = encrypted_script[i];
    }

    for (size_t i = 0; i < decrypted_script.size(); ++i)
    {
        decrypted_script[i] = decrypted_script[i] ^ key;
    }

    return std::string(decrypted_script.begin(), decrypted_script.end());
}

int FalconBehaviorEngine::load_chisels(sinsp &inspector, vector<sinsp_chisel *> &chisels)
{
    for (auto &rule : pattern->rules)
    {
        if (rule.lua_script.empty())
        {
            continue;
        }

        sinsp_chisel *ch = new sinsp_chisel(&inspector, rule.lua_script, false);

        // parse_chisel_args(ch, filter_factory, optind, argc, argv, &n_filterargs);

        ch->on_init();

        chisels.push_back(ch);
    }

    return true;
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
    uint32_t nargs = ch->get_n_args();
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
    for (int i = 0; i < evt->get_num_params(); i++)
    {
        string name = evt->get_param_name(i);
        string value;

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
    root["pid"] = th->m_pid;
    root["process_name"] = th->get_comm();
    root["api"] = evt->get_name();
    root["args"] = args_s;
    root["return_code"] = return_code;
    root["timestamp"] = evt->get_ts();
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
            Json::Value sig_res = Json::Value();
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

            bool is_old_sig = false;
            if (sigs_map.find(sig_set_it->second.class_id) != sigs_map.end())
            {
                sig_res = sigs_map[sig_set_it->second.class_id];
                is_old_sig = true;
            }
            else
            {
                sig_res["classid"] = sig_set_it->second.class_id;
                sig_res["class"] = class_it->second;
                sig_res["severity"] = 0;
                sig_res["marks"] = Json::Value();
                sig_res["marks"] = Json::arrayValue;
            }

            bool is_old_mark = false;
            for (auto &m : sig_res["marks"])
            {
                if (m["sig_id"] == sig_id)
                {
                    is_old_mark = true;
                    for (auto &l : mark["logs_index"])
                    {
                        m["logs_index"].append(l);
                    }
                }
            }

            if (!is_old_mark)
            {
                sig_res["marks"].append(mark);
            }

            if (!is_old_sig)
            {
                sigs_map[sig_set_it->second.class_id] = sig_res;
            }
        }
        else
        {
            LOG_ERROR(logger, "there is not sig_id %s in the pattern", sig_id.c_str());
        }
    }

    for (auto &sig : sigs_map)
    {
        signatures.append(sig.second);
    }
    root["signatures"] = signatures;

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
