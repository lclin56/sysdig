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

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
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

static std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;

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

    while (num_events < max_events)
    {
        sinsp_evt *ev = get_event(inspector, [](const std::string &error_msg)
                                  { cout << "[ERROR] " << error_msg << endl; });

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - begin).count();
        if (duration > timeout)
        {
            cout << "[ERROR] "
                 << "scan timeout" << endl;
            for (std::vector<sinsp_chisel *>::iterator it = chisels.begin(); it != chisels.end(); ++it)
            {
                (*it)->do_timeout(ev);
            }
        }

        if (ev != nullptr)
        {
            for (std::vector<sinsp_chisel *>::iterator it = chisels.begin(); it != chisels.end(); ++it)
            {
                if ((*it)->run(ev) == false)
                {
                    continue;
                }
            }
        }
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

    file.read(reinterpret_cast<char *>(&pattern->version), sizeof(pattern->version));
    file.read(reinterpret_cast<char *>(&pattern->crc), sizeof(pattern->crc));
    file.read(reinterpret_cast<char *>(&pattern->rule_num), sizeof(pattern->rule_num));
    file.read(reinterpret_cast<char *>(&pattern->size), sizeof(pattern->size));
    file.read(reinterpret_cast<char *>(&pattern->build_time), sizeof(pattern->build_time));
    file.read(pattern->name, sizeof(pattern->name));

    for (size_t i = 0; i < pattern->rule_num; ++i)
    {
        FBRule rule;
        file.read(reinterpret_cast<char *>(&rule.id), sizeof(rule.id));
        file.read(reinterpret_cast<char *>(&rule.crc), sizeof(rule.crc));
        file.read(reinterpret_cast<char *>(&rule.size), sizeof(rule.size));
        file.read(reinterpret_cast<char *>(&rule.build_time), sizeof(rule.build_time));

        std::vector<uint8_t> encrypted_script(rule.size);
        file.read(reinterpret_cast<char *>(encrypted_script.data()), rule.size);
        rule.lua_script = decrypt_lua_script(encrypted_script);
        pattern->rules.push_back(rule);
        cout<<"Rule "<< rule.id << endl << rule.lua_script << endl;
    }

    return true;
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

sinsp_evt* FalconBehaviorEngine::get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);

	if(res == SCAP_SUCCESS)
	{
		return ev;
	}
	if(res == SCAP_EOF)
	{
		std::cout << "-- EOF" << std::endl;
		interrupted = true;
		return nullptr;
	}

	if(res != SCAP_TIMEOUT && res != SCAP_FILTERED_EVENT)
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

int main()
{
    FalconBehaviorEngine engine;
    FBConf conf = {.pattern_path = "fbe_ptn.bin"};
    engine.init(conf);
    engine.scan("./dump.scap", "");
}