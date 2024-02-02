#ifndef FALCON_BEHAVIOR_ENGINE_H
#define FALCON_BEHAVIOR_ENGINE_H
#include <string>
#include <vector>
#include <cstring>
#include <functional>
#include <map>

namespace Json
{
	class Value;
}

struct FBConf
{
	std::string pattern_path;
};

enum FBRuleType
{
    FB_Rule_Type_Lua = 0,
    FB_Rule_Type_Yaml
};


struct FBRule
{
	uint32_t id;
	uint32_t crc;
	uint64_t size;
	u_int8_t type;
	uint32_t build_time;
	std::string text;
};

struct FBSig
{
	int score;
	std::string text;
	std::string class_id;
	int severity;
};

struct FBPattern
{
	uint32_t version;
	uint32_t crc;
	uint32_t rule_num;
	uint32_t build_time;
	uint64_t size;
	char name[16];
	std::vector<FBRule> rules;
	std::map<std::string, std::string> sig_class;
	std::map<std::string, FBSig> sig_settings;
	std::vector<std::string> ignore_events;

	FBPattern() { std::memset(name, 0, sizeof(name)); }
};

struct sinsp;
struct sinsp_evt;
struct sinsp_chisel;
struct falco_engine;

class FalconBehaviorEngine
{
public:
	FalconBehaviorEngine();
	~FalconBehaviorEngine();

	int init(const FBConf &conf);

	int load_pattern(const std::string &patternFile);

	std::string scan(const std::string &file_path, const std::string &filter_string, int timeout = 600, size_t max_events = 1000000);

	void uninit();

private:
	FBPattern *pattern;

	std::function<void(sinsp &, sinsp_evt *)> dump;
	const uint8_t g_backoff_timeout_secs = 2;
	bool enable_glogger = false;
	std::string filter_string = "";
	bool interrupted = false;

	std::string default_output;
	std::string process_output;
	std::string net_output;
	void *logger;

	int unload_pattern();
	bool load_pattern_file(const std::string &patternFile, FBPattern *pattern);
	int parse_sig_map(const std::string &json_string, std::map<std::string, std::string> &sig_class_map, std::map<std::string, FBSig> &sig_settings_map, std::vector<std::string> &ignore_events);
	std::vector<uint8_t> decrypt_and_decompress(const std::vector<uint8_t> &encrypted_data, const int key = 123);
	std::string decrypt_rule_text(const std::vector<uint8_t> &encrypted_text, uint8_t key = 123);

	// libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp &inspector);
	sinsp_evt *get_event(sinsp &inspector, std::function<void(const std::string &)> handle_error);
	int load_chisels(sinsp &inspector, std::vector<sinsp_chisel *> &chisels);
	int load_yaml_rules(sinsp &inspector, falco_engine &engine, size_t &source_idx);
	void parse_chisel_args(sinsp_chisel *ch, std::string args);
	int format_evt(sinsp &inspector, sinsp_evt *evt, std::map<uint64_t, std::map<std::string, std::string>> &args_catch, std::string &evt_s);
	int format_report(std::map<uint64_t, std::string> &raw_logs, std::map<uint64_t, Json::Value> &raw_sigs, std::string &report_s);
};
#endif