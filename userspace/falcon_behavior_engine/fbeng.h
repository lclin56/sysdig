#ifndef FB_ENG_H
#define FB_ENG_H
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
	std::string temp_dir;
	std::string token;
	int log_mode;
	int log_level;
	void* log_callback;
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
struct ArgsCatchInfo;
struct EventFmtInfo;

typedef void (*LogCxxCallback)(const char *log);

class FBEngine
{
public:
	FBEngine();

	int init(FBConf &conf);

	~FBEngine();

	std::string scan(const std::string &scap_file, const std::string &evt_log_file = "./evt_log.json", const std::string &filter_string = std::string(), int timeout = 600, size_t max_events = 1000000);
	
	std::string rscan(const std::string &scap_file, const std::string rule, bool is_file = true, const std::string &filter_string = std::string(), int timeout = 600, size_t max_events = 1000000);

	int cal_dynamic_score(const std::string &signatures);

	int set_temp_dir(std::string dir);

	static uint32_t get_version();

	static std::string get_version_str();

    uint32_t get_pattern_version();

private:
	FBPattern *pattern;
	std::string temp_dir;
	uint64_t token;

	bool interrupted = false;

	void *logger;

	void uninit();

	int load_pattern(const std::string &patternFile);

	bool ensure_dir_exists(std::string &dir);
	int unload_pattern();
	bool load_pattern_file(const std::string &patternFile, FBPattern *pattern);
	int parse_sig_map(const std::string &json_string, std::map<std::string, std::string> &sig_class_map, std::map<std::string, FBSig> &sig_settings_map, std::vector<std::string> &ignore_events);
	std::vector<uint8_t> decrypt_and_decompress(const std::vector<uint8_t> &encrypted_data, const int key = 123);
	std::string decrypt_rule_text(const std::vector<uint8_t> &encrypted_text, uint8_t key = 123);

	// libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp &inspector);
	sinsp_evt *get_event(sinsp &inspector, std::function<void(const std::string &)> handle_error);
	int load_chisels(sinsp &inspector, std::vector<sinsp_chisel *> &chisels);
	int load_yaml_rules(sinsp &inspector, falco_engine &engine, size_t &source_idx);
	int format_evt(sinsp &inspector, sinsp_evt *evt, std::map<uint64_t, ArgsCatchInfo> &args_catch, EventFmtInfo &evt_fmt);
	std::string format_report(std::map<uint64_t, uint64_t> &pre_evt_pool, const std::string &log_path, const std::string &report_path, const std::map<uint64_t, Json::Value> &raw_sigs);
	std::string get_random_str(int length);
};
#endif // FB_ENG_H