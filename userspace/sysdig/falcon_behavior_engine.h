#ifndef FALCON_BEHAVIOR_ENGINE_H
#define FALCON_BEHAVIOR_ENGINE_H
#include <string>
#include <vector>
#include <cstring>
#include <functional>

struct FBConf
{
	std::string pattern_path;
};

struct FBRule
{
	uint32_t id;
	uint32_t crc;
	uint64_t size;
	uint32_t build_time;
	std::string lua_script;
};

struct FBPattern
{
	uint32_t version;
	uint32_t crc;
	uint32_t rule_num;
	uint64_t size;
	uint32_t build_time;
	char name[16];
	std::vector<FBRule> rules;

	FBPattern() { std::memset(name, 0, sizeof(name)); }
};

struct sinsp;
struct sinsp_evt;
struct sinsp_chisel;

class FalconBehaviorEngine
{
public:
	FalconBehaviorEngine() = default;
	~FalconBehaviorEngine() = default;

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

	int unload_pattern();
	bool load_pattern_file(const std::string &patternFile, FBPattern *pattern);
	std::string decrypt_lua_script(const std::vector<uint8_t> &encrypted_script, uint8_t key = 123);

	// libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp &inspector);
	sinsp_evt *get_event(sinsp &inspector, std::function<void(const std::string &)> handle_error);
	int load_chisels(sinsp &inspector, std::vector<sinsp_chisel *> &chisels);
	void parse_chisel_args(sinsp_chisel *ch, std::string args);
};

#endif