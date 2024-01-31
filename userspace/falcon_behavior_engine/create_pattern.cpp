#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <random>
#include <numeric>
#include <sstream>
#include <zlib.h>
#include <filesystem>
#include <json/json.h>

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
    uint32_t build_time;
    uint64_t size;
    uint64_t rules_size;
    uint64_t sig_map_size;
    char name[16];
    std::vector<FBRule> rules;
    std::string sig_map_str;

    FBPattern() { std::memset(name, 0, sizeof(name)); }
};

uint32_t crc32(const std::vector<uint8_t> &data)
{
    uint32_t crc = 0xFFFFFFFF;
    for (auto byte : data)
    {
        crc = crc ^ byte;
        for (int j = 7; j >= 0; j--)
        {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

std::vector<uint8_t> encrypt_lua_script(const std::string &lua_script, uint8_t key = 123)
{
    std::vector<uint8_t> encrypted_script(lua_script.size());
    for (size_t i = 0; i < lua_script.size(); ++i)
    {
        encrypted_script[i] = lua_script[i] ^ key;
    }

    std::vector<uint8_t> reordered(encrypted_script.size());
    const size_t step = key % 5 + 1;
    for (size_t i = 0; i < encrypted_script.size(); ++i)
    {
        size_t new_pos = (i + step) % encrypted_script.size();
        reordered[new_pos] = encrypted_script[i];
    }

    return reordered;
}

std::string decrypt_lua_script(const std::vector<uint8_t> &encrypted_script, uint8_t key = 123)
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

std::vector<uint8_t> compress_and_encrypt(const std::string &data, const int key = 123)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK)
        throw std::runtime_error("deflateInit failed while compressing.");

    zs.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(data.data()));
    zs.avail_in = data.size();

    int ret;
    char outbuffer[1024];
    std::vector<uint8_t> outdata;

    do
    {
        zs.next_out = reinterpret_cast<Bytef *>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = deflate(&zs, Z_FINISH);

        for (size_t i = 0; i < sizeof(outbuffer) - zs.avail_out; ++i)
        {
            outbuffer[i] ^= static_cast<char>(key);
        }

        if (outdata.size() < zs.total_out)
        {
            outdata.insert(outdata.end(), outbuffer, outbuffer + zs.total_out - outdata.size());
        }
    } while (ret == Z_OK);

    deflateEnd(&zs);

    if (ret != Z_STREAM_END)
    {
        throw std::runtime_error("Exception during zlib compression: (" + std::to_string(ret) + ") " + zs.msg);
    }

    return outdata;
}

std::vector<uint8_t> decrypt_and_decompress(const std::vector<uint8_t> &encrypted_data, const int key = 123)
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

bool load_pattern_file(const std::string &pattern_file, FBPattern *pattern)
{
    std::ifstream file(pattern_file, std::ios::binary | std::ios::in);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file for reading: " << pattern_file << std::endl;
        throw std::runtime_error("File opening failed");
    }

    // file.read(reinterpret_cast<char *>(&pattern), sizeof(FBPattern) - sizeof(pattern->rules));
    file.read(reinterpret_cast<char *>(&pattern->version), sizeof(pattern->version));
    file.read(reinterpret_cast<char *>(&pattern->crc), sizeof(pattern->crc));
    file.read(reinterpret_cast<char *>(&pattern->rule_num), sizeof(pattern->rule_num));
    file.read(reinterpret_cast<char *>(&pattern->build_time), sizeof(pattern->build_time));
    file.read(reinterpret_cast<char *>(&pattern->size), sizeof(pattern->size));
    file.read(reinterpret_cast<char *>(&pattern->rules_size), sizeof(pattern->rules_size));
    file.read(reinterpret_cast<char *>(&pattern->sig_map_size), sizeof(pattern->sig_map_size));
    file.read(reinterpret_cast<char *>(&pattern->name), sizeof(pattern->name));

    std::vector<uint8_t> compressed_rules(pattern->rules_size);
    file.read(reinterpret_cast<char *>(compressed_rules.data()), pattern->rules_size);

    std::vector<uint8_t> compressed_sig_map(pattern->sig_map_size);
    file.read(reinterpret_cast<char *>(compressed_sig_map.data()), pattern->sig_map_size);

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
    pattern->sig_map_str = std::string(decompressed_sig_map.begin(), decompressed_sig_map.end());
    return true;
}

void create_pattern_file(FBPattern &pattern, const std::string &filename)
{
    std::ofstream file(filename, std::ios::binary | std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
        throw std::runtime_error("File opening failed");
    }

    std::ostringstream oss(std::ios::binary);
    // Write each rule and calculate CRC and size as you go
    for (auto &rule : pattern.rules)
    {
        // Encrypt and write the Lua script
        auto encrypted_script = encrypt_lua_script(rule.lua_script);
        rule.size = encrypted_script.size();
        rule.crc = crc32(encrypted_script);

        // Write rule header (excluding CRC and size)
        oss.write(reinterpret_cast<const char *>(&rule.id), sizeof(rule.id));
        oss.write(reinterpret_cast<const char *>(&rule.crc), sizeof(rule.crc));
        oss.write(reinterpret_cast<const char *>(&rule.size), sizeof(rule.size));
        oss.write(reinterpret_cast<const char *>(&rule.build_time), sizeof(rule.build_time));
        oss.write(reinterpret_cast<const char *>(encrypted_script.data()), encrypted_script.size());
    }

    std::string rule_data = oss.str();
    std::vector<uint8_t> compress_rules = compress_and_encrypt(rule_data);
    pattern.rules_size = compress_rules.size();
    std::vector<uint8_t> compress_sig_map = compress_and_encrypt(pattern.sig_map_str);
    pattern.sig_map_size = compress_sig_map.size();
    std::vector<uint8_t> compress_data(compress_rules.begin(), compress_rules.end());
    compress_data.insert(compress_data.end(), compress_sig_map.begin(), compress_sig_map.end());

    pattern.size = compress_data.size() + 4 * sizeof(uint32_t) + 3 * sizeof(uint64_t) + sizeof(pattern.name);
    pattern.crc = crc32(compress_data);

    // file.write(reinterpret_cast<const char *>(&pattern), sizeof(FBPattern) - sizeof(pattern.rules));
    file.write(reinterpret_cast<const char *>(&pattern.version), sizeof(pattern.version));
    file.write(reinterpret_cast<const char *>(&pattern.crc), sizeof(pattern.crc));
    file.write(reinterpret_cast<const char *>(&pattern.rule_num), sizeof(pattern.rule_num));
    file.write(reinterpret_cast<const char *>(&pattern.build_time), sizeof(pattern.build_time));
    file.write(reinterpret_cast<const char *>(&pattern.size), sizeof(pattern.size));
    file.write(reinterpret_cast<const char *>(&pattern.rules_size), sizeof(pattern.rules_size));
    file.write(reinterpret_cast<const char *>(&pattern.sig_map_size), sizeof(pattern.sig_map_size));
    file.write(reinterpret_cast<const char *>(&pattern.name), sizeof(pattern.name));

    file.write(reinterpret_cast<const char *>(compress_rules.data()), pattern.rules_size);
    file.write(reinterpret_cast<const char *>(compress_sig_map.data()), pattern.sig_map_size);

    if (!file)
    {
        std::cerr << "Error occurred during file write: " << filename << std::endl;
        throw std::runtime_error("File write failed");
    }
}

int main()
{
	// 读取规则列表文件 rules_list.json
	std::ifstream rulesListFile("rules/rules_list.json");
	if(!rulesListFile)
	{
		std::cerr << "Failed to open rules_list.json" << std::endl;
		return 1;
	}

	Json::CharReaderBuilder builder;
	Json::Value rulesList;
	std::string errs;

	if(!Json::parseFromStream(builder, rulesListFile, &rulesList, &errs))
	{
		std::cerr << "Failed to parse rules_list.json: " << errs << std::endl;
		return 1;
	}

	// 创建测试 pattern
	FBPattern test_pattern;
	test_pattern.version = 1;
	test_pattern.crc = 0; // 占位符，将在 create_pattern_file 中计算
	test_pattern.build_time = 12345678;
	strncpy(test_pattern.name, "TestPattern", sizeof(test_pattern.name));

	// 读取 Lua 规则并添加到测试 pattern
	const Json::Value &ruleArray = rulesList["rules"];

	for(const auto &ruleItem : ruleArray)
	{
		std::string rulePath = ruleItem["rule_path"].asString();
	    int ruleId = ruleItem["rule_id"].asInt();
		std::ifstream luaFile(rulePath);

		if(luaFile)
		{
			std::string luaScript((std::istreambuf_iterator<char>(luaFile)),
					      std::istreambuf_iterator<char>());
			FBRule rule{ruleId, 0, 0, 0, luaScript};
			test_pattern.rules.push_back(rule);
		}
		else
		{
			std::cerr << "Failed to open Lua file: " << rulePath << std::endl;
		}
	}

	// 更新 rule_num 和 size
	test_pattern.rule_num = test_pattern.rules.size();
	test_pattern.size = 0; // This will be calculated in create_pattern_file

	std::ifstream sig_map_file("rules/sig_map.json");
	if(sig_map_file)
	{
		std::string sig_map_str((std::istreambuf_iterator<char>(sig_map_file)),
					std::istreambuf_iterator<char>());
		test_pattern.sig_map_str = sig_map_str;
	}

    // 更新rule_num和size
    test_pattern.rule_num = test_pattern.rules.size();
    test_pattern.size = 0;
    test_pattern.rules_size = 0;
    test_pattern.sig_map_size = 0;

    // 创建pattern文件
    create_pattern_file(test_pattern, "fbe_ptn.bin");

    // 加载pattern文件
    FBPattern loaded_pattern;
    load_pattern_file("fbe_ptn.bin", &loaded_pattern);
    std::cout << "Loaded Pattern Name: " << loaded_pattern.name << std::endl;
    for (const auto &rule : loaded_pattern.rules)
    {
        std::cout << "Rule ID: " << rule.id << ", Lua Script: " << rule.lua_script << std::endl;
    }

    std::cout << test_pattern.sig_map_str << std::endl;

    return 0;
}
