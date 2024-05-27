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
#include <getopt.h>

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
    uint8_t type;
    uint32_t build_time;
    std::string text;
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

uint64_t token = 123;

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

std::vector<uint8_t> encrypt_text(const std::string &text, uint8_t key = 123)
{
    std::vector<uint8_t> encrypted_script(text.size());
    for (size_t i = 0; i < text.size(); ++i)
    {
        encrypted_script[i] = text[i] ^ key;
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

std::string decrypt_text(const std::vector<uint8_t> &encrypted_script, uint8_t key = 123)
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

    std::vector<uint8_t> decompressed_rules = decrypt_and_decompress(compressed_rules, token);
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

        rule.text = decrypt_text(encrypted_script, token);
        pattern->rules.push_back(rule);
    }

    std::vector<uint8_t> decompressed_sig_map = decrypt_and_decompress(compressed_sig_map, token);
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
        auto encrypted_script = encrypt_text(rule.text, token);
        rule.size = encrypted_script.size();
        rule.crc = crc32(encrypted_script);

        // Write rule header (excluding CRC and size)
        oss.write(reinterpret_cast<const char *>(&rule.id), sizeof(rule.id));
        oss.write(reinterpret_cast<const char *>(&rule.crc), sizeof(rule.crc));
        oss.write(reinterpret_cast<const char *>(&rule.size), sizeof(rule.size));
        oss.write(reinterpret_cast<const char *>(&rule.type), sizeof(rule.type));
        oss.write(reinterpret_cast<const char *>(&rule.build_time), sizeof(rule.build_time));
        oss.write(reinterpret_cast<const char *>(encrypted_script.data()), encrypted_script.size());
    }

    std::string rule_data = oss.str();
    std::vector<uint8_t> compress_rules = compress_and_encrypt(rule_data, token);
    pattern.rules_size = compress_rules.size();
    std::vector<uint8_t> compress_sig_map = compress_and_encrypt(pattern.sig_map_str, token);
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

void printUsage()
{
    std::cout << "Usage: [options]\n"
              << "Options:\n"
              << "  -t, --token          Set the token string (default: FBE_TEST_KEY)\n"
              << "  -c, --config         Path to the rule configuration file (default: ./rules_conf.json)\n"
              << "  -v, --version        Pattern version (default: 0)\n"
              << "  -p, --pattern        Path to the pattern file, this overrides the default pattern file name based on version\n"
              << "  -h, --help           Display this help and exit\n";
}

int main(int argc, char *argv[])
{
    std::string token_s = "FBE_TEST_KEY";
    std::string rule_conf_file = "./rules_conf.json";
    unsigned int pattern_version = 0;        
    std::string pattern_file = "./fbeptn";

    const char *const short_opts = "ht:c:v:p:";
    const option long_opts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"token", required_argument, nullptr, 't'},
        {"config", required_argument, nullptr, 'c'},
        {"version", required_argument, nullptr, 'v'},
        {"pattern", required_argument, nullptr, 'p'},
        {nullptr, no_argument, nullptr, 0}};

    while (true)
    {
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);

        if (-1 == opt)
            break;

        switch (opt)
        {
        case 'h':
            printUsage();
            return 0;
        case 't':
            token_s = optarg;
            break;
        case 'c':
            rule_conf_file = optarg;
            break;
        case 'v':
            pattern_version = std::stoul(optarg);
            break;
        case 'p':
            pattern_file = optarg; 
            break;
        case '?': 
        default:
            printUsage();
            return 1;
        }
    }

    if (!token_s.empty())
    {
        std::hash<std::string> hash_fn;
        token = hash_fn(token_s);
    }

    pattern_file += "." + std::to_string(pattern_version); 

    std::ifstream rules_conf_file(rule_conf_file);
    if (!rules_conf_file)
    {
        std::cerr << "Failed to open " << rule_conf_file << std::endl;
        return 1;
    }

    Json::CharReaderBuilder builder;
    Json::Value root;
    std::string errs;

    if (!Json::parseFromStream(builder, rules_conf_file, &root, &errs))
    {
        std::cerr << "Failed to parse: " << rule_conf_file << errs << std::endl;
        return 1;
    }

    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();

    // 创建测试 pattern
    FBPattern pattern;
    pattern.version = pattern_version;
    pattern.crc = 0; // 占位符，将在 create_pattern_file 中计算
    pattern.build_time = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(duration).count());
    std::filesystem::path p_path(pattern_file);
    std::string p_name = p_path.filename();
    strncpy(pattern.name, p_name.c_str(), sizeof(pattern.name));
    pattern.name[sizeof(pattern.name) - 1] = '\0';

    // 读取 Lua 规则并添加到 pattern
    const Json::Value &rule_array = root["rules"];

    for (const auto &rule_item : rule_array)
    {
        std::string rule_path = rule_item["rule_path"].asString();
        uint32_t rule_id = rule_item["rule_id"].asInt();
        std::ifstream rule_file(rule_path);

        FBRuleType rule_type = FB_Rule_Type_Lua;
        if (rule_item["rule_type"])
        {
            if (rule_item["rule_type"].asString() == "yaml")
            {
                rule_type = FB_Rule_Type_Yaml;
            }
        }

        if (rule_file)
        {
            std::string rule_text((std::istreambuf_iterator<char>(rule_file)),
                                  std::istreambuf_iterator<char>());
            FBRule rule{rule_id, 0, 0, rule_type, 0, rule_text};
            pattern.rules.push_back(rule);
        }
        else
        {
            std::cerr << "Failed to open Rule file: " << rule_path << std::endl;
        }
    }

    // 更新 rule_num 和 size
    pattern.rule_num = pattern.rules.size();
    pattern.size = 0; // This will be calculated in create_pattern_file

    const Json::Value &sig_map = root["sig_map"];
    Json::FastWriter writer;
    std::string sig_map_str = writer.write(sig_map);
    pattern.sig_map_str = sig_map_str;

    // 更新rule_num和size
    pattern.rule_num = pattern.rules.size();
    pattern.size = 0;
    pattern.rules_size = 0;
    pattern.sig_map_size = 0;

    // 创建pattern文件
    create_pattern_file(pattern, pattern_file);

    // 加载pattern文件
    FBPattern loaded_pattern;
    load_pattern_file(pattern_file, &loaded_pattern);
    std::cout << "Loaded Pattern Name: " << loaded_pattern.name << std::endl;
    for (const auto &rule : loaded_pattern.rules)
    {
        std::cout << "Rule ID: " << rule.id << ", Lua Script: " << rule.text << std::endl;
    }

    // std::cout << pattern.sig_map_str << std::endl;

    return 0;
}
