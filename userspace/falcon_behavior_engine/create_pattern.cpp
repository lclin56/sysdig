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

FBPattern load_pattern_file(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::in);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file for reading: " << filename << std::endl;
        throw std::runtime_error("File opening failed");
    }

    FBPattern pattern;
    file.read(reinterpret_cast<char *>(&pattern), sizeof(FBPattern));

    file.seekg(0, std::ios::end);
    auto end_pos = file.tellg();
    auto compressed_data_size = static_cast<std::size_t>(end_pos) - sizeof(FBPattern);
    file.seekg(sizeof(FBPattern), std::ios::beg);

    std::vector<uint8_t> compressed_data(compressed_data_size);
    file.read(reinterpret_cast<char *>(compressed_data.data()), compressed_data_size);

    if (!file)
    {
        std::cerr << "Error occurred during file read: " << filename << std::endl;
        throw std::runtime_error("File read failed");
    }

    std::vector<uint8_t> decompressed_data = decrypt_and_decompress(compressed_data);
    std::istringstream iss(std::string(decompressed_data.begin(), decompressed_data.end()), std::ios::binary);

    for (size_t i = 0; i < pattern.rule_num; ++i)
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
        pattern.rules.push_back(rule);
    }

    return pattern;
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
    std::vector<uint8_t> compress_data = compress_and_encrypt(rule_data);

    pattern.size = compress_data.size() + sizeof(FBPattern);
    pattern.crc = crc32(compress_data);

    file.write(reinterpret_cast<const char *>(&pattern), sizeof(FBPattern));
    file.write(reinterpret_cast<const char *>(compress_data.data()), compress_data.size());

    if (!file)
    {
        std::cerr << "Error occurred during file write: " << filename << std::endl;
        throw std::runtime_error("File write failed");
    }
}

int main()
{
    // 创建测试pattern
    FBPattern test_pattern;
    test_pattern.version = 1;
    test_pattern.crc = 0; // 占位符，将在create_pattern_file中计算
    test_pattern.build_time = 12345678;
    strncpy(test_pattern.name, "TestPattern", sizeof(test_pattern.name));

    // 读取./rules目录下的.lua脚本
    std::string path = "./rules";
    int ruleId = 1;
    for (const auto &entry : std::filesystem::directory_iterator(path))
    {
        if (entry.path().extension() == ".lua")
        {
            std::ifstream luaFile(entry.path());
            if (luaFile)
            {
                std::string luaScript((std::istreambuf_iterator<char>(luaFile)),
                                      std::istreambuf_iterator<char>());
                FBRule rule{ruleId++, 0, 0, 0, luaScript};
                test_pattern.rules.push_back(rule);
            }
        }
    }

    // 更新rule_num和size
    test_pattern.rule_num = test_pattern.rules.size();
    test_pattern.size = 0; // This will be calculated in create_pattern_file

    // 创建pattern文件
    create_pattern_file(test_pattern, "pattern_file.bin");

    // 加载pattern文件
    FBPattern loaded_pattern = load_pattern_file("pattern_file.bin");
    std::cout << "Loaded Pattern Name: " << loaded_pattern.name << std::endl;
    for (const auto &rule : loaded_pattern.rules)
    {
        std::cout << "Rule ID: " << rule.crc << ", Lua Script: " << rule.lua_script << std::endl;
    }

    return 0;
}
