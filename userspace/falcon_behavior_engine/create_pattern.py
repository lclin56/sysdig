import os
import zlib
import struct  
import random

'''
def reorder_data(data, encrypt=True, key=123):
    random.seed(key)  
    indexes = list(range(len(data)))
    random.shuffle(indexes)  
    if encrypt:
        reordered = bytes(data[i] for i in indexes)
    else:
        reversed_indexes = [0] * len(data)
        for i, index in enumerate(indexes):
            reversed_indexes[index] = i
        reordered = bytes(data[i] for i in reversed_indexes)

    return reordered
'''

def xor_encrypt_decrypt(data, key=123):
    return bytes(b ^ key for b in data)

def reorder_data(data, encrypt=True, key=123):
    step = key % 5 + 1
    if encrypt:
        data = bytes(data[(i - step) % len(data)] for i in range(len(data)))
    else:
        data = bytes(data[(i + step) % len(data)] for i in range(len(data)))
    return data


def encrypt_lua_script(lua_script, key=123):
    encrypted = xor_encrypt_decrypt(lua_script, key)
    return reorder_data(encrypted, encrypt=True)

def decrypt_lua_script(encrypted_script, key=123):
    decrypted = reorder_data(encrypted_script, encrypt=False)
    return xor_encrypt_decrypt(decrypted, key).decode('utf-8')

class FBRule:
    def __init__(self, id, crc, lua_script, build_time=0):
        self.id = id
        self.crc = crc
        self.lua_script = lua_script.encode('utf-8')
        self.size = len(self.lua_script)
        self.build_time = build_time

    def pack(self):
        encrypted_script = encrypt_lua_script(self.lua_script)
        header = struct.pack('<I I Q I', self.id, self.crc, len(encrypted_script), self.build_time)
        return header + encrypted_script

    @classmethod
    def unpack(cls, data):
        header = struct.unpack('<I I Q I', data[:20])
        id, crc, size, build_time = header
        encrypted_script = data[20:20+size]
        lua_script = decrypt_lua_script(encrypted_script)
        return cls(id, crc, lua_script, build_time)

class FBPattern:
    def __init__(self, version, crc, rules, build_time=0, name='PatternName'):
        self.version = version
        self.crc = crc
        self.rules = rules
        self.rule_num = len(rules)
        self.size = sum(rule.size for rule in rules)
        self.build_time = build_time
        self.name = name[:16]

    def pack(self):
        packed_rules = b"".join(rule.pack() for rule in self.rules)
        header = struct.pack('<I I I Q I 16s', self.version, self.crc, self.rule_num, self.size, self.build_time, self.name.encode('utf-8'))
        return header + packed_rules

    @classmethod
    def unpack(cls, data):
        header = struct.unpack('<I I I Q I 16s', data[:40])
        version, crc, rule_num, size, build_time, name = header
        name = name.decode('utf-8').strip('\x00')

        rules_data = data[40:]
        rules = []
        offset = 0
        for _ in range(rule_num):
            rule_header = struct.unpack('<I I Q I', rules_data[offset:offset+20])
            _, _, rule_size, _ = rule_header
            rule_data = rules_data[offset:offset + 20 + rule_size]
            rules.append(FBRule.unpack(rule_data))
            offset += 20 + rule_size

        return cls(version, crc, rules, build_time, name.strip())

def create_pattern_file(pattern, filename):
    with open(filename, 'wb') as file:
        file.write(pattern.pack())

def load_pattern_file(filename):
    with open(filename, 'rb') as file:
        data = file.read()
        return FBPattern.unpack(data)

# Example usage
# rules = [
#     FBRule(1, 0, "print('Hello, world!')"),
#     FBRule(2, 0, "print('Another script')")
# ]
    
rules = []

rules_directory = "rules"

for filename in os.listdir(rules_directory):
    if filename.endswith(".lua"):
        with open(os.path.join(rules_directory, filename), "r") as file:
            script_content = file.read()
            rule = FBRule(len(rules) + 1, 0, script_content)
            rules.append(rule)

pattern = FBPattern(1, 0, rules, name='ExamplePattern')
create_pattern_file(pattern, 'fbe_ptn.bin')

loaded_pattern = load_pattern_file('fbe_ptn.bin')
print(f"Loaded Pattern Name: {loaded_pattern.name}")
for rule in loaded_pattern.rules:
    print(f"Rule ID: {rule.id}, Script: {rule.lua_script}")
