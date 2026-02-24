#pragma warning(disable : 4996)
#include "../stages/stages.h"
#include "../dumper.h"
#include "../../core/logger/logger.h"
#include "../../core/process/process.h"

#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <set>
#include <map>
#include <mutex>
#include <chrono>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <random>
#include <unordered_set>
#include <unordered_map>

namespace {

    std::mutex memoryMutex;

    struct MemoryRegion {
        uintptr_t base;
        size_t size;
        DWORD protect;
        std::vector<uint8_t> data;
    };

    struct FoundOffset {
        std::string category;
        std::string name;
        uintptr_t offset;
        std::string description;
        std::string pattern;
    };

    struct FoundString {
        uintptr_t address;
        uintptr_t offset;
        std::string value;
        std::string category;
    };

    struct FoundFunction {
        uintptr_t address;
        uintptr_t offset;
        std::string name;
        std::string pattern;
        size_t size_estimate;
    };

    struct FoundXref {
        uintptr_t from_offset;
        uintptr_t to_offset;
        std::string type;
    };

    struct AutoPattern {
        std::string name;
        std::string category;
        uintptr_t offset;
        std::string pattern;
        std::string description;
        int confidence;
        std::string type;
    };

    std::vector<MemoryRegion> g_all_regions;
    std::vector<MemoryRegion> g_executable_regions;
    std::vector<MemoryRegion> g_readable_regions;
    std::vector<FoundOffset> g_found_offsets;
    std::vector<FoundString> g_found_strings;
    std::vector<FoundFunction> g_found_functions;
    std::vector<FoundXref> g_found_xrefs;
    std::vector<AutoPattern> g_auto_patterns;
    uintptr_t g_module_base = 0;
    size_t g_module_size = 0;

    std::string protect_to_str(DWORD protect) {
        if (protect & PAGE_EXECUTE_READWRITE) return "RWX";
        if (protect & PAGE_EXECUTE_READ) return "RX";
        if (protect & PAGE_EXECUTE_WRITECOPY) return "RWX_C";
        if (protect & PAGE_EXECUTE) return "X";
        if (protect & PAGE_READWRITE) return "RW";
        if (protect & PAGE_READONLY) return "R";
        if (protect & PAGE_WRITECOPY) return "RW_C";
        if (protect & PAGE_NOACCESS) return "NA";
        return "?";
    }

    std::string bytes_to_hex(const std::vector<uint8_t>& data, size_t start, size_t count) {
        std::ostringstream oss;
        for (size_t i = 0; i < count && (start + i) < data.size(); ++i) {
            oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(data[start + i]);
            if (i < count - 1) oss << " ";
        }
        return oss.str();
    }

    std::string bytes_to_ida_pattern(const std::vector<uint8_t>& data, size_t start, size_t count, const std::vector<bool>& wildcards = {}) {
        std::ostringstream oss;
        for (size_t i = 0; i < count && (start + i) < data.size(); ++i) {
            if (!wildcards.empty() && i < wildcards.size() && wildcards[i]) {
                oss << "??";
            }
            else {
                oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(data[start + i]);
            }
            if (i < count - 1) oss << " ";
        }
        return oss.str();
    }

    std::string bytes_to_ascii(const std::vector<uint8_t>& data, size_t start, size_t count) {
        std::string result;
        for (size_t i = 0; i < count && (start + i) < data.size(); ++i) {
            uint8_t c = data[start + i];
            result += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
        }
        return result;
    }

    std::string sanitize_name(const std::string& str) {
        std::string result;
        for (char c : str) {
            if (std::isalnum(c) || c == '_') {
                result += c;
            }
            else if (c == ' ' || c == '-' || c == '.') {
                result += '_';
            }
        }
        if (!result.empty() && std::isdigit(result[0])) {
            result = "_" + result;
        }
        return result;
    }

    std::string format_size(size_t size) {
        std::ostringstream oss;
        if (size >= 1024 * 1024) {
            oss << std::fixed << std::setprecision(2) << (size / (1024.0 * 1024.0)) << " MB";
        }
        else if (size >= 1024) {
            oss << std::fixed << std::setprecision(2) << (size / 1024.0) << " KB";
        }
        else {
            oss << size << " B";
        }
        return oss.str();
    }

    std::string generate_unique_name(const std::string& prefix, uintptr_t offset) {
        std::ostringstream oss;
        oss << prefix << "_" << std::hex << std::uppercase << offset;
        return oss.str();
    }

    std::vector<uint8_t> read_region_data(uintptr_t base, size_t size) {
        std::vector<uint8_t> buffer(size);
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(process::g_process.get_handle(), reinterpret_cast<LPCVOID>(base), buffer.data(), buffer.size(), &bytesRead)) {
            buffer.resize(bytesRead);
            return buffer;
        }
        return {};
    }

    void add_found_offset(const std::string& category, const std::string& name, uintptr_t offset, const std::string& desc = "", const std::string& pattern = "") {
        FoundOffset fo;
        fo.category = category;
        fo.name = name;
        fo.offset = offset;
        fo.description = desc;
        fo.pattern = pattern;
        g_found_offsets.push_back(fo);
    }

    void add_auto_pattern(const std::string& name, const std::string& category, uintptr_t offset,
        const std::string& pattern, const std::string& desc, int confidence, const std::string& type) {
        AutoPattern ap;
        ap.name = name;
        ap.category = category;
        ap.offset = offset;
        ap.pattern = pattern;
        ap.description = desc;
        ap.confidence = confidence;
        ap.type = type;
        g_auto_patterns.push_back(ap);
    }

    struct PatternDefinition {
        std::string name_prefix;
        std::string category;
        std::vector<uint8_t> bytes;
        std::vector<bool> mask;
        std::string description;
        int confidence;
        std::string type;
        bool extract_target;
        int target_offset;
    };

    std::vector<PatternDefinition> get_pattern_definitions() {
        return {
            { "func_prologue_save_rbx", "Function", { 0x48, 0x89, 0x5C, 0x24 }, { true, true, true, true }, "Function prologue - save RBX", 90, "function", false, 0 },
            { "func_prologue_sub_rsp", "Function", { 0x48, 0x83, 0xEC }, { true, true, true }, "Function prologue - sub RSP", 85, "function", false, 0 },
            { "func_prologue_push_rbx", "Function", { 0x40, 0x53 }, { true, true }, "Function prologue - push RBX", 80, "function", false, 0 },
            { "func_prologue_push_rbp", "Function", { 0x40, 0x55 }, { true, true }, "Function prologue - push RBP", 80, "function", false, 0 },
            { "func_prologue_mov_rax_rsp", "Function", { 0x48, 0x8B, 0xC4 }, { true, true, true }, "Function prologue - mov RAX, RSP", 85, "function", false, 0 },
            { "func_prologue_push_rbp_mov", "Function", { 0x55, 0x48, 0x8B, 0xEC }, { true, true, true, true }, "Function prologue - push RBP; mov RBP, RSP", 95, "function", false, 0 },
            { "func_prologue_save_rcx", "Function", { 0x48, 0x89, 0x4C, 0x24 }, { true, true, true, true }, "Function prologue - save RCX", 85, "function", false, 0 },
            { "func_prologue_save_rdx", "Function", { 0x48, 0x89, 0x54, 0x24 }, { true, true, true, true }, "Function prologue - save RDX", 85, "function", false, 0 },
            { "func_prologue_save_r8", "Function", { 0x4C, 0x89, 0x44, 0x24 }, { true, true, true, true }, "Function prologue - save R8", 85, "function", false, 0 },
            { "func_prologue_big_stack", "Function", { 0x48, 0x81, 0xEC }, { true, true, true }, "Function prologue - big stack allocation", 90, "function", false, 0 },

            { "lea_rcx_rip", "Reference", { 0x48, 0x8D, 0x0D }, { true, true, true }, "LEA RCX, [RIP+x]", 70, "lea", true, 3 },
            { "lea_rdx_rip", "Reference", { 0x48, 0x8D, 0x15 }, { true, true, true }, "LEA RDX, [RIP+x]", 70, "lea", true, 3 },
            { "lea_rax_rip", "Reference", { 0x48, 0x8D, 0x05 }, { true, true, true }, "LEA RAX, [RIP+x]", 70, "lea", true, 3 },
            { "lea_rbx_rip", "Reference", { 0x48, 0x8D, 0x1D }, { true, true, true }, "LEA RBX, [RIP+x]", 70, "lea", true, 3 },
            { "lea_rsi_rip", "Reference", { 0x48, 0x8D, 0x35 }, { true, true, true }, "LEA RSI, [RIP+x]", 70, "lea", true, 3 },
            { "lea_rdi_rip", "Reference", { 0x48, 0x8D, 0x3D }, { true, true, true }, "LEA RDI, [RIP+x]", 70, "lea", true, 3 },
            { "lea_r8_rip", "Reference", { 0x4C, 0x8D, 0x05 }, { true, true, true }, "LEA R8, [RIP+x]", 70, "lea", true, 3 },
            { "lea_r9_rip", "Reference", { 0x4C, 0x8D, 0x0D }, { true, true, true }, "LEA R9, [RIP+x]", 70, "lea", true, 3 },
            { "lea_r10_rip", "Reference", { 0x4C, 0x8D, 0x15 }, { true, true, true }, "LEA R10, [RIP+x]", 70, "lea", true, 3 },
            { "lea_r11_rip", "Reference", { 0x4C, 0x8D, 0x1D }, { true, true, true }, "LEA R11, [RIP+x]", 70, "lea", true, 3 },

            { "mov_rcx_rip", "DataAccess", { 0x48, 0x8B, 0x0D }, { true, true, true }, "MOV RCX, [RIP+x]", 75, "mov_read", true, 3 },
            { "mov_rdx_rip", "DataAccess", { 0x48, 0x8B, 0x15 }, { true, true, true }, "MOV RDX, [RIP+x]", 75, "mov_read", true, 3 },
            { "mov_rax_rip", "DataAccess", { 0x48, 0x8B, 0x05 }, { true, true, true }, "MOV RAX, [RIP+x]", 75, "mov_read", true, 3 },
            { "mov_rbx_rip", "DataAccess", { 0x48, 0x8B, 0x1D }, { true, true, true }, "MOV RBX, [RIP+x]", 75, "mov_read", true, 3 },
            { "mov_rsi_rip", "DataAccess", { 0x48, 0x8B, 0x35 }, { true, true, true }, "MOV RSI, [RIP+x]", 75, "mov_read", true, 3 },
            { "mov_rdi_rip", "DataAccess", { 0x48, 0x8B, 0x3D }, { true, true, true }, "MOV RDI, [RIP+x]", 75, "mov_read", true, 3 },

            { "mov_rip_rax", "DataAccess", { 0x48, 0x89, 0x05 }, { true, true, true }, "MOV [RIP+x], RAX", 80, "mov_write", true, 3 },
            { "mov_rip_rcx", "DataAccess", { 0x48, 0x89, 0x0D }, { true, true, true }, "MOV [RIP+x], RCX", 80, "mov_write", true, 3 },
            { "mov_rip_rdx", "DataAccess", { 0x48, 0x89, 0x15 }, { true, true, true }, "MOV [RIP+x], RDX", 80, "mov_write", true, 3 },
            { "mov_rip_rbx", "DataAccess", { 0x48, 0x89, 0x1D }, { true, true, true }, "MOV [RIP+x], RBX", 80, "mov_write", true, 3 },

            { "cmp_byte_rip", "Comparison", { 0x80, 0x3D }, { true, true }, "CMP BYTE [RIP+x], imm8", 65, "cmp", true, 2 },
            { "cmp_dword_rip", "Comparison", { 0x83, 0x3D }, { true, true }, "CMP DWORD [RIP+x], imm8", 65, "cmp", true, 2 },
            { "test_byte_rip", "Comparison", { 0xF6, 0x05 }, { true, true }, "TEST BYTE [RIP+x], imm8", 65, "test", true, 2 },

            { "call_near", "Call", { 0xE8 }, { true }, "CALL near", 60, "call", true, 1 },
            { "jmp_near", "Jump", { 0xE9 }, { true }, "JMP near", 60, "jmp", true, 1 },

            { "vtable_ptr", "VTable", { 0x48, 0x8D, 0x05 }, { true, true, true }, "Possible VTable reference", 50, "vtable", true, 3 },

            { "xor_reg_reg", "Crypto", { 0x48, 0x31 }, { true, true }, "XOR r64, r64", 40, "xor", false, 0 },
            { "xor_eax_eax", "Crypto", { 0x33, 0xC0 }, { true, true }, "XOR EAX, EAX (return 0)", 70, "xor", false, 0 },
            { "xor_ecx_ecx", "Crypto", { 0x33, 0xC9 }, { true, true }, "XOR ECX, ECX", 60, "xor", false, 0 },

            { "ret", "Return", { 0xC3 }, { true }, "RET", 50, "ret", false, 0 },
            { "ret_imm16", "Return", { 0xC2 }, { true }, "RET imm16", 50, "ret", false, 0 },

            { "int3", "Debug", { 0xCC }, { true }, "INT3 (breakpoint)", 30, "int3", false, 0 },
            { "nop", "Padding", { 0x90 }, { true }, "NOP", 20, "nop", false, 0 },

            { "movaps_xmm", "SIMD", { 0x0F, 0x28 }, { true, true }, "MOVAPS xmm", 55, "simd", false, 0 },
            { "movups_xmm", "SIMD", { 0x0F, 0x10 }, { true, true }, "MOVUPS xmm", 55, "simd", false, 0 },

            { "string_cmp", "StringOp", { 0xF3, 0xA6 }, { true, true }, "REPE CMPSB", 70, "string", false, 0 },
            { "string_mov", "StringOp", { 0xF3, 0xA4 }, { true, true }, "REP MOVSB", 70, "string", false, 0 },

            { "lock_prefix", "Atomic", { 0xF0 }, { true }, "LOCK prefix", 60, "atomic", false, 0 },

            { "seh_handler", "Exception", { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x05 }, { true, true, true, true, true, true, true }, "Possible SEH handler", 80, "exception", false, 0 },
        };
    }

    struct UniquePattern {
        std::string pattern;
        uintptr_t offset;
        std::string name;
        int ref_count;
        std::string context;
    };

    class PatternScanner {
    private:
        std::unordered_map<std::string, int> pattern_counts;
        std::vector<UniquePattern> unique_patterns;
        std::unordered_set<uintptr_t> scanned_offsets;

    public:
        void scan_all_patterns() {
            auto definitions = get_pattern_definitions();

            logger::info("scanning for {} pattern types...", definitions.size());

            for (const auto& region : g_executable_regions) {
                if (region.data.empty()) continue;

                for (const auto& def : definitions) {
                    scan_pattern_in_region(region, def);
                }
            }

            find_unique_patterns();
            categorize_patterns();
        }

        void scan_pattern_in_region(const MemoryRegion& region, const PatternDefinition& def) {
            if (region.data.size() < def.bytes.size()) return;

            for (size_t i = 0; i + def.bytes.size() + 8 <= region.data.size(); ++i) {
                bool match = true;
                for (size_t j = 0; j < def.bytes.size(); ++j) {
                    if (def.mask[j] && region.data[i + j] != def.bytes[j]) {
                        match = false;
                        break;
                    }
                }

                if (!match) continue;

                bool is_func_boundary = (i == 0 || region.data[i - 1] == 0xCC || region.data[i - 1] == 0xC3);

                if (def.type == "function" && !is_func_boundary) continue;

                uintptr_t offset = (region.base + i) - g_module_base;

                if (scanned_offsets.count(offset)) continue;
                scanned_offsets.insert(offset);

                std::string full_pattern = bytes_to_hex(region.data, i, std::min(static_cast<size_t>(16), region.data.size() - i));

                uintptr_t target_offset = 0;
                if (def.extract_target && i + def.target_offset + 4 <= region.data.size()) {
                    int32_t disp;
                    std::memcpy(&disp, &region.data[i + def.target_offset], sizeof(disp));
                    uintptr_t target = region.base + i + def.target_offset + 4 + disp;

                    if (target >= g_module_base && target < g_module_base + g_module_size) {
                        target_offset = target - g_module_base;
                    }
                }

                std::string name = generate_unique_name(def.name_prefix, offset);
                std::string desc = def.description;

                if (target_offset != 0) {
                    std::ostringstream oss;
                    oss << desc << " -> target: 0x" << std::hex << std::uppercase << target_offset;
                    desc = oss.str();
                }

                add_auto_pattern(name, def.category, offset, full_pattern, desc, def.confidence, def.type);

                pattern_counts[def.name_prefix]++;
            }
        }

        void find_unique_patterns() {
            std::unordered_map<std::string, std::vector<size_t>> pattern_indices;

            for (size_t i = 0; i < g_auto_patterns.size(); ++i) {
                std::string key = g_auto_patterns[i].pattern.substr(0, 23);
                pattern_indices[key].push_back(i);
            }

            for (const auto& [pattern, indices] : pattern_indices) {
                if (indices.size() == 1) {
                    const auto& ap = g_auto_patterns[indices[0]];
                    UniquePattern up;
                    up.pattern = ap.pattern;
                    up.offset = ap.offset;
                    up.name = ap.name;
                    up.ref_count = 1;
                    up.context = ap.description;
                    unique_patterns.push_back(up);
                }
            }

            logger::info("found {} unique patterns out of {}", unique_patterns.size(), g_auto_patterns.size());
        }

        void categorize_patterns() {
            std::map<uintptr_t, int> xref_counts;

            for (const auto& ap : g_auto_patterns) {
                if (ap.type == "call" || ap.type == "jmp") {
                    for (const auto& region : g_executable_regions) {
                        if (region.data.size() < 5) continue;

                        size_t local_offset = (g_module_base + ap.offset) - region.base;
                        if (local_offset >= region.data.size()) continue;

                        int32_t disp;
                        std::memcpy(&disp, &region.data[local_offset + 1], sizeof(disp));
                        uintptr_t target = (g_module_base + ap.offset) + 5 + disp;

                        if (target >= g_module_base && target < g_module_base + g_module_size) {
                            xref_counts[target - g_module_base]++;
                        }
                    }
                }
            }

            std::vector<std::pair<uintptr_t, int>> sorted_xrefs(xref_counts.begin(), xref_counts.end());
            std::sort(sorted_xrefs.begin(), sorted_xrefs.end(), [](const auto& a, const auto& b) {
                return a.second > b.second;
                });

            int hot_func_count = 0;
            for (const auto& [offset, count] : sorted_xrefs) {
                if (count >= 10 && hot_func_count < 100) {
                    std::ostringstream name;
                    name << "hot_function_" << std::hex << std::uppercase << offset;

                    add_found_offset("HotFunction", name.str(), offset,
                        "Frequently called function (" + std::to_string(count) + " refs)");

                    hot_func_count++;
                }
            }
        }

        const std::vector<UniquePattern>& get_unique_patterns() const {
            return unique_patterns;
        }

        void print_statistics() {
            logger::info("pattern scan statistics:");
            for (const auto& [name, count] : pattern_counts) {
                logger::info("  {} : {} matches", name, count);
            }
        }
    };

    class RandomPatternGenerator {
    private:
        std::mt19937 rng;
        std::vector<std::pair<std::string, uintptr_t>> generated_patterns;

    public:
        RandomPatternGenerator() : rng(std::random_device{}()) {}

        void generate_random_patterns(int count) {
            logger::info("generating {} random unique patterns...", count);

            std::set<std::string> seen_patterns;
            int attempts = 0;
            int max_attempts = count * 10;

            while (generated_patterns.size() < static_cast<size_t>(count) && attempts < max_attempts) {
                attempts++;

                if (g_executable_regions.empty()) break;

                std::uniform_int_distribution<size_t> region_dist(0, g_executable_regions.size() - 1);
                const auto& region = g_executable_regions[region_dist(rng)];

                if (region.data.size() < 20) continue;

                std::uniform_int_distribution<size_t> offset_dist(0, region.data.size() - 20);
                size_t local_offset = offset_dist(rng);

                bool at_boundary = (local_offset == 0 ||
                    region.data[local_offset - 1] == 0xCC ||
                    region.data[local_offset - 1] == 0xC3);

                if (!at_boundary) {
                    for (size_t back = 1; back < 16 && local_offset >= back; ++back) {
                        if (region.data[local_offset - back] == 0xCC ||
                            region.data[local_offset - back] == 0xC3) {
                            local_offset = local_offset - back + 1;
                            at_boundary = true;
                            break;
                        }
                    }
                }

                if (!at_boundary) continue;

                std::string pattern = bytes_to_hex(region.data, local_offset, 16);

                if (seen_patterns.count(pattern)) continue;

                bool has_interesting_bytes = false;
                for (size_t i = 0; i < 4 && local_offset + i < region.data.size(); ++i) {
                    uint8_t b = region.data[local_offset + i];
                    if (b == 0x48 || b == 0x4C || b == 0x40 || b == 0x55 ||
                        b == 0xE8 || b == 0xE9 || b == 0x8B || b == 0x8D) {
                        has_interesting_bytes = true;
                        break;
                    }
                }

                if (!has_interesting_bytes) continue;

                seen_patterns.insert(pattern);

                uintptr_t offset = (region.base + local_offset) - g_module_base;
                generated_patterns.push_back({ pattern, offset });

                std::ostringstream name;
                name << "random_pattern_" << std::hex << std::uppercase << offset;

                add_auto_pattern(name.str(), "RandomPattern", offset, pattern,
                    "Randomly discovered pattern", 50, "random");
            }

            logger::info("generated {} random patterns in {} attempts", generated_patterns.size(), attempts);
        }

        std::string create_wildcard_pattern(const std::string& pattern) {
            std::istringstream iss(pattern);
            std::ostringstream oss;
            std::string byte;
            int pos = 0;

            while (iss >> byte) {
                if (pos > 0) oss << " ";

                if (pos >= 3 && pos <= 6) {
                    oss << "??";
                }
                else {
                    oss << byte;
                }
                pos++;
            }

            return oss.str();
        }

        const std::vector<std::pair<std::string, uintptr_t>>& get_generated_patterns() const {
            return generated_patterns;
        }
    };

    class ContextAnalyzer {
    public:
        struct ContextInfo {
            std::string likely_purpose;
            std::vector<std::string> nearby_strings;
            int xref_count;
            bool is_exported;
            std::string call_convention;
        };

        ContextInfo analyze_offset(uintptr_t offset) {
            ContextInfo info;
            info.xref_count = 0;
            info.is_exported = false;
            info.call_convention = "unknown";

            uintptr_t addr = g_module_base + offset;

            for (const auto& region : g_executable_regions) {
                if (region.data.size() < 5) continue;

                for (size_t i = 0; i + 5 <= region.data.size(); ++i) {
                    if (region.data[i] == 0xE8) {
                        int32_t disp;
                        std::memcpy(&disp, &region.data[i + 1], sizeof(disp));
                        uintptr_t target = region.base + i + 5 + disp;
                        if (target == addr) {
                            info.xref_count++;
                        }
                    }
                }
            }

            for (const auto& str : g_found_strings) {
                if (std::abs(static_cast<int64_t>(str.offset) - static_cast<int64_t>(offset)) < 0x1000) {
                    if (info.nearby_strings.size() < 5) {
                        info.nearby_strings.push_back(str.value.substr(0, 50));
                    }
                }
            }

            auto buffer = process::g_process.read_bytes(addr, 16);
            if (buffer.size() >= 4) {
                if (buffer[0] == 0x48 && buffer[1] == 0x89 && buffer[2] == 0x5C) {
                    info.call_convention = "fastcall_save_nonvolatile";
                }
                else if (buffer[0] == 0x48 && buffer[1] == 0x83 && buffer[2] == 0xEC) {
                    info.call_convention = "fastcall_stack_alloc";
                }
                else if (buffer[0] == 0x40 && (buffer[1] == 0x53 || buffer[1] == 0x55)) {
                    info.call_convention = "fastcall_push_reg";
                }
            }

            if (info.xref_count > 50) {
                info.likely_purpose = "Core/Utility function";
            }
            else if (info.xref_count > 20) {
                info.likely_purpose = "Common function";
            }
            else if (info.xref_count > 5) {
                info.likely_purpose = "Regular function";
            }
            else if (info.xref_count > 0) {
                info.likely_purpose = "Rarely called function";
            }
            else {
                info.likely_purpose = "Unused or internal function";
            }

            for (const auto& str : info.nearby_strings) {
                std::string lower = str;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

                if (lower.find("error") != std::string::npos || lower.find("exception") != std::string::npos) {
                    info.likely_purpose = "Error handling";
                    break;
                }
                if (lower.find("lua") != std::string::npos || lower.find("script") != std::string::npos) {
                    info.likely_purpose = "Lua/Script related";
                    break;
                }
                if (lower.find("render") != std::string::npos || lower.find("draw") != std::string::npos) {
                    info.likely_purpose = "Rendering";
                    break;
                }
                if (lower.find("network") != std::string::npos || lower.find("packet") != std::string::npos) {
                    info.likely_purpose = "Networking";
                    break;
                }
                if (lower.find("physics") != std::string::npos || lower.find("collision") != std::string::npos) {
                    info.likely_purpose = "Physics";
                    break;
                }
            }

            return info;
        }
    };

    void scan_strings() {
        std::set<std::string> seen;

        for (const auto& region : g_readable_regions) {
            if (region.data.empty()) continue;

            for (size_t i = 0; i < region.data.size(); ++i) {
                std::string str;
                bool valid = true;

                for (size_t j = i; j < region.data.size() && j < i + 512; ++j) {
                    uint8_t c = region.data[j];
                    if (c == 0) break;
                    if (c >= 32 && c < 127) {
                        str += static_cast<char>(c);
                    }
                    else if (c == '\t' || c == '\n' || c == '\r') {
                        str += ' ';
                    }
                    else {
                        valid = false;
                        break;
                    }
                }

                if (valid && str.length() >= 4 && seen.find(str) == seen.end()) {
                    seen.insert(str);

                    FoundString entry;
                    entry.address = region.base + i;
                    entry.offset = entry.address - g_module_base;
                    entry.value = str;

                    std::string lower = str;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

                    if (lower.find("error") != std::string::npos || lower.find("exception") != std::string::npos) {
                        entry.category = "Error";
                    }
                    else if (lower.find("lua") != std::string::npos || lower.find("script") != std::string::npos) {
                        entry.category = "Lua";
                    }
                    else if (lower.find("roblox") != std::string::npos || lower.find("rbx") != std::string::npos) {
                        entry.category = "Roblox";
                    }
                    else if (lower.find("identity") != std::string::npos || lower.find("security") != std::string::npos) {
                        entry.category = "Security";
                    }
                    else if (lower.find("render") != std::string::npos || lower.find("graphics") != std::string::npos) {
                        entry.category = "Render";
                    }
                    else if (lower.find("physics") != std::string::npos || lower.find("collision") != std::string::npos) {
                        entry.category = "Physics";
                    }
                    else if (lower.find("network") != std::string::npos || lower.find("replicat") != std::string::npos) {
                        entry.category = "Network";
                    }
                    else if (lower.find("debug") != std::string::npos || lower.find("assert") != std::string::npos) {
                        entry.category = "Debug";
                    }
                    else {
                        entry.category = "General";
                    }

                    g_found_strings.push_back(entry);
                    i += str.length();
                }
            }
        }
    }

    void scan_functions() {
        for (const auto& region : g_executable_regions) {
            if (region.data.empty()) continue;

            for (size_t i = 0; i + 16 < region.data.size(); ++i) {
                bool is_func_start = false;

                if (i == 0 || region.data[i - 1] == 0xCC || region.data[i - 1] == 0xC3) {
                    if (region.data[i] == 0x48 && region.data[i + 1] == 0x89 && region.data[i + 2] == 0x5C && region.data[i + 3] == 0x24) {
                        is_func_start = true;
                    }
                    else if (region.data[i] == 0x48 && region.data[i + 1] == 0x83 && region.data[i + 2] == 0xEC) {
                        is_func_start = true;
                    }
                    else if (region.data[i] == 0x40 && region.data[i + 1] == 0x53) {
                        is_func_start = true;
                    }
                    else if (region.data[i] == 0x40 && region.data[i + 1] == 0x55) {
                        is_func_start = true;
                    }
                    else if (region.data[i] == 0x48 && region.data[i + 1] == 0x8B && region.data[i + 2] == 0xC4) {
                        is_func_start = true;
                    }
                    else if (region.data[i] == 0x55 && region.data[i + 1] == 0x48 && region.data[i + 2] == 0x8B && region.data[i + 3] == 0xEC) {
                        is_func_start = true;
                    }
                }

                if (is_func_start) {
                    FoundFunction entry;
                    entry.address = region.base + i;
                    entry.offset = entry.address - g_module_base;

                    std::ostringstream name;
                    name << "sub_" << std::hex << std::uppercase << entry.offset;
                    entry.name = name.str();
                    entry.pattern = bytes_to_hex(region.data, i, 16);

                    size_t func_end = i;
                    for (size_t j = i + 1; j < region.data.size() && j < i + 0x10000; ++j) {
                        if (region.data[j] == 0xC3 || region.data[j] == 0xCC) {
                            func_end = j;
                            break;
                        }
                    }
                    entry.size_estimate = func_end - i;

                    g_found_functions.push_back(entry);
                }
            }
        }
    }

    void scan_xrefs() {
        for (const auto& region : g_executable_regions) {
            if (region.data.size() < 5) continue;

            for (size_t i = 0; i + 5 <= region.data.size(); ++i) {
                if (region.data[i] == 0xE8 || region.data[i] == 0xE9) {
                    int32_t disp;
                    std::memcpy(&disp, &region.data[i + 1], sizeof(disp));
                    uintptr_t target = region.base + i + 5 + disp;

                    if (target >= g_module_base && target < g_module_base + g_module_size) {
                        FoundXref entry;
                        entry.from_offset = (region.base + i) - g_module_base;
                        entry.to_offset = target - g_module_base;
                        entry.type = (region.data[i] == 0xE8) ? "CALL" : "JMP";

                        if (g_found_xrefs.size() < 100000) {
                            g_found_xrefs.push_back(entry);
                        }
                    }
                }
            }
        }
    }

    void dump_offsets_txt() {
        std::ofstream file("dump_offsets.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                         INTERNAL OFFSETS DUMP                                #\n";
        file << "################################################################################\n\n";

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        file << "Generated: " << std::ctime(&time);
        file << "Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n";
        file << "Module Size: 0x" << g_module_size << " (" << format_size(g_module_size) << ")\n\n";

        std::map<std::string, std::vector<FoundOffset>> categorized;
        for (const auto& entry : g_found_offsets) {
            categorized[entry.category].push_back(entry);
        }

        for (const auto& [category, entries] : categorized) {
            file << "================================================================================\n";
            file << "[" << category << "] - " << entries.size() << " offsets\n";
            file << "================================================================================\n";

            for (const auto& entry : entries) {
                file << "  " << std::left << std::setw(45) << std::setfill(' ') << entry.name
                    << " = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << entry.offset;
                if (!entry.description.empty()) {
                    file << "  ; " << entry.description;
                }
                file << "\n";
            }
            file << "\n";
        }

        file.close();
    }

    void dump_auto_patterns_txt() {
        std::ofstream file("dump_auto_patterns.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                         AUTO-DISCOVERED PATTERNS                             #\n";
        file << "################################################################################\n\n";

        file << "Total Patterns: " << std::dec << g_auto_patterns.size() << "\n\n";

        std::map<std::string, std::vector<AutoPattern>> categorized;
        for (const auto& ap : g_auto_patterns) {
            categorized[ap.category].push_back(ap);
        }

        for (const auto& [category, patterns] : categorized) {
            file << "================================================================================\n";
            file << "[" << category << "] - " << patterns.size() << " patterns\n";
            file << "================================================================================\n";

            size_t show = std::min(patterns.size(), static_cast<size_t>(100));
            for (size_t i = 0; i < show; ++i) {
                const auto& ap = patterns[i];
                file << "  " << std::left << std::setw(40) << std::setfill(' ') << ap.name
                    << " = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << ap.offset
                    << "  ; conf:" << std::dec << std::setw(3) << ap.confidence << " " << ap.description << "\n";
                file << "    pattern: " << ap.pattern << "\n";
            }

            if (patterns.size() > 100) {
                file << "  ... and " << std::dec << (patterns.size() - 100) << " more\n";
            }
            file << "\n";
        }

        file.close();
    }

    void dump_unique_patterns_txt(const std::vector<UniquePattern>& unique) {
        std::ofstream file("dump_unique_patterns.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                           UNIQUE PATTERNS                                    #\n";
        file << "#            (Patterns that appear only once - good for signatures)            #\n";
        file << "################################################################################\n\n";

        file << "Total Unique Patterns: " << std::dec << unique.size() << "\n\n";

        for (const auto& up : unique) {
            file << "Name:    " << up.name << "\n";
            file << "Offset:  0x" << std::hex << std::uppercase << up.offset << "\n";
            file << "Pattern: " << up.pattern << "\n";
            file << "Context: " << up.context << "\n";
            file << std::string(60, '-') << "\n";
        }

        file.close();
    }

    void dump_strings_txt() {
        std::ofstream file("dump_strings.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                            STRINGS DUMP                                      #\n";
        file << "################################################################################\n\n";

        file << "Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n";
        file << "Total Strings: " << std::dec << g_found_strings.size() << "\n\n";

        std::map<std::string, std::vector<FoundString>> categorized;
        for (const auto& str : g_found_strings) {
            categorized[str.category].push_back(str);
        }

        for (const auto& [category, entries] : categorized) {
            file << "================================================================================\n";
            file << "[" << category << "] - " << entries.size() << " strings\n";
            file << "================================================================================\n";

            for (const auto& entry : entries) {
                std::string display = entry.value;
                if (display.length() > 80) {
                    display = display.substr(0, 77) + "...";
                }

                file << "  0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << entry.offset
                    << " = \"" << display << "\"\n";
            }
            file << "\n";
        }

        file.close();
    }

    void dump_functions_txt() {
        std::ofstream file("dump_functions.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                           FUNCTIONS DUMP                                     #\n";
        file << "################################################################################\n\n";

        file << "Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n";
        file << "Total Functions: " << std::dec << g_found_functions.size() << "\n\n";

        file << "[FUNCTIONS]\n";
        file << std::string(100, '-') << "\n";

        for (const auto& func : g_found_functions) {
            file << "  " << std::left << std::setw(20) << std::setfill(' ') << func.name
                << " = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << func.offset
                << "  ; size: ~0x" << std::setw(6) << func.size_estimate
                << "  " << func.pattern << "\n";
        }

        file.close();
    }

    void dump_xrefs_txt() {
        std::ofstream file("dump_xrefs.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                             XREFS DUMP                                       #\n";
        file << "################################################################################\n\n";

        file << "Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n";
        file << "Total XRefs: " << std::dec << g_found_xrefs.size() << "\n\n";

        std::map<uintptr_t, int> ref_counts;
        for (const auto& xref : g_found_xrefs) {
            ref_counts[xref.to_offset]++;
        }

        std::vector<std::pair<uintptr_t, int>> sorted(ref_counts.begin(), ref_counts.end());
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
            });

        file << "[MOST REFERENCED]\n";
        file << std::string(60, '-') << "\n";

        size_t show = std::min(sorted.size(), static_cast<size_t>(100));
        for (size_t i = 0; i < show; ++i) {
            file << "  target_" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << sorted[i].first
                << " = 0x" << sorted[i].first
                << "  ; " << std::dec << sorted[i].second << " refs\n";
        }

        file.close();
    }

    void dump_regions_txt() {
        std::ofstream file("dump_regions.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                            REGIONS DUMP                                      #\n";
        file << "################################################################################\n\n";

        file << "Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n";
        file << "Module Size: 0x" << g_module_size << " (" << format_size(g_module_size) << ")\n\n";

        file << "[STATISTICS]\n";
        file << "  Total Regions:      " << std::dec << g_all_regions.size() << "\n";
        file << "  Executable Regions: " << g_executable_regions.size() << "\n";
        file << "  Readable Regions:   " << g_readable_regions.size() << "\n\n";

        file << "[ALL REGIONS]\n";
        file << std::string(90, '-') << "\n";

        int idx = 0;
        for (const auto& region : g_all_regions) {
            file << "  region_" << std::dec << std::setw(4) << std::setfill('0') << idx++
                << " = { offset: 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << (region.base - g_module_base)
                << ", size: 0x" << std::setw(8) << region.size
                << ", protect: " << std::setw(6) << std::setfill(' ') << protect_to_str(region.protect)
                << " }\n";
        }

        file.close();
    }

    void dump_header_hpp() {
        std::ofstream file("dump_offsets.hpp");
        if (!file.is_open()) return;

        file << "#pragma once\n\n";
        file << "// Auto-generated offsets header\n";
        file << "// Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n\n";

        file << "#include <cstdint>\n\n";

        file << "namespace offsets {\n\n";

        file << "    constexpr uintptr_t MODULE_SIZE = 0x" << std::hex << std::uppercase << g_module_size << ";\n\n";

        std::map<std::string, std::vector<FoundOffset>> categorized;
        for (const auto& entry : g_found_offsets) {
            categorized[entry.category].push_back(entry);
        }

        for (const auto& [category, entries] : categorized) {
            std::string ns_name = sanitize_name(category);
            if (ns_name.empty()) ns_name = "misc";

            file << "    namespace " << ns_name << " {\n";

            for (const auto& entry : entries) {
                std::string var_name = sanitize_name(entry.name);
                if (var_name.empty()) continue;

                file << "        constexpr uintptr_t " << var_name
                    << " = 0x" << std::hex << std::uppercase << entry.offset << ";";

                if (!entry.description.empty()) {
                    file << " // " << entry.description;
                }
                file << "\n";
            }

            file << "    }\n\n";
        }

        file << "    namespace AutoPatterns {\n";
        int pattern_count = 0;
        for (const auto& ap : g_auto_patterns) {
            if (pattern_count++ >= 500) break;
            if (ap.confidence < 70) continue;

            std::string var_name = sanitize_name(ap.name);
            file << "        constexpr uintptr_t " << var_name
                << " = 0x" << std::hex << std::uppercase << ap.offset << ";\n";
        }
        file << "    }\n\n";

        file << "    namespace Strings {\n";
        int str_count = 0;
        for (const auto& str : g_found_strings) {
            if (str_count++ >= 200) break;
            std::string name = sanitize_name(str.value.substr(0, 30));
            if (name.empty() || name.length() < 3) continue;

            file << "        constexpr uintptr_t str_" << name
                << " = 0x" << std::hex << std::uppercase << str.offset << ";\n";
        }
        file << "    }\n\n";

        file << "    namespace Functions {\n";
        int func_count = 0;
        for (const auto& func : g_found_functions) {
            if (func_count++ >= 200) break;
            file << "        constexpr uintptr_t " << func.name
                << " = 0x" << std::hex << std::uppercase << func.offset << ";\n";
        }
        file << "    }\n\n";

        file << "}\n";

        file.close();
    }

    void dump_json() {
        std::ofstream file("dump_offsets.json");
        if (!file.is_open()) return;

        file << "{\n";

        file << "  \"module\": {\n";
        file << "    \"base\": \"0x" << std::hex << std::uppercase << g_module_base << "\",\n";
        file << "    \"size\": \"0x" << g_module_size << "\",\n";
        file << "    \"size_readable\": \"" << format_size(g_module_size) << "\"\n";
        file << "  },\n\n";

        file << "  \"statistics\": {\n";
        file << "    \"total_regions\": " << std::dec << g_all_regions.size() << ",\n";
        file << "    \"executable_regions\": " << g_executable_regions.size() << ",\n";
        file << "    \"readable_regions\": " << g_readable_regions.size() << ",\n";
        file << "    \"offsets_found\": " << g_found_offsets.size() << ",\n";
        file << "    \"auto_patterns_found\": " << g_auto_patterns.size() << ",\n";
        file << "    \"strings_found\": " << g_found_strings.size() << ",\n";
        file << "    \"functions_found\": " << g_found_functions.size() << ",\n";
        file << "    \"xrefs_found\": " << g_found_xrefs.size() << "\n";
        file << "  },\n\n";

        file << "  \"offsets\": {\n";
        bool first = true;
        for (const auto& entry : g_found_offsets) {
            if (!first) file << ",\n";
            first = false;

            file << "    \"" << entry.name << "\": {\n";
            file << "      \"offset\": \"0x" << std::hex << std::uppercase << entry.offset << "\",\n";
            file << "      \"category\": \"" << entry.category << "\"";
            if (!entry.description.empty()) {
                file << ",\n      \"description\": \"" << entry.description << "\"";
            }
            if (!entry.pattern.empty()) {
                file << ",\n      \"pattern\": \"" << entry.pattern << "\"";
            }
            file << "\n    }";
        }
        file << "\n  },\n\n";

        file << "  \"auto_patterns\": [\n";
        first = true;
        int count = 0;
        for (const auto& ap : g_auto_patterns) {
            if (count++ >= 1000) break;
            if (!first) file << ",\n";
            first = false;

            file << "    {\n";
            file << "      \"name\": \"" << ap.name << "\",\n";
            file << "      \"offset\": \"0x" << std::hex << std::uppercase << ap.offset << "\",\n";
            file << "      \"category\": \"" << ap.category << "\",\n";
            file << "      \"pattern\": \"" << ap.pattern << "\",\n";
            file << "      \"confidence\": " << std::dec << ap.confidence << ",\n";
            file << "      \"type\": \"" << ap.type << "\"\n";
            file << "    }";
        }
        file << "\n  ],\n\n";

        file << "  \"strings\": [\n";
        first = true;
        count = 0;
        for (const auto& str : g_found_strings) {
            if (count++ >= 500) break;
            if (!first) file << ",\n";
            first = false;

            std::string escaped = str.value;
            for (size_t i = 0; i < escaped.size(); ++i) {
                if (escaped[i] == '"' || escaped[i] == '\\') {
                    escaped.insert(i, "\\");
                    i++;
                }
                else if (escaped[i] == '\n' || escaped[i] == '\r' || escaped[i] == '\t') {
                    escaped[i] = ' ';
                }
            }

            file << "    {\n";
            file << "      \"offset\": \"0x" << std::hex << std::uppercase << str.offset << "\",\n";
            file << "      \"category\": \"" << str.category << "\",\n";
            file << "      \"value\": \"" << escaped.substr(0, 100) << "\"\n";
            file << "    }";
        }
        file << "\n  ]\n";

        file << "}\n";

        file.close();
    }

    void dump_summary_txt() {
        std::ofstream file("dump_summary.txt");
        if (!file.is_open()) return;

        file << "################################################################################\n";
        file << "#                            DUMP SUMMARY                                      #\n";
        file << "################################################################################\n\n";

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        file << "Generated: " << std::ctime(&time) << "\n";

        file << "[MODULE]\n";
        file << "  module_base         = 0x" << std::hex << std::uppercase << g_module_base << "\n";
        file << "  module_size         = 0x" << g_module_size << " (" << format_size(g_module_size) << ")\n";
        file << "  module_end          = 0x" << (g_module_base + g_module_size) << "\n\n";

        file << "[STATISTICS]\n";
        file << "  total_regions       = " << std::dec << g_all_regions.size() << "\n";
        file << "  executable_regions  = " << g_executable_regions.size() << "\n";
        file << "  readable_regions    = " << g_readable_regions.size() << "\n";
        file << "  offsets_found       = " << g_found_offsets.size() << "\n";
        file << "  auto_patterns       = " << g_auto_patterns.size() << "\n";
        file << "  strings_found       = " << g_found_strings.size() << "\n";
        file << "  functions_found     = " << g_found_functions.size() << "\n";
        file << "  xrefs_found         = " << g_found_xrefs.size() << "\n\n";

        file << "[OUTPUT FILES]\n";
        file << "  dump_offsets.txt        - Named offsets\n";
        file << "  dump_auto_patterns.txt  - Auto-discovered patterns\n";
        file << "  dump_unique_patterns.txt- Unique patterns (good for sigs)\n";
        file << "  dump_strings.txt        - All strings\n";
        file << "  dump_functions.txt      - Detected functions\n";
        file << "  dump_xrefs.txt          - Cross references\n";
        file << "  dump_regions.txt        - Memory regions\n";
        file << "  dump_offsets.hpp        - C++ header\n";
        file << "  dump_offsets.json       - JSON format\n";
        file << "  dump_summary.txt        - This file\n\n";

        file << "[FOUND OFFSETS]\n";
        file << std::string(70, '-') << "\n";

        for (const auto& entry : g_found_offsets) {
            file << "  " << std::left << std::setw(40) << std::setfill(' ') << entry.name
                << " = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << entry.offset
                << "  [" << entry.category << "]\n";
        }

        file << "\n[HIGH CONFIDENCE AUTO PATTERNS]\n";
        file << std::string(70, '-') << "\n";

        int pattern_shown = 0;
        for (const auto& ap : g_auto_patterns) {
            if (ap.confidence >= 80 && pattern_shown < 50) {
                file << "  " << std::left << std::setw(40) << std::setfill(' ') << ap.name
                    << " = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << ap.offset
                    << "  conf:" << std::dec << ap.confidence << "\n";
                pattern_shown++;
            }
        }

        file.close();
    }

    void dump_all_files() {
        logger::info("dumping all memory data to files...");

        scan_strings();
        scan_functions();
        scan_xrefs();

        PatternScanner scanner;
        scanner.scan_all_patterns();
        scanner.print_statistics();

        RandomPatternGenerator random_gen;
        random_gen.generate_random_patterns(100);

        dump_offsets_txt();
        dump_auto_patterns_txt();
        dump_unique_patterns_txt(scanner.get_unique_patterns());
        dump_strings_txt();
        dump_functions_txt();
        dump_xrefs_txt();
        dump_regions_txt();
        dump_header_hpp();
        dump_json();
        dump_summary_txt();

        logger::info("dump complete: {} offsets, {} auto patterns, {} strings, {} functions, {} xrefs",
            g_found_offsets.size(), g_auto_patterns.size(), g_found_strings.size(),
            g_found_functions.size(), g_found_xrefs.size());
    }

    bool init_memory_regions() {
        std::lock_guard<std::mutex> lock(memoryMutex);

        g_all_regions.clear();
        g_executable_regions.clear();
        g_readable_regions.clear();
        g_found_offsets.clear();
        g_found_strings.clear();
        g_found_functions.clear();
        g_found_xrefs.clear();
        g_auto_patterns.clear();

        auto base = process::g_process.get_module_base();
        auto dos = process::g_process.read<IMAGE_DOS_HEADER>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto nt = process::g_process.read<IMAGE_NT_HEADERS64>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;

        g_module_base = base;
        g_module_size = nt->OptionalHeader.SizeOfImage;

        uintptr_t current = base;
        uintptr_t end = base + g_module_size;
        MEMORY_BASIC_INFORMATION mbi{};

        while (current < end) {
            if (!VirtualQueryEx(process::g_process.get_handle(), reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi)))
                break;

            if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
                MemoryRegion region;
                region.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.protect = mbi.Protect;
                region.data = read_region_data(region.base, region.size);

                g_all_regions.push_back(region);

                if (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    g_executable_regions.push_back(region);
                }

                if (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                    g_readable_regions.push_back(region);
                }
            }

            current = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return !g_all_regions.empty();
    }

    std::vector<uint8_t> read_region(const MemoryRegion& region) {
        return region.data;
    }

    struct CodePattern {
        uintptr_t lea = 0;
        uintptr_t callBefore = 0;
        uintptr_t callAfter = 0;
        uintptr_t mov = 0;
        uintptr_t movTarget = 0;
        uintptr_t offsets = 0;
        uintptr_t leaTarget = 0;
    };

    uintptr_t findStringInMemory(const std::string& searchStr, bool caseInsensitive = false) {
        std::vector<char> searchPattern(searchStr.begin(), searchStr.end());

        if (caseInsensitive) {
            std::transform(searchPattern.begin(), searchPattern.end(), searchPattern.begin(), ::tolower);
        }

        for (const auto& region : g_readable_regions) {
            auto buffer = read_region(region);
            if (buffer.size() < searchStr.size()) continue;

            std::vector<uint8_t> searchBuf = buffer;
            if (caseInsensitive) {
                std::transform(searchBuf.begin(), searchBuf.end(), searchBuf.begin(), ::tolower);
            }

            auto it = std::search(
                searchBuf.begin(), searchBuf.end(),
                searchPattern.begin(), searchPattern.end()
            );

            if (it != searchBuf.end()) {
                return region.base + std::distance(searchBuf.begin(), it);
            }
        }

        return 0;
    }

    uintptr_t get_function_start(uintptr_t addr) {
        auto buffer = process::g_process.read_bytes(addr - 0x500, 0x500);
        if (buffer.empty()) return addr;

        for (std::size_t i = buffer.size(); i > 0; --i) {
            if (buffer[i - 1] == 0xCC || buffer[i - 1] == 0xC3) {
                return addr - 0x500 + i;
            }
        }
        return addr;
    }

    std::vector<uintptr_t> scan_for_xrefs_addr(uintptr_t target) {
        std::vector<uintptr_t> results;

        for (const auto& region : g_executable_regions) {
            auto buffer = read_region(region);
            if (buffer.size() < 4) continue;

            for (size_t i = 0; i + 4 <= buffer.size(); ++i) {
                int32_t disp;
                std::memcpy(&disp, &buffer[i], sizeof(disp));
                uintptr_t resolved = region.base + i + 4 + disp;

                if (resolved == target) {
                    results.push_back(region.base + i);
                }
            }
        }

        return results;
    }

    int32_t getRel32(const std::vector<uint8_t>& buf, size_t offset) {
        if (offset + 4 > buf.size()) return 0;
        int32_t val;
        std::memcpy(&val, &buf[offset], sizeof(val));
        return val;
    }

    CodePattern findLeaCallPattern(const std::string& searchStr, uintptr_t stringAddress, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int mov = 0, const std::string& info = "") {
        CodePattern result;
        size_t callScanRange = 0x300;

        auto findNearbyCall = [&](const std::vector<uint8_t>& buf, size_t startOffset, size_t range, bool forward = true, int skip = 0) -> size_t {
            size_t index = startOffset;
            size_t checked = 0;
            size_t skipped = 0;

            while ((forward ? index < buf.size() - 5 : index >= 5) && checked < range) {
                if (buf[index] == 0xE8) {
                    if (static_cast<int>(skipped++) < skip) {
                        index += forward ? 1 : -1;
                        ++checked;
                        continue;
                    }
                    return index;
                }
                index += forward ? 1 : -1;
                ++checked;
            }
            return 0;
            };

        for (const auto& region : g_executable_regions) {
            auto buffer = read_region(region);
            if (buffer.size() < 7) continue;

            for (size_t i = 0; i + 7 < buffer.size(); ++i) {
                if (opcode != 0 && buffer[i] != static_cast<uint8_t>(opcode)) continue;

                uintptr_t leaAddr = region.base + i;
                int32_t displacement = getRel32(buffer, i + 3);
                uintptr_t targetAddr = leaAddr + 7 + displacement;

                if (targetAddr != stringAddress) continue;

                result.lea = leaAddr;

                if (info.starts_with("FFlag")) {
                    size_t functionStart = i;
                    while (functionStart > 5 && !(buffer[functionStart] == 0x48 && buffer[functionStart + 1] == 0x83 && buffer[functionStart + 2] == 0xEC)) {
                        functionStart--;
                    }

                    for (size_t j = functionStart; j + 7 < buffer.size(); ++j) {
                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x8B && buffer[j + 2] == 0x0D) {
                            int32_t rel = getRel32(buffer, j + 3);
                            uintptr_t rip = region.base + j + 7;
                            uintptr_t absAddr = rip + rel;

                            result.mov = region.base + j;
                            result.movTarget = absAddr;
                        }

                        if (buffer[j] == 0x4C && buffer[j + 1] == 0x8D && buffer[j + 2] == 0x05) {
                            int32_t rel = getRel32(buffer, j + 3);
                            uintptr_t instrAddr = region.base + j;
                            uintptr_t rip = instrAddr + 7;
                            uintptr_t absAddr = rip + rel;

                            if (absAddr > g_module_base && absAddr < g_module_base + g_module_size) {
                                result.leaTarget = absAddr;
                            }
                        }

                        if (result.movTarget && result.leaTarget)
                            break;
                    }
                }

                if (info == "mov_cs_qword") {
                    size_t searchStart = (i > 0x100) ? i - 0x100 : 0;
                    size_t searchEnd = std::min(i + 0x100, buffer.size() - 7);

                    for (size_t j = searchStart; j < searchEnd; ++j) {
                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x89 && buffer[j + 2] == 0x05) {
                            int32_t rel = getRel32(buffer, j + 3);
                            uintptr_t movInstr = region.base + j;
                            uintptr_t rip = movInstr + 7;
                            uintptr_t targetAddr2 = rip + rel;

                            result.mov = movInstr;
                            result.movTarget = targetAddr2;
                            return result;
                        }
                    }
                }

                if (searchStr.starts_with("Maximum")) {
                    int skipCount = 0;
                    for (size_t j = i; j >= 2; --j) {
                        if (buffer[j - 2] == 0x48) {
                            if (skipCount < 17) {
                                ++skipCount;
                                continue;
                            }
                            result.movTarget = region.base + j - 2;
                            break;
                        }
                    }
                }

                if (mov > 0) {
                    size_t skippedMov = 0;
                    for (size_t j = 0; j + 6 < buffer.size(); ++j) {
                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x89 && buffer[j + 2] == 0x05) {
                            uintptr_t movAddr = region.base + j;
                            int32_t disp = getRel32(buffer, j + 3);
                            uintptr_t movTarget = movAddr + 7 + disp;

                            if (skippedMov < static_cast<size_t>(mov)) {
                                skippedMov++;
                                continue;
                            }

                            result.mov = movAddr;
                            result.movTarget = movTarget;
                            break;
                        }
                    }
                }

                if (skipCallUp > 0) {
                    size_t callOffsetUp = findNearbyCall(buffer, i, callScanRange, false, skipCallUp);
                    if (callOffsetUp) {
                        result.callBefore = region.base + callOffsetUp + 5 + getRel32(buffer, callOffsetUp + 1);
                        return result;
                    }
                }

                if (skipCallDown > 0) {
                    size_t callOffsetDown = findNearbyCall(buffer, i + 7, callScanRange, true, skipCallDown);
                    if (callOffsetDown) {
                        result.callAfter = region.base + callOffsetDown + 5 + getRel32(buffer, callOffsetDown + 1);
                        return result;
                    }
                }

                return result;
            }
        }

        return result;
    }

    uintptr_t Xrefs_scan(const std::string& searchStr, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int mov = 0, const std::string& info = "") {
        uintptr_t stringAddr = findStringInMemory(searchStr);
        if (!stringAddr) {
            return 0;
        }

        CodePattern pattern = findLeaCallPattern(searchStr, stringAddr, opcode, skipCallDown, skipCallUp, mov, info);

        if (pattern.leaTarget) {
            return pattern.leaTarget;
        }
        if (searchStr.starts_with("Cluster") || searchStr.starts_with("cannot") || searchStr.starts_with("Maximum") || pattern.movTarget) {
            return pattern.movTarget;
        }
        else if (pattern.callAfter) {
            return pattern.callAfter;
        }
        else if (pattern.callBefore) {
            return pattern.callBefore;
        }
        else if (pattern.offsets) {
            return pattern.offsets;
        }

        return 0;
    }

    std::pair<std::vector<char>, std::string> hexStringToPattern(const std::string& hexPattern) {
        std::vector<char> bytes;
        std::string mask;
        std::istringstream stream(hexPattern);
        std::string byteString;

        while (stream >> byteString) {
            if (byteString == "?" || byteString == "??") {
                bytes.push_back(0x00);
                mask += '?';
            }
            else {
                bytes.push_back(static_cast<char>(strtol(byteString.c_str(), nullptr, 16)));
                mask += 'x';
            }
        }
        return { bytes, mask };
    }

    uintptr_t fastfindPattern(const std::string& hexPattern, bool extractOffset = false, const std::string& OffsetType = "dword") {
        auto [pattern, mask] = hexStringToPattern(hexPattern);
        if (pattern.empty() || pattern.size() != mask.size()) return 0;

        HANDLE hProc = process::g_process.get_handle();
        if (!hProc || hProc == INVALID_HANDLE_VALUE) return 0;

        for (const auto& region : g_executable_regions) {
            auto buffer = read_region(region);
            if (buffer.size() < pattern.size()) continue;

            for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
                bool match = true;

                for (size_t j = 0; j < pattern.size(); ++j) {
                    if (mask[j] == 'x' && buffer[i + j] != static_cast<uint8_t>(pattern[j])) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    uintptr_t result = region.base + i;

                    if (extractOffset) {
                        int32_t rel = 0;
                        uintptr_t offsetAddr = result + 3;

                        if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(offsetAddr), &rel, sizeof(rel), nullptr))
                            continue;

                        uintptr_t finalOffset;
                        if (OffsetType == "byte") {
                            finalOffset = result + rel + 7;
                        }
                        else {
                            finalOffset = offsetAddr + rel + sizeof(rel);
                        }

                        if (finalOffset >= g_module_base && finalOffset < g_module_base + g_module_size)
                            return finalOffset;
                    }
                    else {
                        return result;
                    }
                }
            }
        }

        return 0;
    }

    uintptr_t find_luad_throw() {
        uintptr_t str_addr = findStringInMemory("error in error handling");
        if (!str_addr) return 0;

        auto xrefs = scan_for_xrefs_addr(str_addr);
        if (xrefs.empty()) return 0;

        for (auto xref : xrefs) {
            auto bytes = process::g_process.read_bytes(xref - 3, 10);
            if (bytes.size() >= 10) {
                for (size_t i = 0; i < 4; ++i) {
                    if ((bytes[i] == 0x48 || bytes[i] == 0x4C) && bytes[i + 1] == 0x8D) {
                        auto func_start = get_function_start(xref);
                        return func_start;
                    }
                }
            }
        }

        return 0;
    }

    std::pair<uintptr_t, uintptr_t> find_lua_globals() {
        uintptr_t str_addr = findStringInMemory("Attempt to migrate WeakObjectRef across VM boundary");
        if (!str_addr) return { 0, 0 };

        auto xrefs = scan_for_xrefs_addr(str_addr);
        if (xrefs.empty()) return { 0, 0 };

        for (auto xref : xrefs) {
            auto func_start = get_function_start(xref);
            auto buffer = process::g_process.read_bytes(func_start, 0x800);
            if (buffer.empty()) continue;

            uintptr_t luah_dummynode = 0;
            uintptr_t luao_nilobject = 0;

            for (size_t i = 0; i + 7 < buffer.size(); ++i) {
                if ((buffer[i] == 0x48 || buffer[i] == 0x4C) && buffer[i + 1] == 0x8D) {
                    int32_t rel;
                    std::memcpy(&rel, &buffer[i + 3], sizeof(rel));
                    uintptr_t target = func_start + i + 7 + rel;

                    if (target < g_module_base || target > g_module_base + g_module_size) continue;

                    if (!luah_dummynode) {
                        luah_dummynode = target;
                    }
                    else if (!luao_nilobject && target != luah_dummynode) {
                        luao_nilobject = target;
                        break;
                    }
                }
            }

            if (luah_dummynode && luao_nilobject) {
                return { luah_dummynode, luao_nilobject };
            }
        }

        return { 0, 0 };
    }

    uintptr_t find_print_function() {
        uintptr_t str_addr = findStringInMemory("Current identity is %d");
        if (!str_addr) return 0;

        auto xrefs = scan_for_xrefs_addr(str_addr);
        if (xrefs.empty()) return 0;

        for (auto xref : xrefs) {
            auto func_start = get_function_start(xref);
            auto buffer = process::g_process.read_bytes(func_start, 0x300);
            if (buffer.empty()) continue;

            size_t xref_offset_in_func = xref - func_start;

            for (size_t i = xref_offset_in_func; i < buffer.size() - 5; ++i) {
                if (buffer[i] == 0xE8) {
                    int32_t rel;
                    std::memcpy(&rel, &buffer[i + 1], sizeof(rel));

                    uintptr_t call_addr = func_start + i;
                    uintptr_t target = call_addr + 5 + rel;

                    if (target > g_module_base && target < g_module_base + g_module_size) {
                        return target;
                    }
                }
            }
        }

        return 0;
    }

    uintptr_t find_getidentitystruct() {
        uintptr_t str_addr = findStringInMemory("Current identity is %d");
        if (!str_addr) return 0;

        auto xrefs = scan_for_xrefs_addr(str_addr);
        if (xrefs.empty()) return 0;

        for (auto xref : xrefs) {
            auto func_start = get_function_start(xref);
            auto buffer = process::g_process.read_bytes(func_start, 0x100);
            if (buffer.empty()) continue;

            for (size_t i = 0; i < buffer.size() - 5; ++i) {
                if (buffer[i] == 0xE8) {
                    int32_t rel;
                    std::memcpy(&rel, &buffer[i + 1], sizeof(rel));

                    uintptr_t call_addr = func_start + i;
                    uintptr_t target = call_addr + 5 + rel;

                    if (target > g_module_base && target < g_module_base + g_module_size) {
                        return target;
                    }
                }
            }
        }

        return 0;
    }

    uintptr_t find_identityptr() {
        uintptr_t str_addr = findStringInMemory("Current identity is %d");
        if (!str_addr) return 0;

        auto xrefs = scan_for_xrefs_addr(str_addr);
        if (xrefs.empty()) return 0;

        for (auto xref : xrefs) {
            auto func_start = get_function_start(xref);
            auto buffer = process::g_process.read_bytes(func_start, 0x100);
            if (buffer.empty()) continue;

            for (size_t i = 0; i < buffer.size() - 7; ++i) {
                if (buffer[i] == 0x48 && buffer[i + 1] == 0x8B && buffer[i + 2] == 0x0D) {
                    int32_t rel;
                    std::memcpy(&rel, &buffer[i + 3], sizeof(rel));

                    uintptr_t instr_addr = func_start + i;
                    uintptr_t target = instr_addr + 7 + rel;

                    if (target > g_module_base && target < g_module_base + g_module_size) {
                        return target;
                    }
                }
            }
        }

        return 0;
    }

    uintptr_t find_ktable() {
        uintptr_t str_addr = findStringInMemory("Trying to call method on object of type: `%s` with incorrect arguments.");
        if (!str_addr) return 0;

        auto xrefs = scan_for_xrefs_addr(str_addr);
        if (xrefs.empty()) return 0;

        for (auto xref : xrefs) {
            auto func_start = get_function_start(xref);
            auto buffer = process::g_process.read_bytes(func_start, 0x500);
            if (buffer.empty()) continue;

            for (size_t i = 0; i + 7 <= buffer.size(); ++i) {
                if (buffer[i] == 0x48 && buffer[i + 1] == 0x8D && buffer[i + 2] == 0x0D) {
                    int32_t disp;
                    std::memcpy(&disp, &buffer[i + 3], sizeof(disp));
                    uintptr_t addr = func_start + i + 7 + disp;

                    if (addr > g_module_base && addr < g_module_base + g_module_size) {
                        return addr;
                    }
                }
            }
        }

        return 0;
    }

}

namespace internal {

    auto internal() -> bool {
        logger::info("scanning internal addresses...");

        if (!init_memory_regions()) {
            logger::error("failed to initialize memory regions");
            return false;
        }

        logger::info("regions: {} total, {} executable, {} readable",
            g_all_regions.size(), g_executable_regions.size(), g_readable_regions.size());

        std::size_t found = 0;
        auto base = g_module_base;

        struct StringScan {
            std::string str;
            std::string name;
            int opcode;
            int skip_down;
            int skip_up;
            int mov;
            std::string info;
            std::string description;
        };

        std::vector<StringScan> string_scans = {
            { "oldResult, moduleRef", "luavm_load", 0x48, 12, 0, 0, "", "LuaVM load function" },
            { "Script Start", "getglobalstate_forinstance", 0x48, 0, 1, 0, "", "Get global state for instance" },
            { "EnableLoadModule", "enable_load_module", 0x48, 1, 0, 0, "FFlag", "FFlag EnableLoadModule" },
            { "DebugCheckRenderThreading", "debug_check_render_threading", 0x48, 1, 0, 0, "FFlag", "FFlag DebugCheckRenderThreading" },
            { "RenderDebugCheckThreading2", "render_debug_check_threading2", 0x48, 1, 0, 0, "FFlag", "FFlag RenderDebugCheckThreading2" },
            { "DisableCorescriptLoadstring", "disable_corescript_loadstring", 0x48, 1, 0, 0, "FFlag", "FFlag DisableCorescriptLoadstring" },
            { "LockViolationInstanceCrash", "lock_violation_instance_crash", 0x48, 1, 0, 0, "FFlag", "FFlag LockViolationInstanceCrash" },
            { "LockViolationScriptCrash", "lock_violation_script_crash", 0x48, 1, 0, 0, "FFlag", "FFlag LockViolationScriptCrash" },
            { "LuaStepIntervalMsOverrideEnabled", "lua_step_interval_ms_override", 0x48, 1, 0, 0, "FFlag", "FFlag LuaStepIntervalMsOverrideEnabled" },
            { "TaskSchedulerTargetFps", "task_scheduler_target_fps", 0x48, 1, 0, 0, "FFlag", "FFlag TaskSchedulerTargetFps" },
            { "WndProcessCheck", "wnd_process_check", 0x48, 1, 0, 0, "FFlag", "FFlag WndProcessCheck" },
            { "HumanoidParallelManagerTaskQueue", "raw_scheduler", 0, 0, 0, 0, "mov_cs_qword", "Raw task scheduler pointer" },
            { "Maximum re-entrancy depth (%i) exceeded", "getscheduler", 0, 0, 0, 0, "Maximum", "Get scheduler function" },
            { "new overlap in different world", "firetouchinterest", 0, 0, 0, 0, "", "Fire touch interest function" },
        };

        for (const auto& scan : string_scans) {
            auto addr = Xrefs_scan(scan.str, scan.opcode, scan.skip_down, scan.skip_up, scan.mov, scan.info);

            if (addr != 0) {
                std::uintptr_t offset = addr - base;
                dumper::g_dumper.add_offset("Internal", scan.name, offset);
                add_found_offset("Internal", scan.name, offset, scan.description);
                logger::info("  {} -> 0x{:X}", scan.name, offset);
                found++;
            }
            else {
                logger::warn("  {} -> not found", scan.name);
            }
        }

        auto print_addr = find_print_function();
        if (print_addr) {
            std::uintptr_t offset = print_addr - base;
            dumper::g_dumper.add_offset("Internal", "print", offset);
            add_found_offset("Internal", "print", offset, "Print function");
            logger::info("  print -> 0x{:X}", offset);
            found++;
        }
        else {
            logger::warn("  print -> not found");
        }

        auto getidentitystruct = find_getidentitystruct();
        if (getidentitystruct) {
            std::uintptr_t offset = getidentitystruct - base;
            dumper::g_dumper.add_offset("Internal", "getidentitystruct", offset);
            add_found_offset("Internal", "getidentitystruct", offset, "Get identity struct function");
            logger::info("  getidentitystruct -> 0x{:X}", offset);
            found++;
        }
        else {
            logger::warn("  getidentitystruct -> not found");
        }

        auto identityptr = find_identityptr();
        if (identityptr) {
            std::uintptr_t offset = identityptr - base;
            dumper::g_dumper.add_offset("Internal", "identityptr", offset);
            add_found_offset("Internal", "identityptr", offset, "Identity pointer");
            logger::info("  identityptr -> 0x{:X}", offset);
            found++;
        }
        else {
            logger::warn("  identityptr -> not found");
        }

        auto ktable = find_ktable();
        if (ktable) {
            std::uintptr_t offset = ktable - base;
            dumper::g_dumper.add_offset("Internal", "ktable", offset);
            add_found_offset("Internal", "ktable", offset, "K table pointer");
            logger::info("  ktable -> 0x{:X}", offset);
            found++;
        }
        else {
            logger::warn("  ktable -> not found");
        }

        auto luad_throw = find_luad_throw();
        if (luad_throw) {
            std::uintptr_t offset = luad_throw - base;
            dumper::g_dumper.add_offset("Internal", "luad_throw", offset);
            add_found_offset("Internal", "luad_throw", offset, "Lua D throw function");
            logger::info("  luad_throw -> 0x{:X}", offset);
            found++;
        }
        else {
            logger::warn("  luad_throw -> not found");
        }

        auto [luah_dummynode, luao_nilobject] = find_lua_globals();
        if (luah_dummynode) {
            std::uintptr_t offset = luah_dummynode - base;
            dumper::g_dumper.add_offset("Internal", "luah_dummynode", offset);
            add_found_offset("Internal", "luah_dummynode", offset, "Lua H dummy node");
            logger::info("  luah_dummynode -> 0x{:X}", offset);
            found++;
        }
        else {
            logger::warn("  luah_dummynode -> not found");
        }

        if (luao_nilobject) {
            std::uintptr_t offset = luao_nilobject - base;
            dumper::g_dumper.add_offset("Internal", "luao_nilobject", offset);
            add_found_offset("Internal", "luao_nilobject", offset, "Lua O nil object");
            logger::info("  luao_nilobject -> 0x{:X}", offset);
            found++;
        }
        else {
            logger::warn("  luao_nilobject -> not found");
        }

        struct PatternScan {
            std::string pattern;
            std::string name;
            bool extract;
            std::string type;
            std::string description;
        };

        std::vector<PatternScan> pattern_scans = {
            { "42 0F B6 8C 30 ?? ?? ?? ?? 0B CA", "opcode_lookup_table", true, "unk", "Opcode lookup table" },
            { "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F8 48 8B F2 48 8B D9 8B", "getglobalstate", false, "", "Get global state function" },
            { "E8 ?? ?? ?? ?? 84 DB 0F 85 ?? ?? ?? ?? 88 5F ?? E9 ?? ?? ?? ?? 49 8B 41", "luau_execute", true, "dword", "Luau execute function" },
            { "48 89 5C 24 ?? 55 56 57 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B F9 E8", "fireproximityprompt", false, "", "Fire proximity prompt" },
            { "48 89 5C 24 ?? 55 56 57 48 83 EC ?? 49 8B F8 48 8B F1 33 ED 89 AC 24 ?? ?? ?? ?? F3 0F 10 81", "firemouseclick", false, "", "Fire mouse click" },
            { "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 33 ED", "firemousehoverenter", false, "", "Fire mouse hover enter" },
            { "48 8D 1D ?? ?? ?? ?? 8B 07", "fake_datamodel", true, "dword", "Fake datamodel pointer" },
        };

        for (const auto& scan : pattern_scans) {
            auto addr = fastfindPattern(scan.pattern, scan.extract, scan.type);

            if (addr != 0) {
                std::uintptr_t offset = addr - base;
                dumper::g_dumper.add_offset("Internal", scan.name, offset);
                add_found_offset("Pattern", scan.name, offset, scan.description, scan.pattern);
                logger::info("  {} -> 0x{:X}", scan.name, offset);
                found++;
            }
            else {
                logger::warn("  {} -> pattern not found", scan.name);
            }
        }

        logger::info("internal: found {} addresses", found);

        dump_all_files(); #include "../stages/stages.h"
#include "../dumper.h"
#include "../../core/logger/logger.h"
#include "../../core/process/process.h"

#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <set>
#include <map>
#include <mutex>
#include <chrono>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <random>
#include <unordered_set>
#include <unordered_map>
#include <regex>

            namespace {

            std::mutex memoryMutex;

            struct MemoryRegion {
                uintptr_t base;
                size_t size;
                DWORD protect;
                std::vector<uint8_t> data;
            };

            struct FoundOffset {
                std::string category;
                std::string name;
                uintptr_t offset;
                std::string description;
                std::string pattern;
            };

            struct FoundString {
                uintptr_t address;
                uintptr_t offset;
                std::string value;
                std::string category;
            };

            struct FoundFunction {
                uintptr_t address;
                uintptr_t offset;
                std::string name;
                std::string original_name;
                std::string pattern;
                size_t size_estimate;
                std::vector<std::string> nearby_strings;
                int xref_count;
                std::string likely_purpose;
            };

            struct FoundXref {
                uintptr_t from_offset;
                uintptr_t to_offset;
                std::string type;
            };

            struct AutoPattern {
                std::string name;
                std::string original_name;
                std::string category;
                uintptr_t offset;
                std::string pattern;
                std::string description;
                int confidence;
                std::string type;
                std::vector<std::string> related_strings;
            };

            struct NamedFunction {
                std::string name;
                uintptr_t offset;
                std::string pattern;
                std::string source;
                int confidence;
                std::vector<std::string> evidence;
            };

            std::vector<MemoryRegion> g_all_regions;
            std::vector<MemoryRegion> g_executable_regions;
            std::vector<MemoryRegion> g_readable_regions;
            std::vector<FoundOffset> g_found_offsets;
            std::vector<FoundString> g_found_strings;
            std::vector<FoundFunction> g_found_functions;
            std::vector<FoundXref> g_found_xrefs;
            std::vector<AutoPattern> g_auto_patterns;
            std::vector<NamedFunction> g_named_functions;
            std::map<uintptr_t, std::vector<std::string>> g_offset_to_strings;
            std::map<uintptr_t, int> g_xref_counts;
            uintptr_t g_module_base = 0;
            size_t g_module_size = 0;

            struct KnownFunctionSignature {
                std::string name;
                std::vector<std::string> string_hints;
                std::vector<uint8_t> prologue_bytes;
                std::vector<bool> prologue_mask;
                int min_xrefs;
                int max_xrefs;
                std::string category;
            };

            std::vector<KnownFunctionSignature> get_known_signatures() {
                return {
                    { "print", { "Current identity is %d", "print" }, { 0x48, 0x89, 0x5C, 0x24 }, { true, true, true, true }, 5, 1000, "Lua" },
                    { "warn", { "warn", "Warning:" }, { 0x48, 0x89, 0x5C, 0x24 }, { true, true, true, true }, 3, 500, "Lua" },
                    { "error", { "error", "Error:" }, { 0x48, 0x89, 0x5C, 0x24 }, { true, true, true, true }, 10, 2000, "Lua" },
                    { "require", { "require", "module" }, { 0x48, 0x89, 0x5C, 0x24 }, { true, true, true, true }, 20, 5000, "Lua" },
                    { "spawn", { "spawn", "thread" }, {}, {}, 5, 500, "Lua" },
                    { "defer", { "defer", "task" }, {}, {}, 3, 300, "Lua" },
                    { "delay", { "delay", "wait" }, {}, {}, 5, 500, "Lua" },
                    { "wait", { "wait", "yield" }, {}, {}, 50, 10000, "Lua" },
                    { "coroutine_resume", { "coroutine", "resume" }, {}, {}, 10, 1000, "Lua" },
                    { "coroutine_yield", { "coroutine", "yield" }, {}, {}, 10, 1000, "Lua" },
                    { "coroutine_create", { "coroutine", "create" }, {}, {}, 5, 500, "Lua" },
                    { "coroutine_wrap", { "coroutine", "wrap" }, {}, {}, 3, 300, "Lua" },
                    { "pcall", { "pcall", "protected" }, {}, {}, 20, 5000, "Lua" },
                    { "xpcall", { "xpcall", "error handler" }, {}, {}, 5, 1000, "Lua" },
                    { "getfenv", { "getfenv", "environment" }, {}, {}, 3, 500, "Lua" },
                    { "setfenv", { "setfenv", "environment" }, {}, {}, 3, 500, "Lua" },
                    { "rawget", { "rawget" }, {}, {}, 5, 1000, "Lua" },
                    { "rawset", { "rawset" }, {}, {}, 5, 1000, "Lua" },
                    { "rawequal", { "rawequal" }, {}, {}, 3, 500, "Lua" },
                    { "rawlen", { "rawlen" }, {}, {}, 3, 500, "Lua" },
                    { "type", { "type", "nil", "boolean", "number", "string", "table", "function", "userdata", "thread" }, {}, {}, 50, 20000, "Lua" },
                    { "typeof", { "typeof" }, {}, {}, 20, 5000, "Lua" },
                    { "tostring", { "tostring", "__tostring" }, {}, {}, 30, 10000, "Lua" },
                    { "tonumber", { "tonumber" }, {}, {}, 20, 5000, "Lua" },
                    { "select", { "select", "#" }, {}, {}, 10, 2000, "Lua" },
                    { "pairs", { "pairs", "__pairs" }, {}, {}, 20, 5000, "Lua" },
                    { "ipairs", { "ipairs", "__ipairs" }, {}, {}, 15, 3000, "Lua" },
                    { "next", { "next" }, {}, {}, 20, 5000, "Lua" },
                    { "unpack", { "unpack" }, {}, {}, 10, 2000, "Lua" },
                    { "pack", { "pack" }, {}, {}, 5, 1000, "Lua" },
                    { "setmetatable", { "setmetatable", "__metatable" }, {}, {}, 20, 5000, "Lua" },
                    { "getmetatable", { "getmetatable", "__metatable" }, {}, {}, 15, 3000, "Lua" },
                    { "newproxy", { "newproxy" }, {}, {}, 3, 500, "Lua" },

                    { "task_spawn", { "task", "spawn" }, {}, {}, 5, 500, "Task" },
                    { "task_defer", { "task", "defer" }, {}, {}, 3, 300, "Task" },
                    { "task_delay", { "task", "delay" }, {}, {}, 3, 300, "Task" },
                    { "task_wait", { "task", "wait" }, {}, {}, 10, 1000, "Task" },
                    { "task_cancel", { "task", "cancel" }, {}, {}, 3, 300, "Task" },
                    { "task_desynchronize", { "task", "desynchronize" }, {}, {}, 1, 100, "Task" },
                    { "task_synchronize", { "task", "synchronize" }, {}, {}, 1, 100, "Task" },

                    { "loadstring", { "loadstring", "bytecode" }, {}, {}, 5, 500, "Execution" },
                    { "load", { "load", "chunk" }, {}, {}, 5, 500, "Execution" },
                    { "dofile", { "dofile" }, {}, {}, 1, 100, "Execution" },
                    { "loadfile", { "loadfile" }, {}, {}, 1, 100, "Execution" },

                    { "string_sub", { "string", "sub" }, {}, {}, 20, 5000, "String" },
                    { "string_len", { "string", "len" }, {}, {}, 20, 5000, "String" },
                    { "string_find", { "string", "find" }, {}, {}, 10, 2000, "String" },
                    { "string_match", { "string", "match" }, {}, {}, 10, 2000, "String" },
                    { "string_gmatch", { "string", "gmatch" }, {}, {}, 5, 1000, "String" },
                    { "string_gsub", { "string", "gsub" }, {}, {}, 5, 1000, "String" },
                    { "string_format", { "string", "format" }, {}, {}, 20, 5000, "String" },
                    { "string_rep", { "string", "rep" }, {}, {}, 5, 1000, "String" },
                    { "string_reverse", { "string", "reverse" }, {}, {}, 3, 500, "String" },
                    { "string_lower", { "string", "lower" }, {}, {}, 5, 1000, "String" },
                    { "string_upper", { "string", "upper" }, {}, {}, 5, 1000, "String" },
                    { "string_char", { "string", "char" }, {}, {}, 5, 1000, "String" },
                    { "string_byte", { "string", "byte" }, {}, {}, 10, 2000, "String" },
                    { "string_split", { "string", "split" }, {}, {}, 5, 1000, "String" },

                    { "table_insert", { "table", "insert" }, {}, {}, 20, 5000, "Table" },
                    { "table_remove", { "table", "remove" }, {}, {}, 10, 2000, "Table" },
                    { "table_concat", { "table", "concat" }, {}, {}, 10, 2000, "Table" },
                    { "table_sort", { "table", "sort" }, {}, {}, 5, 1000, "Table" },
                    { "table_find", { "table", "find" }, {}, {}, 5, 1000, "Table" },
                    { "table_create", { "table", "create" }, {}, {}, 10, 2000, "Table" },
                    { "table_clone", { "table", "clone" }, {}, {}, 5, 1000, "Table" },
                    { "table_clear", { "table", "clear" }, {}, {}, 5, 1000, "Table" },
                    { "table_freeze", { "table", "freeze" }, {}, {}, 3, 500, "Table" },
                    { "table_isfrozen", { "table", "isfrozen" }, {}, {}, 3, 500, "Table" },

                    { "math_abs", { "math", "abs" }, {}, {}, 10, 2000, "Math" },
                    { "math_floor", { "math", "floor" }, {}, {}, 10, 2000, "Math" },
                    { "math_ceil", { "math", "ceil" }, {}, {}, 5, 1000, "Math" },
                    { "math_sqrt", { "math", "sqrt" }, {}, {}, 10, 2000, "Math" },
                    { "math_sin", { "math", "sin" }, {}, {}, 5, 1000, "Math" },
                    { "math_cos", { "math", "cos" }, {}, {}, 5, 1000, "Math" },
                    { "math_tan", { "math", "tan" }, {}, {}, 3, 500, "Math" },
                    { "math_random", { "math", "random" }, {}, {}, 10, 2000, "Math" },
                    { "math_randomseed", { "math", "randomseed" }, {}, {}, 3, 500, "Math" },
                    { "math_min", { "math", "min" }, {}, {}, 10, 2000, "Math" },
                    { "math_max", { "math", "max" }, {}, {}, 10, 2000, "Math" },
                    { "math_clamp", { "math", "clamp" }, {}, {}, 5, 1000, "Math" },
                    { "math_lerp", { "math", "lerp" }, {}, {}, 3, 500, "Math" },
                    { "math_sign", { "math", "sign" }, {}, {}, 3, 500, "Math" },
                    { "math_round", { "math", "round" }, {}, {}, 5, 1000, "Math" },
                    { "math_noise", { "math", "noise" }, {}, {}, 3, 500, "Math" },

                    { "debug_traceback", { "debug", "traceback" }, {}, {}, 5, 1000, "Debug" },
                    { "debug_info", { "debug", "info" }, {}, {}, 3, 500, "Debug" },
                    { "debug_profilebegin", { "debug", "profilebegin" }, {}, {}, 3, 500, "Debug" },
                    { "debug_profileend", { "debug", "profileend" }, {}, {}, 3, 500, "Debug" },
                    { "debug_setmemorycategory", { "debug", "setmemorycategory" }, {}, {}, 1, 100, "Debug" },
                    { "debug_resetmemorycategory", { "debug", "resetmemorycategory" }, {}, {}, 1, 100, "Debug" },

                    { "os_time", { "os", "time" }, {}, {}, 5, 1000, "OS" },
                    { "os_date", { "os", "date" }, {}, {}, 3, 500, "OS" },
                    { "os_difftime", { "os", "difftime" }, {}, {}, 1, 100, "OS" },
                    { "os_clock", { "os", "clock" }, {}, {}, 5, 1000, "OS" },

                    { "bit32_band", { "bit32", "band" }, {}, {}, 5, 1000, "Bit" },
                    { "bit32_bor", { "bit32", "bor" }, {}, {}, 5, 1000, "Bit" },
                    { "bit32_bxor", { "bit32", "bxor" }, {}, {}, 3, 500, "Bit" },
                    { "bit32_bnot", { "bit32", "bnot" }, {}, {}, 3, 500, "Bit" },
                    { "bit32_lshift", { "bit32", "lshift" }, {}, {}, 5, 1000, "Bit" },
                    { "bit32_rshift", { "bit32", "rshift" }, {}, {}, 5, 1000, "Bit" },
                    { "bit32_arshift", { "bit32", "arshift" }, {}, {}, 3, 500, "Bit" },
                    { "bit32_extract", { "bit32", "extract" }, {}, {}, 3, 500, "Bit" },
                    { "bit32_replace", { "bit32", "replace" }, {}, {}, 3, 500, "Bit" },

                    { "buffer_create", { "buffer", "create" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_fromstring", { "buffer", "fromstring" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_tostring", { "buffer", "tostring" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_len", { "buffer", "len" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_copy", { "buffer", "copy" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_fill", { "buffer", "fill" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_readi8", { "buffer", "readi8" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_readu8", { "buffer", "readu8" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_writei8", { "buffer", "writei8" }, {}, {}, 3, 500, "Buffer" },
                    { "buffer_writeu8", { "buffer", "writeu8" }, {}, {}, 3, 500, "Buffer" },

                    { "utf8_char", { "utf8", "char" }, {}, {}, 3, 500, "UTF8" },
                    { "utf8_codes", { "utf8", "codes" }, {}, {}, 3, 500, "UTF8" },
                    { "utf8_codepoint", { "utf8", "codepoint" }, {}, {}, 3, 500, "UTF8" },
                    { "utf8_len", { "utf8", "len" }, {}, {}, 3, 500, "UTF8" },
                    { "utf8_offset", { "utf8", "offset" }, {}, {}, 3, 500, "UTF8" },
                    { "utf8_graphemes", { "utf8", "graphemes" }, {}, {}, 3, 500, "UTF8" },
                    { "utf8_nfcnormalize", { "utf8", "nfcnormalize" }, {}, {}, 1, 100, "UTF8" },
                    { "utf8_nfdnormalize", { "utf8", "nfdnormalize" }, {}, {}, 1, 100, "UTF8" },

                    { "Instance_new", { "Instance", "new" }, {}, {}, 50, 20000, "Instance" },
                    { "Instance_Clone", { "Clone", "Instance" }, {}, {}, 20, 5000, "Instance" },
                    { "Instance_Destroy", { "Destroy", "Instance" }, {}, {}, 30, 10000, "Instance" },
                    { "Instance_ClearAllChildren", { "ClearAllChildren" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_FindFirstChild", { "FindFirstChild" }, {}, {}, 30, 10000, "Instance" },
                    { "Instance_FindFirstChildOfClass", { "FindFirstChildOfClass" }, {}, {}, 10, 2000, "Instance" },
                    { "Instance_FindFirstChildWhichIsA", { "FindFirstChildWhichIsA" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_FindFirstAncestor", { "FindFirstAncestor" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_FindFirstAncestorOfClass", { "FindFirstAncestorOfClass" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_FindFirstAncestorWhichIsA", { "FindFirstAncestorWhichIsA" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_FindFirstDescendant", { "FindFirstDescendant" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_GetChildren", { "GetChildren" }, {}, {}, 20, 5000, "Instance" },
                    { "Instance_GetDescendants", { "GetDescendants" }, {}, {}, 10, 2000, "Instance" },
                    { "Instance_GetFullName", { "GetFullName" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_IsA", { "IsA" }, {}, {}, 30, 10000, "Instance" },
                    { "Instance_IsAncestorOf", { "IsAncestorOf" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_IsDescendantOf", { "IsDescendantOf" }, {}, {}, 10, 2000, "Instance" },
                    { "Instance_WaitForChild", { "WaitForChild" }, {}, {}, 10, 2000, "Instance" },
                    { "Instance_GetPropertyChangedSignal", { "GetPropertyChangedSignal" }, {}, {}, 5, 1000, "Instance" },
                    { "Instance_GetAttribute", { "GetAttribute" }, {}, {}, 10, 2000, "Instance" },
                    { "Instance_SetAttribute", { "SetAttribute" }, {}, {}, 10, 2000, "Instance" },
                    { "Instance_GetAttributes", { "GetAttributes" }, {}, {}, 5, 1000, "Instance" },

                    { "game_GetService", { "GetService" }, {}, {}, 50, 20000, "Services" },
                    { "game_FindService", { "FindService" }, {}, {}, 10, 2000, "Services" },

                    { "luau_execute", { "execute", "bytecode", "vm" }, {}, {}, 100, 50000, "VM" },
                    { "luau_load", { "load", "compile", "bytecode" }, {}, {}, 20, 5000, "VM" },
                    { "lua_pushvalue", { "push", "stack" }, {}, {}, 50, 20000, "LuaAPI" },
                    { "lua_pushnil", { "pushnil", "nil" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_pushnumber", { "pushnumber" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_pushstring", { "pushstring" }, {}, {}, 50, 20000, "LuaAPI" },
                    { "lua_pushboolean", { "pushboolean" }, {}, {}, 20, 5000, "LuaAPI" },
                    { "lua_pushthread", { "pushthread" }, {}, {}, 10, 2000, "LuaAPI" },
                    { "lua_pushlightuserdata", { "pushlightuserdata" }, {}, {}, 10, 2000, "LuaAPI" },
                    { "lua_pushcclosure", { "pushcclosure", "closure" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_pop", { "pop", "stack" }, {}, {}, 50, 20000, "LuaAPI" },
                    { "lua_gettop", { "gettop" }, {}, {}, 50, 20000, "LuaAPI" },
                    { "lua_settop", { "settop" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_getfield", { "getfield" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_setfield", { "setfield" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_gettable", { "gettable" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_settable", { "settable" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_rawget", { "rawget" }, {}, {}, 20, 5000, "LuaAPI" },
                    { "lua_rawset", { "rawset" }, {}, {}, 20, 5000, "LuaAPI" },
                    { "lua_newuserdata", { "newuserdata" }, {}, {}, 20, 5000, "LuaAPI" },
                    { "lua_newthread", { "newthread" }, {}, {}, 10, 2000, "LuaAPI" },
                    { "lua_newstate", { "newstate", "lua_State" }, {}, {}, 5, 500, "LuaAPI" },
                    { "lua_close", { "lua_close", "close state" }, {}, {}, 5, 500, "LuaAPI" },
                    { "lua_call", { "lua_call", "call" }, {}, {}, 50, 20000, "LuaAPI" },
                    { "lua_pcall", { "lua_pcall", "pcall" }, {}, {}, 30, 10000, "LuaAPI" },
                    { "lua_error", { "lua_error", "error" }, {}, {}, 20, 5000, "LuaAPI" },
                    { "lua_throw", { "throw", "error" }, {}, {}, 10, 2000, "LuaAPI" },
                    { "lua_yield", { "lua_yield", "yield" }, {}, {}, 10, 2000, "LuaAPI" },
                    { "lua_resume", { "lua_resume", "resume" }, {}, {}, 10, 2000, "LuaAPI" },
                    { "lua_gc", { "lua_gc", "garbage" }, {}, {}, 10, 2000, "LuaAPI" },

                    { "FireServer", { "FireServer" }, {}, {}, 20, 5000, "Remote" },
                    { "InvokeServer", { "InvokeServer" }, {}, {}, 10, 2000, "Remote" },
                    { "FireClient", { "FireClient" }, {}, {}, 10, 2000, "Remote" },
                    { "InvokeClient", { "InvokeClient" }, {}, {}, 5, 1000, "Remote" },
                    { "FireAllClients", { "FireAllClients" }, {}, {}, 5, 1000, "Remote" },

                    { "Connect", { "Connect", "RBXScriptConnection" }, {}, {}, 100, 50000, "Signal" },
                    { "Disconnect", { "Disconnect" }, {}, {}, 30, 10000, "Signal" },
                    { "Wait", { "Wait", "Signal" }, {}, {}, 20, 5000, "Signal" },
                    { "Fire", { "Fire", "BindableEvent" }, {}, {}, 10, 2000, "Signal" },
                    { "Invoke", { "Invoke", "BindableFunction" }, {}, {}, 10, 2000, "Signal" },

                    { "TweenService_Create", { "TweenService", "Create" }, {}, {}, 10, 2000, "Tween" },
                    { "Tween_Play", { "Tween", "Play" }, {}, {}, 10, 2000, "Tween" },
                    { "Tween_Cancel", { "Tween", "Cancel" }, {}, {}, 5, 1000, "Tween" },
                    { "Tween_Pause", { "Tween", "Pause" }, {}, {}, 5, 1000, "Tween" },

                    { "Raycast", { "Raycast", "RaycastResult" }, {}, {}, 20, 5000, "Physics" },
                    { "Blockcast", { "Blockcast" }, {}, {}, 5, 1000, "Physics" },
                    { "Spherecast", { "Spherecast" }, {}, {}, 5, 1000, "Physics" },
                    { "GetPartBoundsInBox", { "GetPartBoundsInBox" }, {}, {}, 3, 500, "Physics" },
                    { "GetPartBoundsInRadius", { "GetPartBoundsInRadius" }, {}, {}, 3, 500, "Physics" },
                    { "GetPartsInPart", { "GetPartsInPart" }, {}, {}, 3, 500, "Physics" },

                    { "GetMouse", { "GetMouse" }, {}, {}, 5, 1000, "Input" },
                    { "IsKeyDown", { "IsKeyDown" }, {}, {}, 10, 2000, "Input" },
                    { "IsMouseButtonPressed", { "IsMouseButtonPressed" }, {}, {}, 5, 1000, "Input" },
                    { "GetKeysPressed", { "GetKeysPressed" }, {}, {}, 3, 500, "Input" },

                    { "HttpService_RequestAsync", { "RequestAsync", "HttpService" }, {}, {}, 5, 1000, "HTTP" },
                    { "HttpService_GetAsync", { "GetAsync", "HttpService" }, {}, {}, 5, 1000, "HTTP" },
                    { "HttpService_PostAsync", { "PostAsync", "HttpService" }, {}, {}, 5, 1000, "HTTP" },
                    { "HttpService_JSONEncode", { "JSONEncode" }, {}, {}, 10, 2000, "HTTP" },
                    { "HttpService_JSONDecode", { "JSONDecode" }, {}, {}, 10, 2000, "HTTP" },

                    { "MarketplaceService_PromptPurchase", { "PromptPurchase" }, {}, {}, 3, 500, "Marketplace" },
                    { "MarketplaceService_PromptGamePassPurchase", { "PromptGamePassPurchase" }, {}, {}, 3, 500, "Marketplace" },
                    { "MarketplaceService_UserOwnsGamePassAsync", { "UserOwnsGamePassAsync" }, {}, {}, 3, 500, "Marketplace" },
                    { "MarketplaceService_GetProductInfo", { "GetProductInfo" }, {}, {}, 3, 500, "Marketplace" },

                    { "DataStore_GetAsync", { "GetAsync", "DataStore" }, {}, {}, 5, 1000, "DataStore" },
                    { "DataStore_SetAsync", { "SetAsync", "DataStore" }, {}, {}, 5, 1000, "DataStore" },
                    { "DataStore_UpdateAsync", { "UpdateAsync", "DataStore" }, {}, {}, 5, 1000, "DataStore" },
                    { "DataStore_RemoveAsync", { "RemoveAsync", "DataStore" }, {}, {}, 3, 500, "DataStore" },
                    { "DataStore_IncrementAsync", { "IncrementAsync", "DataStore" }, {}, {}, 3, 500, "DataStore" },

                    { "Players_GetPlayerByUserId", { "GetPlayerByUserId" }, {}, {}, 5, 1000, "Players" },
                    { "Players_GetPlayerFromCharacter", { "GetPlayerFromCharacter" }, {}, {}, 10, 2000, "Players" },
                    { "Players_GetPlayers", { "GetPlayers" }, {}, {}, 10, 2000, "Players" },
                    { "Player_Kick", { "Kick", "Player" }, {}, {}, 5, 1000, "Players" },
                    { "Player_GetRankInGroup", { "GetRankInGroup" }, {}, {}, 3, 500, "Players" },
                    { "Player_IsInGroup", { "IsInGroup" }, {}, {}, 3, 500, "Players" },
                    { "Player_GetFriendsOnline", { "GetFriendsOnline" }, {}, {}, 3, 500, "Players" },
                    { "Player_IsFriendsWith", { "IsFriendsWith" }, {}, {}, 3, 500, "Players" },

                    { "Humanoid_MoveTo", { "MoveTo", "Humanoid" }, {}, {}, 5, 1000, "Humanoid" },
                    { "Humanoid_TakeDamage", { "TakeDamage" }, {}, {}, 5, 1000, "Humanoid" },
                    { "Humanoid_ChangeState", { "ChangeState", "HumanoidStateType" }, {}, {}, 5, 1000, "Humanoid" },
                    { "Humanoid_GetState", { "GetState" }, {}, {}, 5, 1000, "Humanoid" },
                    { "Humanoid_EquipTool", { "EquipTool" }, {}, {}, 3, 500, "Humanoid" },
                    { "Humanoid_UnequipTools", { "UnequipTools" }, {}, {}, 3, 500, "Humanoid" },

                    { "Sound_Play", { "Play", "Sound" }, {}, {}, 10, 2000, "Sound" },
                    { "Sound_Stop", { "Stop", "Sound" }, {}, {}, 5, 1000, "Sound" },
                    { "Sound_Pause", { "Pause", "Sound" }, {}, {}, 3, 500, "Sound" },
                    { "Sound_Resume", { "Resume", "Sound" }, {}, {}, 3, 500, "Sound" },

                    { "Animation_Play", { "Play", "AnimationTrack" }, {}, {}, 10, 2000, "Animation" },
                    { "Animation_Stop", { "Stop", "AnimationTrack" }, {}, {}, 5, 1000, "Animation" },
                    { "Animator_LoadAnimation", { "LoadAnimation", "Animator" }, {}, {}, 10, 2000, "Animation" },

                    { "Camera_WorldToScreenPoint", { "WorldToScreenPoint" }, {}, {}, 5, 1000, "Camera" },
                    { "Camera_WorldToViewportPoint", { "WorldToViewportPoint" }, {}, {}, 5, 1000, "Camera" },
                    { "Camera_ScreenPointToRay", { "ScreenPointToRay" }, {}, {}, 5, 1000, "Camera" },
                    { "Camera_ViewportPointToRay", { "ViewportPointToRay" }, {}, {}, 5, 1000, "Camera" },
                    { "Camera_GetPartsObscuringTarget", { "GetPartsObscuringTarget" }, {}, {}, 3, 500, "Camera" },

                    { "CFrame_new", { "CFrame", "new" }, {}, {}, 50, 20000, "CFrame" },
                    { "CFrame_lookAt", { "CFrame", "lookAt" }, {}, {}, 10, 2000, "CFrame" },
                    { "CFrame_fromEulerAnglesXYZ", { "fromEulerAnglesXYZ" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_fromEulerAnglesYXZ", { "fromEulerAnglesYXZ" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_fromAxisAngle", { "fromAxisAngle" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_fromMatrix", { "fromMatrix" }, {}, {}, 3, 500, "CFrame" },
                    { "CFrame_Inverse", { "Inverse", "CFrame" }, {}, {}, 10, 2000, "CFrame" },
                    { "CFrame_Lerp", { "Lerp", "CFrame" }, {}, {}, 10, 2000, "CFrame" },
                    { "CFrame_ToWorldSpace", { "ToWorldSpace" }, {}, {}, 10, 2000, "CFrame" },
                    { "CFrame_ToObjectSpace", { "ToObjectSpace" }, {}, {}, 10, 2000, "CFrame" },
                    { "CFrame_PointToWorldSpace", { "PointToWorldSpace" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_PointToObjectSpace", { "PointToObjectSpace" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_VectorToWorldSpace", { "VectorToWorldSpace" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_VectorToObjectSpace", { "VectorToObjectSpace" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_GetComponents", { "GetComponents", "CFrame" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_ToEulerAnglesXYZ", { "ToEulerAnglesXYZ" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_ToEulerAnglesYXZ", { "ToEulerAnglesYXZ" }, {}, {}, 5, 1000, "CFrame" },
                    { "CFrame_ToAxisAngle", { "ToAxisAngle" }, {}, {}, 3, 500, "CFrame" },
                    { "CFrame_ToOrientation", { "ToOrientation" }, {}, {}, 5, 1000, "CFrame" },

                    { "Vector3_new", { "Vector3", "new" }, {}, {}, 100, 50000, "Vector3" },
                    { "Vector3_Lerp", { "Lerp", "Vector3" }, {}, {}, 10, 2000, "Vector3" },
                    { "Vector3_Dot", { "Dot", "Vector3" }, {}, {}, 10, 2000, "Vector3" },
                    { "Vector3_Cross", { "Cross", "Vector3" }, {}, {}, 10, 2000, "Vector3" },
                    { "Vector3_FuzzyEq", { "FuzzyEq" }, {}, {}, 3, 500, "Vector3" },

                    { "Vector2_new", { "Vector2", "new" }, {}, {}, 30, 10000, "Vector2" },
                    { "Vector2_Lerp", { "Lerp", "Vector2" }, {}, {}, 5, 1000, "Vector2" },
                    { "Vector2_Dot", { "Dot", "Vector2" }, {}, {}, 5, 1000, "Vector2" },
                    { "Vector2_Cross", { "Cross", "Vector2" }, {}, {}, 3, 500, "Vector2" },

                    { "Color3_new", { "Color3", "new" }, {}, {}, 30, 10000, "Color3" },
                    { "Color3_fromRGB", { "fromRGB" }, {}, {}, 20, 5000, "Color3" },
                    { "Color3_fromHSV", { "fromHSV" }, {}, {}, 5, 1000, "Color3" },
                    { "Color3_fromHex", { "fromHex" }, {}, {}, 3, 500, "Color3" },
                    { "Color3_ToHSV", { "ToHSV" }, {}, {}, 3, 500, "Color3" },
                    { "Color3_ToHex", { "ToHex" }, {}, {}, 3, 500, "Color3" },
                    { "Color3_Lerp", { "Lerp", "Color3" }, {}, {}, 5, 1000, "Color3" },

                    { "UDim2_new", { "UDim2", "new" }, {}, {}, 20, 5000, "UDim2" },
                    { "UDim2_fromScale", { "fromScale" }, {}, {}, 10, 2000, "UDim2" },
                    { "UDim2_fromOffset", { "fromOffset" }, {}, {}, 10, 2000, "UDim2" },
                    { "UDim2_Lerp", { "Lerp", "UDim2" }, {}, {}, 3, 500, "UDim2" },

                    { "Region3_new", { "Region3", "new" }, {}, {}, 5, 1000, "Region3" },
                    { "Region3_ExpandToGrid", { "ExpandToGrid" }, {}, {}, 3, 500, "Region3" },

                    { "Ray_new", { "Ray", "new" }, {}, {}, 10, 2000, "Ray" },
                    { "Ray_ClosestPoint", { "ClosestPoint" }, {}, {}, 3, 500, "Ray" },
                    { "Ray_Distance", { "Distance", "Ray" }, {}, {}, 3, 500, "Ray" },

                    { "Random_new", { "Random", "new" }, {}, {}, 5, 1000, "Random" },
                    { "Random_NextNumber", { "NextNumber" }, {}, {}, 5, 1000, "Random" },
                    { "Random_NextInteger", { "NextInteger" }, {}, {}, 5, 1000, "Random" },
                    { "Random_NextUnitVector", { "NextUnitVector" }, {}, {}, 3, 500, "Random" },
                    { "Random_Clone", { "Clone", "Random" }, {}, {}, 3, 500, "Random" },

                    { "NumberRange_new", { "NumberRange", "new" }, {}, {}, 3, 500, "NumberRange" },
                    { "NumberSequence_new", { "NumberSequence", "new" }, {}, {}, 3, 500, "NumberSequence" },
                    { "ColorSequence_new", { "ColorSequence", "new" }, {}, {}, 3, 500, "ColorSequence" },

                    { "Rect_new", { "Rect", "new" }, {}, {}, 5, 1000, "Rect" },

                    { "BrickColor_new", { "BrickColor", "new" }, {}, {}, 10, 2000, "BrickColor" },
                    { "BrickColor_random", { "random", "BrickColor" }, {}, {}, 3, 500, "BrickColor" },

                    { "Enum_GetEnumItems", { "GetEnumItems" }, {}, {}, 10, 2000, "Enum" },

                    { "DateTime_now", { "DateTime", "now" }, {}, {}, 5, 1000, "DateTime" },
                    { "DateTime_fromUnixTimestamp", { "fromUnixTimestamp" }, {}, {}, 3, 500, "DateTime" },
                    { "DateTime_fromUnixTimestampMillis", { "fromUnixTimestampMillis" }, {}, {}, 3, 500, "DateTime" },
                    { "DateTime_fromIsoDate", { "fromIsoDate" }, {}, {}, 3, 500, "DateTime" },
                    { "DateTime_ToUniversalTime", { "ToUniversalTime" }, {}, {}, 3, 500, "DateTime" },
                    { "DateTime_ToLocalTime", { "ToLocalTime" }, {}, {}, 3, 500, "DateTime" },
                    { "DateTime_ToIsoDate", { "ToIsoDate" }, {}, {}, 3, 500, "DateTime" },
                    { "DateTime_FormatUniversalTime", { "FormatUniversalTime" }, {}, {}, 3, 500, "DateTime" },
                    { "DateTime_FormatLocalTime", { "FormatLocalTime" }, {}, {}, 3, 500, "DateTime" },

                    { "PathfindingService_CreatePath", { "CreatePath", "PathfindingService" }, {}, {}, 3, 500, "Pathfinding" },
                    { "Path_ComputeAsync", { "ComputeAsync", "Path" }, {}, {}, 3, 500, "Pathfinding" },
                    { "Path_GetWaypoints", { "GetWaypoints", "Path" }, {}, {}, 3, 500, "Pathfinding" },

                    { "CollectionService_GetTagged", { "GetTagged" }, {}, {}, 5, 1000, "Collection" },
                    { "CollectionService_AddTag", { "AddTag" }, {}, {}, 5, 1000, "Collection" },
                    { "CollectionService_RemoveTag", { "RemoveTag" }, {}, {}, 3, 500, "Collection" },
                    { "CollectionService_HasTag", { "HasTag" }, {}, {}, 5, 1000, "Collection" },
                    { "CollectionService_GetTags", { "GetTags" }, {}, {}, 3, 500, "Collection" },
                };
            }

            std::string protect_to_str(DWORD protect) {
                if (protect & PAGE_EXECUTE_READWRITE) return "RWX";
                if (protect & PAGE_EXECUTE_READ) return "RX";
                if (protect & PAGE_EXECUTE_WRITECOPY) return "RWX_C";
                if (protect & PAGE_EXECUTE) return "X";
                if (protect & PAGE_READWRITE) return "RW";
                if (protect & PAGE_READONLY) return "R";
                if (protect & PAGE_WRITECOPY) return "RW_C";
                if (protect & PAGE_NOACCESS) return "NA";
                return "?";
            }

            std::string bytes_to_hex(const std::vector<uint8_t>& data, size_t start, size_t count) {
                std::ostringstream oss;
                for (size_t i = 0; i < count && (start + i) < data.size(); ++i) {
                    oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(data[start + i]);
                    if (i < count - 1) oss << " ";
                }
                return oss.str();
            }

            std::string bytes_to_ascii(const std::vector<uint8_t>& data, size_t start, size_t count) {
                std::string result;
                for (size_t i = 0; i < count && (start + i) < data.size(); ++i) {
                    uint8_t c = data[start + i];
                    result += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
                }
                return result;
            }

            std::string sanitize_name(const std::string& str) {
                std::string result;
                for (char c : str) {
                    if (std::isalnum(c) || c == '_') {
                        result += c;
                    }
                    else if (c == ' ' || c == '-' || c == '.' || c == ':') {
                        result += '_';
                    }
                }
                if (!result.empty() && std::isdigit(result[0])) {
                    result = "_" + result;
                }
                return result;
            }

            std::string format_size(size_t size) {
                std::ostringstream oss;
                if (size >= 1024 * 1024) {
                    oss << std::fixed << std::setprecision(2) << (size / (1024.0 * 1024.0)) << " MB";
                }
                else if (size >= 1024) {
                    oss << std::fixed << std::setprecision(2) << (size / 1024.0) << " KB";
                }
                else {
                    oss << size << " B";
                }
                return oss.str();
            }

            std::vector<uint8_t> read_region_data(uintptr_t base, size_t size) {
                std::vector<uint8_t> buffer(size);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(process::g_process.get_handle(), reinterpret_cast<LPCVOID>(base), buffer.data(), buffer.size(), &bytesRead)) {
                    buffer.resize(bytesRead);
                    return buffer;
                }
                return {};
            }

            void add_found_offset(const std::string& category, const std::string& name, uintptr_t offset, const std::string& desc = "", const std::string& pattern = "") {
                FoundOffset fo;
                fo.category = category;
                fo.name = name;
                fo.offset = offset;
                fo.description = desc;
                fo.pattern = pattern;
                g_found_offsets.push_back(fo);
            }

            void add_named_function(const std::string& name, uintptr_t offset, const std::string& pattern, const std::string& source, int confidence, const std::vector<std::string>& evidence) {
                NamedFunction nf;
                nf.name = name;
                nf.offset = offset;
                nf.pattern = pattern;
                nf.source = source;
                nf.confidence = confidence;
                nf.evidence = evidence;
                g_named_functions.push_back(nf);
            }

            void scan_strings() {
                std::set<std::string> seen;

                for (const auto& region : g_readable_regions) {
                    if (region.data.empty()) continue;

                    for (size_t i = 0; i < region.data.size(); ++i) {
                        std::string str;
                        bool valid = true;

                        for (size_t j = i; j < region.data.size() && j < i + 512; ++j) {
                            uint8_t c = region.data[j];
                            if (c == 0) break;
                            if (c >= 32 && c < 127) {
                                str += static_cast<char>(c);
                            }
                            else if (c == '\t' || c == '\n' || c == '\r') {
                                str += ' ';
                            }
                            else {
                                valid = false;
                                break;
                            }
                        }

                        if (valid && str.length() >= 4 && seen.find(str) == seen.end()) {
                            seen.insert(str);

                            FoundString entry;
                            entry.address = region.base + i;
                            entry.offset = entry.address - g_module_base;
                            entry.value = str;

                            std::string lower = str;
                            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

                            if (lower.find("error") != std::string::npos || lower.find("exception") != std::string::npos) {
                                entry.category = "Error";
                            }
                            else if (lower.find("lua") != std::string::npos || lower.find("script") != std::string::npos) {
                                entry.category = "Lua";
                            }
                            else if (lower.find("roblox") != std::string::npos || lower.find("rbx") != std::string::npos) {
                                entry.category = "Roblox";
                            }
                            else if (lower.find("identity") != std::string::npos || lower.find("security") != std::string::npos) {
                                entry.category = "Security";
                            }
                            else if (lower.find("render") != std::string::npos || lower.find("graphics") != std::string::npos) {
                                entry.category = "Render";
                            }
                            else if (lower.find("physics") != std::string::npos || lower.find("collision") != std::string::npos) {
                                entry.category = "Physics";
                            }
                            else if (lower.find("network") != std::string::npos || lower.find("replicat") != std::string::npos) {
                                entry.category = "Network";
                            }
                            else if (lower.find("debug") != std::string::npos || lower.find("assert") != std::string::npos) {
                                entry.category = "Debug";
                            }
                            else {
                                entry.category = "General";
                            }

                            g_found_strings.push_back(entry);
                            i += str.length();
                        }
                    }
                }
            }

            void build_string_xref_map() {
                logger::info("building string xref map...");

                for (const auto& str : g_found_strings) {
                    uintptr_t str_addr = g_module_base + str.offset;

                    for (const auto& region : g_executable_regions) {
                        if (region.data.size() < 7) continue;

                        for (size_t i = 0; i + 7 <= region.data.size(); ++i) {
                            if ((region.data[i] == 0x48 || region.data[i] == 0x4C) && region.data[i + 1] == 0x8D) {
                                int32_t disp;
                                std::memcpy(&disp, &region.data[i + 3], sizeof(disp));
                                uintptr_t target = region.base + i + 7 + disp;

                                if (target == str_addr) {
                                    uintptr_t func_offset = 0;

                                    for (size_t back = i; back > 0 && back > i - 0x500; --back) {
                                        if (region.data[back] == 0xCC || region.data[back] == 0xC3) {
                                            func_offset = (region.base + back + 1) - g_module_base;
                                            break;
                                        }
                                    }

                                    if (func_offset == 0) {
                                        func_offset = (region.base + i) - g_module_base;
                                    }

                                    g_offset_to_strings[func_offset].push_back(str.value);
                                }
                            }
                        }
                    }
                }

                logger::info("found {} functions with string references", g_offset_to_strings.size());
            }

            void count_xrefs() {
                logger::info("counting xrefs...");

                for (const auto& region : g_executable_regions) {
                    if (region.data.size() < 5) continue;

                    for (size_t i = 0; i + 5 <= region.data.size(); ++i) {
                        if (region.data[i] == 0xE8) {
                            int32_t disp;
                            std::memcpy(&disp, &region.data[i + 1], sizeof(disp));
                            uintptr_t target = region.base + i + 5 + disp;

                            if (target >= g_module_base && target < g_module_base + g_module_size) {
                                g_xref_counts[target - g_module_base]++;
                            }
                        }
                    }
                }

                logger::info("counted xrefs for {} targets", g_xref_counts.size());
            }

            std::string try_identify_function(uintptr_t offset, const std::vector<std::string>& nearby_strings, int xref_count) {
                auto signatures = get_known_signatures();

                std::map<std::string, int> scores;

                for (const auto& sig : signatures) {
                    int score = 0;
                    std::vector<std::string> matched_hints;

                    for (const auto& hint : sig.string_hints) {
                        std::string hint_lower = hint;
                        std::transform(hint_lower.begin(), hint_lower.end(), hint_lower.begin(), ::tolower);

                        for (const auto& str : nearby_strings) {
                            std::string str_lower = str;
                            std::transform(str_lower.begin(), str_lower.end(), str_lower.begin(), ::tolower);

                            if (str_lower.find(hint_lower) != std::string::npos || hint_lower.find(str_lower) != std::string::npos) {
                                score += 10;
                                matched_hints.push_back(hint);
                                break;
                            }

                            if (str_lower == hint_lower) {
                                score += 25;
                                matched_hints.push_back(hint);
                                break;
                            }
                        }
                    }

                    if (sig.min_xrefs > 0 && sig.max_xrefs > 0) {
                        if (xref_count >= sig.min_xrefs && xref_count <= sig.max_xrefs) {
                            score += 5;
                        }
                    }

                    if (matched_hints.size() >= 2) {
                        score += 20;
                    }

                    if (score > 0) {
                        scores[sig.name] = score;
                    }
                }

                if (scores.empty()) {
                    return "";
                }

                std::string best_match;
                int best_score = 0;

                for (const auto& [name, score] : scores) {
                    if (score > best_score) {
                        best_score = score;
                        best_match = name;
                    }
                }

                if (best_score >= 20) {
                    return best_match;
                }

                return "";
            }

            std::string extract_function_name_from_strings(const std::vector<std::string>& strings) {
                std::vector<std::pair<std::string, int>> candidates;

                std::regex func_pattern(R"(^[a-zA-Z_][a-zA-Z0-9_]*$)");
                std::regex method_pattern(R"(^[a-zA-Z_][a-zA-Z0-9_]*:[a-zA-Z_][a-zA-Z0-9_]*$)");
                std::regex service_method_pattern(R"(^[A-Z][a-zA-Z]+Service\.[a-zA-Z_][a-zA-Z0-9_]*$)");

                for (const auto& str : strings) {
                    if (str.length() < 2 || str.length() > 50) continue;

                    if (std::regex_match(str, func_pattern)) {
                        if (str[0] >= 'a' && str[0] <= 'z') {
                            candidates.push_back({ str, 30 });
                        }
                        else if (str[0] >= 'A' && str[0] <= 'Z') {
                            candidates.push_back({ str, 20 });
                        }
                    }

                    if (std::regex_match(str, method_pattern)) {
                        candidates.push_back({ str, 25 });
                    }

                    if (std::regex_match(str, service_method_pattern)) {
                        candidates.push_back({ str, 35 });
                    }

                    if (str.find("(") != std::string::npos && str.find(")") != std::string::npos) {
                        size_t start = 0;
                        size_t end = str.find("(");
                        if (end > start && end < 30) {
                            std::string func_name = str.substr(start, end);
                            if (std::regex_match(func_name, func_pattern)) {
                                candidates.push_back({ func_name, 15 });
                            }
                        }
                    }
                }

                if (candidates.empty()) {
                    return "";
                }

                std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
                    return a.second > b.second;
                    });

                return candidates[0].first;
            }

            void identify_functions() {
                logger::info("identifying functions by name...");

                build_string_xref_map();
                count_xrefs();

                std::set<std::string> used_names;

                for (const auto& [offset, strings] : g_offset_to_strings) {
                    int xref_count = g_xref_counts.count(offset) ? g_xref_counts[offset] : 0;

                    std::string identified_name = try_identify_function(offset, strings, xref_count);

                    if (identified_name.empty()) {
                        identified_name = extract_function_name_from_strings(strings);
                    }

                    if (!identified_name.empty()) {
                        std::string final_name = identified_name;

                        if (used_names.count(final_name)) {
                            int suffix = 2;
                            while (used_names.count(final_name + "_" + std::to_string(suffix))) {
                                suffix++;
                            }
                            final_name = final_name + "_" + std::to_string(suffix);
                        }

                        used_names.insert(final_name);

                        auto buffer = process::g_process.read_bytes(g_module_base + offset, 16);
                        std::string pattern = buffer.empty() ? "" : bytes_to_hex(buffer, 0, 16);

                        int confidence = 50;
                        if (strings.size() >= 3) confidence += 20;
                        if (xref_count >= 10) confidence += 15;
                        if (identified_name == final_name) confidence += 10;

                        std::vector<std::string> evidence;
                        for (size_t i = 0; i < std::min(strings.size(), static_cast<size_t>(5)); ++i) {
                            evidence.push_back(strings[i].substr(0, 50));
                        }

                        add_named_function(final_name, offset, pattern, "string_analysis", confidence, evidence);
                    }
                }

                auto signatures = get_known_signatures();

                for (const auto& sig : signatures) {
                    if (used_names.count(sig.name)) continue;

                    for (const auto& hint : sig.string_hints) {
                        uintptr_t str_addr = 0;

                        for (const auto& str : g_found_strings) {
                            std::string str_lower = str.value;
                            std::string hint_lower = hint;
                            std::transform(str_lower.begin(), str_lower.end(), str_lower.begin(), ::tolower);
                            std::transform(hint_lower.begin(), hint_lower.end(), hint_lower.begin(), ::tolower);

                            if (str_lower == hint_lower || str_lower.find(hint_lower) == 0) {
                                str_addr = g_module_base + str.offset;
                                break;
                            }
                        }

                        if (str_addr == 0) continue;

                        for (const auto& region : g_executable_regions) {
                            if (region.data.size() < 7) continue;

                            for (size_t i = 0; i + 7 <= region.data.size(); ++i) {
                                if ((region.data[i] == 0x48 || region.data[i] == 0x4C) && region.data[i + 1] == 0x8D) {
                                    int32_t disp;
                                    std::memcpy(&disp, &region.data[i + 3], sizeof(disp));
                                    uintptr_t target = region.base + i + 7 + disp;

                                    if (target == str_addr) {
                                        uintptr_t func_start = 0;

                                        for (size_t back = i; back > 0 && back > i - 0x500; --back) {
                                            if (region.data[back] == 0xCC || region.data[back] == 0xC3) {
                                                func_start = region.base + back + 1;
                                                break;
                                            }
                                        }

                                        if (func_start == 0) {
                                            func_start = region.base + i - 0x20;
                                        }

                                        uintptr_t offset = func_start - g_module_base;

                                        if (!used_names.count(sig.name)) {
                                            used_names.insert(sig.name);

                                            auto buffer = process::g_process.read_bytes(func_start, 16);
                                            std::string pattern = buffer.empty() ? "" : bytes_to_hex(buffer, 0, 16);

                                            add_named_function(sig.name, offset, pattern, "signature_match", 70, { hint });
                                        }

                                        break;
                                    }
                                }
                            }

                            if (used_names.count(sig.name)) break;
                        }

                        if (used_names.count(sig.name)) break;
                    }
                }

                logger::info("identified {} named functions", g_named_functions.size());
            }

            void dump_named_functions_txt() {
                std::ofstream file("dump_named_functions.txt");
                if (!file.is_open()) return;

                file << "################################################################################\n";
                file << "#                         NAMED FUNCTIONS DUMP                                 #\n";
                file << "#              (Functions identified by string/signature analysis)             #\n";
                file << "################################################################################\n\n";

                file << "Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n";
                file << "Total Named Functions: " << std::dec << g_named_functions.size() << "\n\n";

                std::map<std::string, std::vector<NamedFunction>> by_category;

                auto signatures = get_known_signatures();
                std::map<std::string, std::string> name_to_category;
                for (const auto& sig : signatures) {
                    name_to_category[sig.name] = sig.category;
                }

                for (const auto& nf : g_named_functions) {
                    std::string category = "Unknown";
                    if (name_to_category.count(nf.name)) {
                        category = name_to_category[nf.name];
                    }
                    else if (nf.name.find("lua") != std::string::npos || nf.name.find("Lua") != std::string::npos) {
                        category = "Lua";
                    }
                    else if (nf.name.find("Instance") != std::string::npos) {
                        category = "Instance";
                    }
                    else if (nf.name.find("Vector") != std::string::npos || nf.name.find("CFrame") != std::string::npos) {
                        category = "Math";
                    }
                    else if (nf.name.find("string") != std::string::npos || nf.name.find("String") != std::string::npos) {
                        category = "String";
                    }
                    else if (nf.name.find("table") != std::string::npos || nf.name.find("Table") != std::string::npos) {
                        category = "Table";
                    }

                    by_category[category].push_back(nf);
                }

                for (const auto& [category, funcs] : by_category) {
                    file << "================================================================================\n";
                    file << "[" << category << "] - " << funcs.size() << " functions\n";
                    file << "================================================================================\n\n";

                    std::vector<NamedFunction> sorted = funcs;
                    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
                        return a.confidence > b.confidence;
                        });

                    for (const auto& nf : sorted) {
                        file << "  " << std::left << std::setw(40) << std::setfill(' ') << nf.name
                            << " = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << nf.offset
                            << "  ; conf:" << std::dec << std::setw(3) << std::setfill(' ') << nf.confidence
                            << " src:" << nf.source << "\n";

                        file << "    pattern: " << nf.pattern << "\n";

                        if (!nf.evidence.empty()) {
                            file << "    evidence:\n";
                            for (const auto& ev : nf.evidence) {
                                file << "      - \"" << ev << "\"\n";
                            }
                        }
                        file << "\n";
                    }
                }

                file.close();
            }

            void dump_named_functions_hpp() {
                std::ofstream file("dump_named_functions.hpp");
                if (!file.is_open()) return;

                file << "#pragma once\n\n";
                file << "// Auto-generated named functions header\n";
                file << "// Module Base: 0x" << std::hex << std::uppercase << g_module_base << "\n";
                file << "// Total Functions: " << std::dec << g_named_functions.size() << "\n\n";

                file << "#include <cstdint>\n\n";

                file << "namespace functions {\n\n";

                auto signatures = get_known_signatures();
                std::map<std::string, std::string> name_to_category;
                for (const auto& sig : signatures) {
                    name_to_category[sig.name] = sig.category;
                }

                std::map<std::string, std::vector<NamedFunction>> by_category;

                for (const auto& nf : g_named_functions) {
                    std::string category = "misc";
                    if (name_to_category.count(nf.name)) {
                        category = sanitize_name(name_to_category[nf.name]);
                    }
                    by_category[category].push_back(nf);
                }

                for (const auto& [category, funcs] : by_category) {
                    file << "    namespace " << category << " {\n";

                    for (const auto& nf : funcs) {
                        std::string var_name = sanitize_name(nf.name);
                        file << "        constexpr uintptr_t " << var_name
                            << " = 0x" << std::hex << std::uppercase << nf.offset << ";\n";
                    }

                    file << "    }\n\n";
                }

                file << "    // All functions in a flat namespace\n";
                file << "    namespace all {\n";

                for (const auto& nf : g_named_functions) {
                    std::string var_name = sanitize_name(nf.name);
                    file << "        constexpr uintptr_t " << var_name
                        << " = 0x" << std::hex << std::uppercase << nf.offset << ";\n";
                }

                file << "    }\n\n";

                file << "}\n";

                file.close();
            }

            void dump_named_functions_json() {
                std::ofstream file("dump_named_functions.json");
                if (!file.is_open()) return;

                file << "{\n";
                file << "  \"module_base\": \"0x" << std::hex << std::uppercase << g_module_base << "\",\n";
                file << "  \"total_functions\": " << std::dec << g_named_functions.size() << ",\n\n";

                file << "  \"functions\": [\n";

                bool first = true;
                for (const auto& nf : g_named_functions) {
                    if (!first) file << ",\n";
                    first = false;

                    file << "    {\n";
                    file << "      \"name\": \"" << nf.name << "\",\n";
                    file << "      \"offset\": \"0x" << std::hex << std::uppercase << nf.offset << "\",\n";
                    file << "      \"pattern\": \"" << nf.pattern << "\",\n";
                    file << "      \"source\": \"" << nf.source << "\",\n";
                    file << "      \"confidence\": " << std::dec << nf.confidence << ",\n";

                    file << "      \"evidence\": [";
                    bool first_ev = true;
                    for (const auto& ev : nf.evidence) {
                        if (!first_ev) file << ", ";
                        first_ev = false;

                        std::string escaped = ev;
                        for (size_t i = 0; i < escaped.size(); ++i) {
                            if (escaped[i] == '"' || escaped[i] == '\\') {
                                escaped.insert(i, "\\");
                                i++;
                            }
                            else if (escaped[i] == '\n' || escaped[i] == '\r' || escaped[i] == '\t') {
                                escaped[i] = ' ';
                            }
                        }
                        file << "\"" << escaped << "\"";
                    }
                    file << "]\n";

                    file << "    }";
                }

                file << "\n  ]\n";
                file << "}\n";

                file.close();
            }

            void scan_functions() {
                for (const auto& region : g_executable_regions) {
                    if (region.data.empty()) continue;

                    for (size_t i = 0; i + 16 < region.data.size(); ++i) {
                        bool is_func_start = false;

                        if (i == 0 || region.data[i - 1] == 0xCC || region.data[i - 1] == 0xC3) {
                            if (region.data[i] == 0x48 && region.data[i + 1] == 0x89 && region.data[i + 2] == 0x5C && region.data[i + 3] == 0x24) {
                                is_func_start = true;
                            }
                            else if (region.data[i] == 0x48 && region.data[i + 1] == 0x83 && region.data[i + 2] == 0xEC) {
                                is_func_start = true;
                            }
                            else if (region.data[i] == 0x40 && region.data[i + 1] == 0x53) {
                                is_func_start = true;
                            }
                            else if (region.data[i] == 0x40 && region.data[i + 1] == 0x55) {
                                is_func_start = true;
                            }
                            else if (region.data[i] == 0x48 && region.data[i + 1] == 0x8B && region.data[i + 2] == 0xC4) {
                                is_func_start = true;
                            }
                            else if (region.data[i] == 0x55 && region.data[i + 1] == 0x48 && region.data[i + 2] == 0x8B && region.data[i + 3] == 0xEC) {
                                is_func_start = true;
                            }
                        }

                        if (is_func_start) {
                            FoundFunction entry;
                            entry.address = region.base + i;
                            entry.offset = entry.address - g_module_base;

                            std::ostringstream name;
                            name << "sub_" << std::hex << std::uppercase << entry.offset;
                            entry.name = name.str();
                            entry.original_name = "";
                            entry.pattern = bytes_to_hex(region.data, i, 16);

                            size_t func_end = i;
                            for (size_t j = i + 1; j < region.data.size() && j < i + 0x10000; ++j) {
                                if (region.data[j] == 0xC3 || region.data[j] == 0xCC) {
                                    func_end = j;
                                    break;
                                }
                            }
                            entry.size_estimate = func_end - i;

                            g_found_functions.push_back(entry);
                        }
                    }
                }
            }

            void scan_xrefs() {
                for (const auto& region : g_executable_regions) {
                    if (region.data.size() < 5) continue;

                    for (size_t i = 0; i + 5 <= region.data.size(); ++i) {
                        if (region.data[i] == 0xE8 || region.data[i] == 0xE9) {
                            int32_t disp;
                            std::memcpy(&disp, &region.data[i +

        return found > 0;
    }

}
