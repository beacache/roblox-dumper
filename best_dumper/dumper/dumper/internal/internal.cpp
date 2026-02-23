#include "../stages/stages.h"
#include "../dumper.h"
#include "../../core/logger/logger.h"
#include "../../core/scanner/scanner.h"
#include "../../core/process/process.h"

#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <set>

namespace {

    auto get_scannable_regions(std::uintptr_t base, std::size_t size)
        -> std::vector<MEMORY_BASIC_INFORMATION> {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
        std::uintptr_t current = base;
        std::uintptr_t end = base + size;

        while (current < end) {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T result = VirtualQueryEx(
                process::g_process.get_handle(),
                reinterpret_cast<LPCVOID>(current),
                &mbi,
                sizeof(MEMORY_BASIC_INFORMATION)
            );

            if (result == 0) break;

            if ((mbi.State == MEM_COMMIT) &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) >= base &&
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) < end) {
                regions.push_back(mbi);
            }

            current += mbi.RegionSize;
        }

        return regions;
    }

    auto scan_for_pattern(const std::vector<MEMORY_BASIC_INFORMATION>& regions,
        const std::vector<std::uint8_t>& bytes,
        const std::vector<bool>& mask) -> std::optional<std::uintptr_t> {

        for (const auto& region : regions) {
            auto region_base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = static_cast<std::size_t>(region.RegionSize);

            auto buffer = process::g_process.read_bytes(region_base, region_size);
            if (buffer.size() < bytes.size()) continue;

            for (std::size_t i = 0; i + bytes.size() <= buffer.size(); ++i) {
                bool found = true;
                for (std::size_t j = 0; j < bytes.size(); ++j) {
                    if (mask[j] && buffer[i + j] != bytes[j]) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    return region_base + i;
                }
            }
        }

        return std::nullopt;
    }

    auto scan_for_string(const std::vector<MEMORY_BASIC_INFORMATION>& regions,
        const std::string& str) -> std::vector<std::uintptr_t> {
        std::vector<std::uintptr_t> results;

        for (const auto& region : regions) {
            auto region_base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = static_cast<std::size_t>(region.RegionSize);

            auto buffer = process::g_process.read_bytes(region_base, region_size);
            if (buffer.size() < str.size()) continue;

            for (std::size_t i = 0; i + str.size() <= buffer.size(); ++i) {
                if (std::memcmp(buffer.data() + i, str.data(), str.size()) == 0) {
                    results.push_back(region_base + i);
                }
            }
        }

        return results;
    }

    auto scan_for_xrefs(const std::vector<MEMORY_BASIC_INFORMATION>& regions,
        std::uintptr_t target) -> std::vector<std::uintptr_t> {
        std::vector<std::uintptr_t> results;

        for (const auto& region : regions) {
            auto region_base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = static_cast<std::size_t>(region.RegionSize);

            auto buffer = process::g_process.read_bytes(region_base, region_size);
            if (buffer.size() < 4) continue;

            for (std::size_t i = 0; i + 4 <= buffer.size(); ++i) {
                std::int32_t disp;
                std::memcpy(&disp, buffer.data() + i, sizeof(disp));
                std::uintptr_t resolved = region_base + i + 4 + disp;
                if (resolved == target) {
                    results.push_back(region_base + i);
                }
            }
        }

        return results;
    }

    auto parse_pattern(const std::string& pattern_str)
        -> std::pair<std::vector<std::uint8_t>, std::vector<bool>> {
        std::vector<std::uint8_t> bytes;
        std::vector<bool> mask;

        std::istringstream stream(pattern_str);
        std::string token;

        while (stream >> token) {
            if (token == "?" || token == "??" || token == "*") {
                bytes.push_back(0x00);
                mask.push_back(false);
            }
            else {
                bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16)));
                mask.push_back(true);
            }
        }

        return { bytes, mask };
    }

    auto get_function_start(std::uintptr_t addr) -> std::uintptr_t {
        auto buffer = process::g_process.read_bytes(addr - 0x500, 0x500);
        if (buffer.empty()) return addr;

        for (std::size_t i = buffer.size(); i > 0; --i) {
            if (buffer[i - 1] == 0xCC || buffer[i - 1] == 0xC3) {
                return addr - 0x500 + i;
            }
        }
        return addr;
    }

    auto find_pattern_near(std::uintptr_t addr, const std::string& pattern_str,
        std::size_t range = 0x300) -> std::optional<std::uintptr_t> {
        auto [bytes, mask] = parse_pattern(pattern_str);
        if (bytes.empty()) return std::nullopt;

        std::uintptr_t start = (addr > range) ? (addr - range) : addr;
        auto buffer = process::g_process.read_bytes(start, range * 2);
        if (buffer.size() < bytes.size()) return std::nullopt;

        for (std::size_t i = 0; i + bytes.size() <= buffer.size(); ++i) {
            bool found = true;
            for (std::size_t j = 0; j < bytes.size(); ++j) {
                if (mask[j] && buffer[i + j] != bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return start + i;
            }
        }

        return std::nullopt;
    }

    auto resolve_rip(std::uintptr_t addr, int disp_offset) -> std::optional<std::uintptr_t> {
        auto bytes = process::g_process.read_bytes(addr + disp_offset, 4);
        if (bytes.size() < 4) return std::nullopt;

        std::int32_t disp;
        std::memcpy(&disp, bytes.data(), sizeof(disp));
        return addr + disp_offset + 4 + disp;
    }

    auto find_first_call(std::uintptr_t func_start, std::size_t range = 0x200)
        -> std::optional<std::uintptr_t> {
        auto buffer = process::g_process.read_bytes(func_start, range);
        if (buffer.size() < 5) return std::nullopt;

        for (std::size_t i = 0; i + 5 <= buffer.size(); ++i) {
            if (buffer[i] == 0xE8) {
                std::int32_t disp;
                std::memcpy(&disp, &buffer[i + 1], sizeof(disp));
                return func_start + i + 5 + disp;
            }
        }

        return std::nullopt;
    }

    auto find_last_call(std::uintptr_t func_start, std::size_t range = 0x200)
        -> std::optional<std::uintptr_t> {
        auto buffer = process::g_process.read_bytes(func_start, range);
        if (buffer.size() < 5) return std::nullopt;

        std::optional<std::uintptr_t> last;
        for (std::size_t i = 0; i + 5 <= buffer.size(); ++i) {
            if (buffer[i] == 0xE8) {
                std::int32_t disp;
                std::memcpy(&disp, &buffer[i + 1], sizeof(disp));
                last = func_start + i + 5 + disp;
            }
        }

        return last;
    }

    struct PatternEntry {
        std::string pattern;
        std::string name;
        int rip_offset;
    };

    struct StringEntry {
        std::string str;
        std::string name;
        std::string hint;
    };

    const std::vector<PatternEntry> PATTERNS = {
        { "48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? E8 ?? ?? ?? ?? 48 8D 05", "appdata_info", 3 },
        { "48 8D 05 ?? ?? ?? ?? 48 83 C4 ?? C3 48 8D 0D", "appdata_info", 3 },
        { "48 83 EC ?? 44 8B C2 48 8B D1 48 8D", "luad_throw", 0 },
        { "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F8 48 8B F2 48 8B D9 8B", "getglobalstate", 0 },
        { "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 2B E0 48 8B 05", "rbx_deserialize", 0 },
        { "42 0F B6 8C 30 ?? ?? ?? ?? 0B CA", "opcode_lookup_table", 5 },
        { "42 0F B6 8C 30 ?? ?? ?? ??", "opcode_lookup_table", 5 },
        { "E8 ?? ?? ?? ?? 84 DB 0F 85 ?? ?? ?? ?? 88 5F ?? E9 ?? ?? ?? ?? 49 8B 41", "luau_execute", 1 },
        { "48 89 5C 24 ?? 55 56 57 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B F9 E8", "fireproximityprompt", 0 },
        { "48 89 5C 24 ?? 55 56 57 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B F9 E8", "fireproximityprompt", 0 },
        { "48 89 5C 24 ?? 55 56 57 48 83 EC ?? 49 8B F8 48 8B F1 33 ED 89 AC 24 ?? ?? ?? ?? F3 0F 10 81", "firemouseclick", 0 },
        { "48 89 5C 24 ?? 55 56 57 48 83 EC ?? 49 8B F8 48 8B F1 33 ED", "firemouseclick", 0 },
        { "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 33 ED", "firemousehoverenter", 0 },
    };

    const std::vector<StringEntry> STRINGS = {
        { "Current identity is %d", "print", "print_call" },
        { "Current identity is %d", "identity_ptr", "identity_qword" },
        { "Current identity is %d", "get_identity_struct", "identity_func" },
        { "EnableLoadModule", "enable_load_module", "fflag_param" },
        { "LockViolationInstanceCrash", "lock_violation_crash", "fflag_param" },
        { "TaskSchedulerTargetFps", "task_scheduler_target_fps", "fflag_param" },
        { "PhysicsSenderMaxBandwidthBps", "physics_sender_max_bandwidth", "fflag_param" },
        { "Trying to call method on object of type: `%s` with incorrect arguments.", "ktable", "lea_rcx_data" },
        { "HumanoidParallelManagerTaskQueue", "raw_scheduler", "mov_cs_qword" },
        { "Maximum re-entrancy depth (%i) exceeded", "getscheduler", "func_start" },
        { "new overlap in different world", "firetouchinterest", "last_call" },
        { "; R%d: %s%s from %d to %d", "opcode_lookup_table", "opcode_after_string" },
    };

}

namespace internal {

    auto internal() -> bool {
        logger::info("scanning internal addresses...");

        std::size_t found = 0;
        auto base = process::g_process.get_module_base();

        auto dos = process::g_process.read<IMAGE_DOS_HEADER>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
            logger::error("internal: invalid DOS header");
            return false;
        }

        auto nt = process::g_process.read<IMAGE_NT_HEADERS64>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
            logger::error("internal: invalid NT header");
            return false;
        }

        std::size_t module_size = nt->OptionalHeader.SizeOfImage;

        auto all_regions = get_scannable_regions(base, module_size);
        logger::info("internal: {} scannable regions", all_regions.size());

        auto text_section = process::g_process.get_section(".text");
        if (!text_section) {
            logger::error("internal: .text section not found");
            return false;
        }

        auto text_regions = get_scannable_regions(text_section->first, text_section->second);

        auto rdata_section = process::g_process.get_section(".rdata");
        std::vector<MEMORY_BASIC_INFORMATION> rdata_regions;
        if (rdata_section) {
            rdata_regions = get_scannable_regions(rdata_section->first, rdata_section->second);
        }

        std::set<std::string> found_names;

        for (const auto& pe : PATTERNS) {
            if (found_names.count(pe.name)) continue;

            auto [bytes, mask] = parse_pattern(pe.pattern);
            auto result = scan_for_pattern(text_regions, bytes, mask);

            if (result) {
                std::uintptr_t final_addr = *result;

                if (pe.rip_offset > 0) {
                    auto resolved = resolve_rip(*result, pe.rip_offset);
                    if (resolved) {
                        final_addr = *resolved;
                    }
                }

                std::uintptr_t offset = final_addr - base;
                dumper::g_dumper.add_offset("Internal", pe.name, offset);
                logger::info("  {} -> 0x{:X}", pe.name, offset);
                found++;
                found_names.insert(pe.name);
            }
        }

        for (const auto& pe : PATTERNS) {
            if (!found_names.count(pe.name)) {
                logger::warn("  {} -> pattern not found", pe.name);
            }
        }

        for (const auto& se : STRINGS) {
            if (found_names.count(se.name)) continue;

            auto str_addrs = scan_for_string(all_regions, se.str);
            if (str_addrs.empty()) {
                continue;
            }

            bool found_it = false;

            for (auto str_addr : str_addrs) {
                if (found_it) break;

                std::uintptr_t final_addr = 0;

                if (se.hint == "opcode_after_string") {
                    auto rdata_str = scan_for_string(rdata_regions, se.str);
                    if (!rdata_str.empty()) {
                        std::uintptr_t scan_addr = rdata_str[0] + se.str.length() + 1;
                        scan_addr = (scan_addr + 0xF) & ~0xF;

                        for (std::size_t off = 0; off < 0x100; off += 0x8) {
                            auto test_addr = scan_addr + off;
                            auto table_xrefs = scan_for_xrefs(text_regions, test_addr);
                            if (!table_xrefs.empty()) {
                                final_addr = test_addr;
                                break;
                            }
                        }
                    }

                    if (final_addr != 0) {
                        std::uintptr_t offset = final_addr - base;
                        dumper::g_dumper.add_offset("Internal", se.name, offset);
                        logger::info("  {} -> 0x{:X} (via string)", se.name, offset);
                        found++;
                        found_it = true;
                        found_names.insert(se.name);
                    }
                    continue;
                }

                auto xrefs = scan_for_xrefs(text_regions, str_addr);
                if (xrefs.empty()) continue;

                for (auto xref : xrefs) {
                    if (found_it) break;

                    std::uintptr_t func_start = get_function_start(xref);

                    if (se.hint == "func_start") {
                        final_addr = func_start;
                    }
                    else if (se.hint == "print_call") {
                        auto buffer = process::g_process.read_bytes(func_start, 0x200);
                        std::vector<std::uintptr_t> calls;

                        for (std::size_t i = 0; i + 5 <= buffer.size(); ++i) {
                            if (buffer[i] == 0xE8) {
                                std::int32_t disp;
                                std::memcpy(&disp, &buffer[i + 1], sizeof(disp));
                                auto target = func_start + i + 5 + disp;
                                calls.push_back(target);
                            }
                        }

                        if (calls.size() >= 2) {
                            final_addr = calls[1];
                        }
                        else if (!calls.empty()) {
                            final_addr = calls[0];
                        }
                    }
                    else if (se.hint == "identity_qword") {
                        auto buffer = process::g_process.read_bytes(func_start, 0x150);

                        for (std::size_t i = 0; i + 7 <= buffer.size(); ++i) {
                            if (buffer[i] == 0x48 && buffer[i + 1] == 0x8B && buffer[i + 2] == 0x0D) {
                                std::int32_t disp;
                                std::memcpy(&disp, &buffer[i + 3], sizeof(disp));
                                auto addr = func_start + i + 7 + disp;
                                final_addr = addr;
                                break;
                            }
                        }
                    }
                    else if (se.hint == "identity_func") {
                        auto call = find_first_call(func_start, 0x100);
                        if (call) {
                            final_addr = *call;
                        }
                    }
                    else if (se.hint == "fflag_param") {
                        auto buffer = process::g_process.read_bytes(func_start, 0x80);

                        for (std::size_t i = 0; i + 7 <= buffer.size(); ++i) {
                            bool is_lea = false;
                            if ((buffer[i] == 0x4C && buffer[i + 1] == 0x8D && buffer[i + 2] == 0x05) ||
                                (buffer[i] == 0x48 && buffer[i + 1] == 0x8D && buffer[i + 2] == 0x15) ||
                                (buffer[i] == 0x48 && buffer[i + 1] == 0x8D && buffer[i + 2] == 0x0D)) {
                                is_lea = true;
                            }

                            if (is_lea) {
                                std::int32_t disp;
                                std::memcpy(&disp, &buffer[i + 3], sizeof(disp));
                                auto addr = func_start + i + 7 + disp;
                                final_addr = addr;
                                break;
                            }
                        }
                    }
                    else if (se.hint == "lea_rcx_data") {
                        auto buffer = process::g_process.read_bytes(func_start, 0x400);
                        for (std::size_t i = 0; i + 7 <= buffer.size(); ++i) {
                            if (buffer[i] == 0x48 && buffer[i + 1] == 0x8D && buffer[i + 2] == 0x0D) {
                                std::int32_t disp;
                                std::memcpy(&disp, &buffer[i + 3], sizeof(disp));
                                auto addr = func_start + i + 7 + disp;
                                final_addr = addr;
                                break;
                            }
                        }
                    }
                    else if (se.hint == "mov_cs_qword") {
                        auto pat = find_pattern_near(xref, "48 89 05", 0x100);
                        if (pat) {
                            auto resolved = resolve_rip(*pat, 3);
                            if (resolved) final_addr = *resolved;
                        }
                    }
                    else if (se.hint == "last_call") {
                        auto call = find_last_call(func_start);
                        if (call) final_addr = *call;
                    }

                    if (final_addr != 0) {
                        std::uintptr_t offset = final_addr - base;
                        dumper::g_dumper.add_offset("Internal", se.name, offset);
                        logger::info("  {} -> 0x{:X}", se.name, offset);
                        found++;
                        found_it = true;
                        found_names.insert(se.name);
                    }
                }
            }

            if (!found_it) {
                logger::warn("  {} -> not found", se.name);
            }
        }

        logger::info("internal: found {} addresses", found);
        return found > 0;
    }

}