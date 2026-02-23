#include "fflags.h"
#include "../dumper.h"
#include "../../core/logger/logger.h"
#include "../../core/process/process.h"
#include "../../core/process/rtti/rtti.h"

#include <vector>
#include <map>
#include <string>
#include <unordered_set>
#include <cstring>
#include <cstdint>

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
                mbi.BaseAddress >= reinterpret_cast<LPCVOID>(base) &&
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) < end) {
                regions.push_back(mbi);
            }

            current += mbi.RegionSize;
        }

        return regions;
    }

    auto scan_region_for_strings(std::uintptr_t region_start, std::size_t region_size, const std::string& target)
        -> std::vector<std::uintptr_t> {
        std::vector<std::uintptr_t> found;

        auto buffer = process::g_process.read_bytes(region_start, region_size);
        if (buffer.empty()) return found;

        for (std::size_t i = 0; i + target.size() <= buffer.size(); ++i) {
            if (std::memcmp(buffer.data() + i, target.data(), target.size()) == 0) {
                found.push_back(region_start + i);
            }
        }

        return found;
    }

    auto scan_region_for_xrefs(std::uintptr_t region_start, std::size_t region_size, std::uintptr_t target_address)
        -> std::vector<std::uintptr_t> {
        std::vector<std::uintptr_t> xrefs;

        if (region_size < sizeof(std::int32_t)) return xrefs;

        auto buffer = process::g_process.read_bytes(region_start, region_size);
        if (buffer.size() < sizeof(std::int32_t)) return xrefs;

        for (std::size_t i = 0; i + sizeof(std::int32_t) <= buffer.size(); ++i) {
            std::int32_t disp;
            std::memcpy(&disp, buffer.data() + i, sizeof(std::int32_t));

            std::uintptr_t potential_target = (region_start + i + sizeof(std::int32_t)) + disp;
            if (potential_target == target_address) {
                xrefs.push_back(region_start + i);
            }
        }

        return xrefs;
    }

    auto get_section_info(std::uintptr_t base, const std::string& section_name)
        -> std::pair<std::uintptr_t, std::size_t> {

        auto dos = process::g_process.read<IMAGE_DOS_HEADER>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return { 0, 0 };
        }

        auto nt = process::g_process.read<IMAGE_NT_HEADERS>(base + dos->e_lfanew);
        if (!nt) {
            return { 0, 0 };
        }

        std::uintptr_t section_table = base + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS);

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            auto section = process::g_process.read<IMAGE_SECTION_HEADER>(
                section_table + i * sizeof(IMAGE_SECTION_HEADER)
            );
            if (!section) continue;

            char name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
            std::memcpy(name, section->Name, IMAGE_SIZEOF_SHORT_NAME);

            if (_strcmpi(name, section_name.c_str()) == 0) {
                std::uintptr_t section_address = base + section->VirtualAddress;
                std::size_t section_size = section->Misc.VirtualSize;
                return { section_address, section_size };
            }
        }

        return { 0, 0 };
    }

    auto get_fflag_bank_offset() -> std::uintptr_t {
        const char* lookup = "DebugSkyGray";
        std::uintptr_t base = process::g_process.get_module_base();

        auto dos = process::g_process.read<IMAGE_DOS_HEADER>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
            logger::error("fflags: invalid DOS header");
            return 0;
        }

        auto nt = process::g_process.read<IMAGE_NT_HEADERS64>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
            logger::error("fflags: invalid NT header");
            return 0;
        }

        std::size_t module_size = nt->OptionalHeader.SizeOfImage;

        logger::info("fflags: scanning for '{}'...", lookup);

        auto regions = get_scannable_regions(base, module_size);
        logger::info("fflags: found {} scannable regions", regions.size());

        std::vector<std::uintptr_t> strings_found;
        for (const auto& region : regions) {
            auto region_base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = static_cast<std::size_t>(region.RegionSize);

            auto strings = scan_region_for_strings(region_base, region_size, lookup);
            for (auto str : strings) {
                strings_found.push_back(str);
            }
        }

        if (strings_found.empty()) {
            logger::error("fflags: string '{}' not found", lookup);
            return 0;
        }

        //logger::info("fflags: found {} instances of '{}'", strings_found.size(), lookup);

        auto text_section = get_section_info(base, ".text");
        if (!text_section.first || !text_section.second) {
            logger::error("fflags: failed to get .text section");
            return 0;
        }

        logger::info("fflags: .text section -> 0x{:X} (size: 0x{:X})",
            text_section.first - base, text_section.second);

        auto text_regions = get_scannable_regions(text_section.first, text_section.second);
        logger::info("fflags: scanning {} .text regions for xrefs...", text_regions.size());

        std::vector<std::uintptr_t> xrefs_found;
        for (const auto& region : text_regions) {
            auto region_base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = static_cast<std::size_t>(region.RegionSize);

            for (auto addr : strings_found) {
                auto xrefs = scan_region_for_xrefs(region_base, region_size, addr);
                xrefs_found.insert(xrefs_found.end(), xrefs.begin(), xrefs.end());
            }
        }

        if (xrefs_found.empty()) {
            logger::error("fflags: no xrefs found");
            return 0;
        }

        logger::info("fflags: found {} xrefs", xrefs_found.size());

        for (auto disp_address : xrefs_found) {
            constexpr std::size_t WINDOW_SIZE = 0x40;

            std::uintptr_t window_start = (disp_address >= (base + WINDOW_SIZE))
                ? (disp_address - WINDOW_SIZE)
                : base;

            std::size_t window_bytes = WINDOW_SIZE + sizeof(std::int32_t);
            auto buffer = process::g_process.read_bytes(window_start, window_bytes);
            if (buffer.size() < 8) continue;

            for (std::size_t offset = 0; offset + 7 < buffer.size(); ++offset) {
                if (buffer[offset] == 0x48 &&
                    buffer[offset + 1] == 0x8B &&
                    buffer[offset + 2] == 0x0D) {

                    std::int32_t disp;
                    std::memcpy(&disp, buffer.data() + offset + 3, sizeof(std::int32_t));

                    std::uintptr_t instr_runtime = window_start + offset;
                    std::uintptr_t rip_after_instr = instr_runtime + 7;
                    std::uintptr_t absolute_addr = rip_after_instr + disp;

                    if (absolute_addr >= base && absolute_addr < base + module_size) {
                        std::uintptr_t offset_from_base = absolute_addr - base;
                        logger::info("fflags: found bank at offset 0x{:X}", offset_from_base);
                        return offset_from_base;
                    }
                }
            }
        }

        logger::error("fflags: failed to find bank offset");
        return 0;
    }

}

namespace fflags {

    auto fflags() -> bool {
        logger::info("dumping fflags...");

        std::uintptr_t base = process::g_process.get_module_base();

        auto bank_offset = get_fflag_bank_offset();
        if (!bank_offset) {
            return false;
        }

        auto fflag_bank = process::g_process.read<std::uintptr_t>(base + bank_offset);
        if (!fflag_bank || *fflag_bank < 0x10000) {
            logger::error("fflags: failed to read fflag bank pointer");
            return false;
        }

        logger::info("fflags: bank pointer -> 0x{:X}", *fflag_bank);

        auto buckets_ptr = process::g_process.read<std::uintptr_t>(*fflag_bank + 0x18);
        auto bucket_mask = process::g_process.read<std::uintptr_t>(*fflag_bank + 0x30);

        if (!buckets_ptr || !bucket_mask) {
            logger::error("fflags: failed to read bucket info");
            return false;
        }

        std::size_t bucket_count = *bucket_mask + 1;
        logger::info("fflags: {} buckets at 0x{:X}", bucket_count, *buckets_ptr);

        std::unordered_set<std::uintptr_t> visited_nodes;
        std::uintptr_t rva_offset = 0;
        std::size_t count = 0;

        auto dos = process::g_process.read<IMAGE_DOS_HEADER>(base);
        auto nt = process::g_process.read<IMAGE_NT_HEADERS64>(base + dos->e_lfanew);
        std::size_t module_size = nt->OptionalHeader.SizeOfImage;

        std::map<std::string, std::uintptr_t> collected_fflags;

        for (std::size_t bucket_idx = 0; bucket_idx < bucket_count; ++bucket_idx) {
            std::uintptr_t bucket_offset_addr = *buckets_ptr + (bucket_idx * 0x10);
            auto first_node = process::g_process.read<std::uintptr_t>(bucket_offset_addr);
            auto last_node = process::g_process.read<std::uintptr_t>(bucket_offset_addr + 0x8);

            if (!first_node || !last_node || *first_node == *last_node) continue;

            std::uintptr_t current_node = *first_node;

            while (current_node != *last_node && current_node) {
                if (visited_nodes.find(current_node) != visited_nodes.end()) break;
                visited_nodes.insert(current_node);

                auto len = process::g_process.read<std::uintptr_t>(current_node + 0x20);
                if (!len || *len == 0 || *len > 1000) {
                    auto next_node = process::g_process.read<std::uintptr_t>(current_node + 0x8);
                    if (!next_node || *next_node == *first_node) break;
                    current_node = *next_node;
                    continue;
                }

                auto fflag_name = process::g_process.read_sso_string(current_node + 0x10);
                if (!fflag_name || fflag_name->empty()) {
                    auto next_node = process::g_process.read<std::uintptr_t>(current_node + 0x8);
                    if (!next_node || *next_node == *first_node) break;
                    current_node = *next_node;
                    continue;
                }

                auto getset = process::g_process.read<std::uintptr_t>(current_node + 0x30);
                if (getset && *getset > 0x10000) {
                    auto info = rtti::scan(*getset);
                    if (info && info->name.find("UnregisteredValueGetSet") != std::string::npos) {
                        auto next_node = process::g_process.read<std::uintptr_t>(current_node + 0x8);
                        if (!next_node || *next_node == *first_node) break;
                        current_node = *next_node;
                        continue;
                    }

                    if (!rva_offset) {
                        for (std::size_t off = 0x8; off < 0x1000; off += 0x8) {
                            auto absolute = process::g_process.read<std::uintptr_t>(*getset + off);
                            if (absolute && *absolute >= base && *absolute < base + module_size) {
                                rva_offset = off;
                                logger::info("fflags: rva offset -> 0x{:X}", rva_offset);
                                break;
                            }
                        }
                    }

                    if (rva_offset) {
                        auto absolute = process::g_process.read<std::uintptr_t>(*getset + rva_offset);
                        if (absolute && *absolute >= base && *absolute < base + module_size) {
                            std::uintptr_t fflag_pointer = *absolute - base;
                            collected_fflags[*fflag_name] = fflag_pointer;
                            count++;
                        }
                    }
                }

                auto next_node = process::g_process.read<std::uintptr_t>(current_node + 0x8);
                if (!next_node || *next_node == *first_node) break;
                current_node = *next_node;
            }
        }

        logger::info("fflags: adding {} flags to dumper", collected_fflags.size());

        for (const auto& [name, offset] : collected_fflags) {
            dumper::g_dumper.add_offset("FFlags", name, offset);
        }

        auto it = dumper::g_dumper.m_offsets.find("FFlags");
        if (it != dumper::g_dumper.m_offsets.end()) {
            logger::info("fflags: verified {} flags in dumper", it->second.size());
        }
        else {
            logger::error("fflags: FAILED to add flags to dumper!");
        }

        logger::info("fflags: found {} flags", count);
        return count > 0;
    }

}