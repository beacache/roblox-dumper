#include "scanner.h"
#include <cstring>
#include <algorithm>

namespace scanner {

    auto Scanner::initialize(HANDLE handle, std::uintptr_t base, std::size_t size) -> bool {
        m_handle = handle;
        m_base = base;
        m_size = size;
        return m_handle != nullptr && m_base != 0 && m_size != 0;
    }

    auto Scanner::read_bytes(std::uintptr_t addr, std::size_t size) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> buffer(size);
        SIZE_T bytes_read = 0;

        if (!ReadProcessMemory(m_handle, reinterpret_cast<LPCVOID>(addr), buffer.data(), size, &bytes_read)) {
            return {};
        }

        buffer.resize(bytes_read);
        return buffer;
    }

    auto Scanner::get_scannable_regions(std::uintptr_t start, std::size_t size) -> std::vector<MEMORY_BASIC_INFORMATION> {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
        std::uintptr_t current = start;
        std::uintptr_t end = start + size;

        while (current < end) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(m_handle, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi)) == 0) {
                break;
            }

            if ((mbi.State == MEM_COMMIT) &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS)) {

                auto region_start = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                auto region_end = region_start + mbi.RegionSize;

                if (region_start < start) region_start = start;
                if (region_end > end) region_end = end;

                if (region_start < region_end) {
                    mbi.BaseAddress = reinterpret_cast<PVOID>(region_start);
                    mbi.RegionSize = region_end - region_start;
                    regions.push_back(mbi);
                }
            }

            current += mbi.RegionSize;
        }

        return regions;
    }

    auto Scanner::scan_region(std::uintptr_t start, std::size_t size, const Pattern& pattern, bool first_only) -> std::vector<ScanResult> {
        std::vector<ScanResult> results;

        if (!pattern.is_valid() || size < pattern.size()) {
            return results;
        }

        auto buffer = read_bytes(start, size);
        if (buffer.size() < pattern.size()) {
            return results;
        }

        const auto& pat_bytes = pattern.bytes;
        const auto& pat_mask = pattern.mask;
        std::size_t pat_size = pattern.size();

        for (std::size_t i = 0; i <= buffer.size() - pat_size; ++i) {
            bool found = true;

            for (std::size_t j = 0; j < pat_size; ++j) {
                if (pat_mask[j] && buffer[i + j] != pat_bytes[j]) {
                    found = false;
                    break;
                }
            }

            if (found) {
                ScanResult result;
                result.address = start + i;
                result.pattern_name = pattern.name;
                result.index = results.size();
                results.push_back(result);

                if (first_only) {
                    return results;
                }
            }
        }

        return results;
    }

    auto Scanner::find_pattern(const Pattern& pattern, bool first_only) -> std::vector<ScanResult> {
        std::vector<ScanResult> results;

        auto regions = get_scannable_regions(m_base, m_size);

        for (const auto& region : regions) {
            auto region_start = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = region.RegionSize;

            auto found = scan_region(region_start, region_size, pattern, first_only);
            results.insert(results.end(), found.begin(), found.end());

            if (first_only && !results.empty()) {
                return results;
            }
        }

        return results;
    }

    auto Scanner::find_pattern(const std::string& pattern_str, bool first_only) -> std::vector<ScanResult> {
        return find_pattern(parse_pattern(pattern_str), first_only);
    }

    auto Scanner::find_pattern_in_section(const Pattern& pattern, const std::string& section, bool first_only) -> std::vector<ScanResult> {
        auto sec = get_section(section);
        if (!sec) {
            return {};
        }

        auto regions = get_scannable_regions(sec->first, sec->second);
        std::vector<ScanResult> results;

        for (const auto& region : regions) {
            auto region_start = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = region.RegionSize;

            auto found = scan_region(region_start, region_size, pattern, first_only);
            results.insert(results.end(), found.begin(), found.end());

            if (first_only && !results.empty()) {
                return results;
            }
        }

        return results;
    }

    auto Scanner::find_string(const std::string& str, bool null_terminated) -> std::vector<std::uintptr_t> {
        std::vector<std::uintptr_t> results;

        auto regions = get_scannable_regions(m_base, m_size);

        for (const auto& region : regions) {
            auto region_start = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = region.RegionSize;

            auto buffer = read_bytes(region_start, region_size);
            if (buffer.size() < str.size()) continue;

            for (std::size_t i = 0; i + str.size() <= buffer.size(); ++i) {
                if (std::memcmp(&buffer[i], str.data(), str.size()) == 0) {
                    if (!null_terminated || (i + str.size() < buffer.size() && buffer[i + str.size()] == 0)) {
                        results.push_back(region_start + i);
                    }
                }
            }
        }

        return results;
    }

    auto Scanner::find_xrefs(std::uintptr_t target, bool relative_only) -> std::vector<std::uintptr_t> {
        std::vector<std::uintptr_t> results;

        auto text_section = get_section(".text");
        if (!text_section) {
            return results;
        }

        auto regions = get_scannable_regions(text_section->first, text_section->second);

        for (const auto& region : regions) {
            auto region_start = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            auto region_size = region.RegionSize;

            auto buffer = read_bytes(region_start, region_size);
            if (buffer.size() < sizeof(std::int32_t)) continue;

            for (std::size_t i = 0; i + sizeof(std::int32_t) <= buffer.size(); ++i) {
                std::int32_t disp;
                std::memcpy(&disp, &buffer[i], sizeof(std::int32_t));

                std::uintptr_t resolved = region_start + i + sizeof(std::int32_t) + disp;

                if (resolved == target) {
                    results.push_back(region_start + i);
                }
            }
        }

        return results;
    }

    auto Scanner::find_string_refs(const std::string& str) -> std::vector<StringRef> {
        std::vector<StringRef> results;

        auto string_addrs = find_string(str);

        for (auto str_addr : string_addrs) {
            auto xrefs = find_xrefs(str_addr);

            for (auto xref : xrefs) {
                StringRef ref;
                ref.string_address = str_addr;
                ref.xref_address = xref;
                ref.content = str;
                results.push_back(ref);
            }
        }

        return results;
    }

    auto Scanner::resolve_rip_relative(std::uintptr_t instruction_addr, std::size_t instruction_size) -> std::optional<std::uintptr_t> {
        auto bytes = read_bytes(instruction_addr, instruction_size);
        if (bytes.size() < instruction_size) {
            return std::nullopt;
        }

        std::size_t disp_offset = 3;

        if (bytes.size() >= 2) {
            if (bytes[0] == 0xE8 || bytes[0] == 0xE9) {
                disp_offset = 1;
                instruction_size = 5;
            }
            else if ((bytes[0] & 0xF0) == 0x70 || bytes[0] == 0xEB) {
                return std::nullopt;
            }
        }

        if (disp_offset + sizeof(std::int32_t) > bytes.size()) {
            return std::nullopt;
        }

        std::int32_t disp;
        std::memcpy(&disp, &bytes[disp_offset], sizeof(std::int32_t));

        return instruction_addr + instruction_size + disp;
    }

    auto Scanner::resolve_call(std::uintptr_t call_addr) -> std::optional<std::uintptr_t> {
        auto bytes = read_bytes(call_addr, 5);
        if (bytes.size() < 5) {
            return std::nullopt;
        }

        if (bytes[0] != 0xE8) {
            return std::nullopt;
        }

        std::int32_t disp;
        std::memcpy(&disp, &bytes[1], sizeof(std::int32_t));

        return call_addr + 5 + disp;
    }

    auto Scanner::get_function_start(std::uintptr_t addr, std::size_t max_search) -> std::optional<std::uintptr_t> {
        const std::vector<std::vector<std::uint8_t>> prologues = {
            { 0x40, 0x53 }, { 0x40, 0x55 }, { 0x40, 0x56 }, { 0x40, 0x57 },
            { 0x48, 0x83, 0xEC }, { 0x48, 0x81, 0xEC },
            { 0x48, 0x89, 0x5C, 0x24 }, { 0x55 }, { 0x56 }, { 0x57 },
            { 0x41, 0x54 }, { 0x41, 0x55 }, { 0x41, 0x56 }, { 0x41, 0x57 },
            { 0x48, 0x8B, 0xC4 }, { 0x4C, 0x8B, 0xDC },
        };

        auto buffer = read_bytes(addr - max_search, max_search);
        if (buffer.empty()) {
            return std::nullopt;
        }

        for (std::size_t offset = buffer.size(); offset > 0; --offset) {
            std::size_t idx = offset - 1;

            if (buffer[idx] == 0xCC) {
                if (idx + 1 < buffer.size()) {
                    return addr - max_search + idx + 1;
                }
            }

            for (const auto& prologue : prologues) {
                if (idx + prologue.size() <= buffer.size()) {
                    bool match = true;
                    for (std::size_t j = 0; j < prologue.size(); ++j) {
                        if (buffer[idx + j] != prologue[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        if (idx > 0) {
                            std::uint8_t prev = buffer[idx - 1];
                            if (prev == 0xC3 || prev == 0xCC || prev == 0x90 || prev == 0x00) {
                                return addr - max_search + idx;
                            }
                        }
                    }
                }
            }
        }

        return std::nullopt;
    }

    auto Scanner::get_section(const std::string& name) -> std::optional<std::pair<std::uintptr_t, std::size_t>> {
        auto dos_bytes = read_bytes(m_base, sizeof(IMAGE_DOS_HEADER));
        if (dos_bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
            return std::nullopt;
        }

        IMAGE_DOS_HEADER dos;
        std::memcpy(&dos, dos_bytes.data(), sizeof(dos));

        if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
            return std::nullopt;
        }

        auto nt_bytes = read_bytes(m_base + dos.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
        if (nt_bytes.size() < sizeof(IMAGE_NT_HEADERS64)) {
            return std::nullopt;
        }

        IMAGE_NT_HEADERS64 nt;
        std::memcpy(&nt, nt_bytes.data(), sizeof(nt));

        if (nt.Signature != IMAGE_NT_SIGNATURE) {
            return std::nullopt;
        }

        std::uintptr_t section_table = m_base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

        for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            auto sec_bytes = read_bytes(section_table + i * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER));
            if (sec_bytes.size() < sizeof(IMAGE_SECTION_HEADER)) {
                continue;
            }

            IMAGE_SECTION_HEADER section;
            std::memcpy(&section, sec_bytes.data(), sizeof(section));

            char sec_name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
            std::memcpy(sec_name, section.Name, IMAGE_SIZEOF_SHORT_NAME);

            if (_stricmp(sec_name, name.c_str()) == 0) {
                return std::make_pair(m_base + section.VirtualAddress, static_cast<std::size_t>(section.Misc.VirtualSize));
            }
        }

        return std::nullopt;
    }

}