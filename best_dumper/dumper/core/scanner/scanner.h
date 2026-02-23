#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "pattern.h"
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace scanner {

    struct ScanResult {
        std::uintptr_t address;
        std::string pattern_name;
        std::size_t index;
    };

    struct StringRef {
        std::uintptr_t string_address;
        std::uintptr_t xref_address;
        std::string content;
    };

    class Scanner {
    public:
        Scanner() = default;

        auto initialize(HANDLE handle, std::uintptr_t base, std::size_t size) -> bool;

        auto find_pattern(const Pattern& pattern, bool first_only = true) -> std::vector<ScanResult>;
        auto find_pattern(const std::string& pattern_str, bool first_only = true) -> std::vector<ScanResult>;

        auto find_pattern_in_section(const Pattern& pattern, const std::string& section, bool first_only = true) -> std::vector<ScanResult>;

        auto find_string(const std::string& str, bool null_terminated = true) -> std::vector<std::uintptr_t>;
        auto find_string_refs(const std::string& str) -> std::vector<StringRef>;

        auto find_xrefs(std::uintptr_t target, bool relative_only = true) -> std::vector<std::uintptr_t>;

        auto resolve_rip_relative(std::uintptr_t instruction_addr, std::size_t instruction_size = 7) -> std::optional<std::uintptr_t>;

        auto resolve_call(std::uintptr_t call_addr) -> std::optional<std::uintptr_t>;

        auto get_function_start(std::uintptr_t addr, std::size_t max_search = 0x1000) -> std::optional<std::uintptr_t>;

        auto read_bytes(std::uintptr_t addr, std::size_t size) -> std::vector<std::uint8_t>;

        auto get_section(const std::string& name) -> std::optional<std::pair<std::uintptr_t, std::size_t>>;

        auto get_base() const -> std::uintptr_t { return m_base; }
        auto get_size() const -> std::size_t { return m_size; }

    private:
        HANDLE m_handle = nullptr;
        std::uintptr_t m_base = 0;
        std::size_t m_size = 0;

        auto scan_region(std::uintptr_t start, std::size_t size, const Pattern& pattern, bool first_only) -> std::vector<ScanResult>;
        auto get_scannable_regions(std::uintptr_t start, std::size_t size) -> std::vector<MEMORY_BASIC_INFORMATION>;
    };

    inline Scanner g_scanner;

}