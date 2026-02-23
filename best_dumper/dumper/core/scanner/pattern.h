#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace scanner {

    struct Pattern {
        std::vector<std::uint8_t> bytes;
        std::vector<bool> mask;
        std::string name;

        Pattern() = default;
        Pattern(const std::string& pattern_str, const std::string& name = "");

        auto is_valid() const -> bool;
        auto size() const -> std::size_t;
    };

    auto parse_pattern(const std::string& pattern_str) -> Pattern;
    auto parse_ida_pattern(const std::string& pattern_str) -> Pattern;
    auto parse_code_pattern(const std::string& bytes, const std::string& mask) -> Pattern;

}