#include "pattern.h"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace scanner {

    Pattern::Pattern(const std::string& pattern_str, const std::string& pattern_name) {
        *this = parse_pattern(pattern_str);
        name = pattern_name;
    }

    auto Pattern::is_valid() const -> bool {
        return !bytes.empty() && bytes.size() == mask.size();
    }

    auto Pattern::size() const -> std::size_t {
        return bytes.size();
    }

    auto parse_pattern(const std::string& pattern_str) -> Pattern {
        Pattern result;
        std::istringstream stream(pattern_str);
        std::string token;

        while (stream >> token) {
            if (token == "?" || token == "??" || token == "*") {
                result.bytes.push_back(0x00);
                result.mask.push_back(false);
            }
            else {
                try {
                    auto byte = static_cast<std::uint8_t>(std::stoul(token, nullptr, 16));
                    result.bytes.push_back(byte);
                    result.mask.push_back(true);
                }
                catch (...) {
                    result.bytes.push_back(0x00);
                    result.mask.push_back(false);
                }
            }
        }

        return result;
    }

    auto parse_ida_pattern(const std::string& pattern_str) -> Pattern {
        std::string converted;
        for (std::size_t i = 0; i < pattern_str.size(); ++i) {
            char c = pattern_str[i];
            if (c == '?') {
                converted += "?? ";
            }
            else if (c == ' ') {
                continue;
            }
            else if (std::isxdigit(static_cast<unsigned char>(c))) {
                converted += c;
                if (i + 1 < pattern_str.size() && std::isxdigit(static_cast<unsigned char>(pattern_str[i + 1]))) {
                    converted += pattern_str[i + 1];
                    converted += ' ';
                    ++i;
                }
            }
        }
        return parse_pattern(converted);
    }

    auto parse_code_pattern(const std::string& bytes, const std::string& mask) -> Pattern {
        Pattern result;

        std::size_t len = (std::min)(bytes.size(), mask.size());
        result.bytes.reserve(len);
        result.mask.reserve(len);

        for (std::size_t i = 0; i < len; ++i) {
            result.bytes.push_back(static_cast<std::uint8_t>(bytes[i]));
            result.mask.push_back(mask[i] == 'x');
        }

        return result;
    }

}