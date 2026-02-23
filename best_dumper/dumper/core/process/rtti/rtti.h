#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rtti {

    struct info {
        std::string name;
        uintptr_t type_desc;
        uintptr_t class_desc;
    };

    auto scan(uintptr_t addr) -> std::optional<info>;
    auto find(uintptr_t base, const std::string& target, size_t max = 0x1000, size_t align = 8) -> std::optional<size_t>;
    auto find_partial(uintptr_t base, const std::string& partial, size_t max = 0x1000, size_t align = 8) -> std::optional<size_t>;
    auto find_all(uintptr_t base, const std::string& target, size_t max = 0x1000, size_t align = 8) -> std::vector<size_t>;
    auto find_all_partial(uintptr_t base, const std::string& partial, size_t max = 0x1000, size_t align = 8) -> std::vector<size_t>;

}