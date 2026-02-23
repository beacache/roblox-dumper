#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace helpers {

    auto find_pointer_by_rtti(std::string_view section_name,
        const std::vector<std::string>& class_names,
        size_t alignment = 8)
        -> std::unordered_map<std::string, std::optional<size_t>>;

    auto find_sso_string_offset(uintptr_t base_address, const std::string& target,
        size_t max_offset = 0x1000, size_t alignment = 8)
        -> std::optional<size_t>;

    auto find_children_offsets(uintptr_t instance, size_t parent_offset)
        -> std::optional<std::pair<size_t, size_t>>;

    auto find_float_offset(uintptr_t base_address, float value,
        size_t max_offset = 0x1000, size_t alignment = 4,
        float tolerance = 0.01f) -> std::optional<size_t>;

    auto find_vec3_offset(uintptr_t base_address, float x, float y, float z,
        size_t max_offset = 0x1000, float tolerance = 5.0f)
        -> std::optional<size_t>;

    auto find_vec2_offset(uintptr_t base_address, float x, float y,
        size_t max_offset = 0x1000, float tolerance = 5.0f)
        -> std::optional<size_t>;

    auto find_color3_offset(uintptr_t base_address, uint8_t r, uint8_t g, uint8_t b,
        size_t max_offset = 0x300) -> std::optional<size_t>;

    template <typename T>
    auto find_offset(uintptr_t base_address, const T& value,
        size_t max_offset = 0x1000, size_t alignment = 8) -> std::optional<size_t>;

    template <typename T>
    auto find_offset_in_pointer(uintptr_t base_address, const T& value,
        size_t max_ptr_offset = 0x300, size_t max_value_offset = 0x100,
        size_t ptr_alignment = 8, size_t value_alignment = 4)
        -> std::optional<std::pair<size_t, size_t>>;

}