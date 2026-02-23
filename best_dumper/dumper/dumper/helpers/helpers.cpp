#include "helpers.h"
#include <algorithm>
#include <cmath>
#include "../../core/process/process.h"
#include "../../core/logger/logger.h"
#include "../../core/process/rtti/rtti.h"

namespace helpers {

    auto find_pointer_by_rtti(std::string_view section_name,
        const std::vector<std::string>& class_names,
        size_t alignment) -> std::unordered_map<std::string, std::optional<size_t>> {

        std::unordered_map<std::string, std::optional<size_t>> results;
        std::unordered_map<std::string, std::vector<uintptr_t>> all_matches;

        for (const auto& name : class_names) {
            results[name] = std::nullopt;
            all_matches[name] = {};
        }

        auto section = process::g_process.get_section(section_name);
        if (!section) {
            logger::error("failed to find section: {}", section_name);
            return results;
        }

        auto [section_start, section_size] = *section;
        auto module_base = process::g_process.get_module_base();

        for (size_t offset = 0; offset < section_size; offset += alignment) {
            auto ptr = process::g_process.read<uintptr_t>(section_start + offset);
            if (!ptr || *ptr < 0x10000) continue;

            auto info = rtti::scan(*ptr);
            if (!info) continue;

            for (const auto& name : class_names) {
                if (info->name == name) {
                    all_matches[name].push_back((section_start + offset) - module_base);
                }
            }
        }

        for (const auto& name : class_names) {
            auto& matches = all_matches[name];
            if (matches.empty()) continue;

            if (name == "DataModel@RBX") {
                std::sort(matches.begin(), matches.end(), std::greater<>());
                results[name] = (matches.size() >= 2) ? matches[1] : matches[0];
            }
            else {
                results[name] = matches[0];
            }
        }

        return results;
    }

    auto find_sso_string_offset(uintptr_t base_address, const std::string& target,
        size_t max_offset, size_t alignment) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto ptr = process::g_process.read<uintptr_t>(base_address + offset);
            if (!ptr || *ptr < 0x10000) continue;

            auto str = process::g_process.read_sso_string(*ptr);
            if (str && *str == target) {
                return offset;
            }
        }
        return std::nullopt;
    }

    auto find_children_offsets(uintptr_t instance, size_t parent_offset)
        -> std::optional<std::pair<size_t, size_t>> {
        for (size_t start_off = 0; start_off < 0x200; start_off += 0x8) {
            if (start_off == parent_offset) continue;

            auto start_ptr = process::g_process.read<uintptr_t>(instance + start_off);
            if (!start_ptr || *start_ptr < 0x10000) continue;

            for (size_t end_off = 0; end_off < 0x20; end_off += 0x8) {
                auto end_ptr = process::g_process.read<uintptr_t>(*start_ptr + end_off);
                if (!end_ptr || *end_ptr < 0x10000) continue;

                auto node_opt = process::g_process.read<uintptr_t>(*start_ptr);
                if (!node_opt) continue;

                size_t count = 0;
                uintptr_t node = *node_opt;
                bool valid = true;

                for (int i = 0; i < 1000 && node != *end_ptr; i++, node += 0x10) {
                    auto child = process::g_process.read<uintptr_t>(node);
                    if (!child || *child < 0x10000) { valid = false; break; }

                    auto vtable = process::g_process.read<uintptr_t>(*child);
                    if (!vtable || *vtable < 0x10000) { valid = false; break; }

                    count++;
                }

                if (valid && count >= 1 && count < 1000) {
                    return std::make_pair(start_off, end_off);
                }
            }
        }
        return std::nullopt;
    }

    template <typename T>
    auto find_offset(uintptr_t base_address, const T& value,
        size_t max_offset, size_t alignment) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto read_val = process::g_process.read<T>(base_address + offset);
            if (read_val && *read_val == value) {
                return offset;
            }
        }
        return std::nullopt;
    }

    template auto find_offset<int32_t>(uintptr_t, const int32_t&, size_t, size_t)->std::optional<size_t>;
    template auto find_offset<int64_t>(uintptr_t, const int64_t&, size_t, size_t)->std::optional<size_t>;
    template auto find_offset<uint32_t>(uintptr_t, const uint32_t&, size_t, size_t)->std::optional<size_t>;
    template auto find_offset<uint16_t>(uintptr_t, const uint16_t&, size_t, size_t)->std::optional<size_t>;

    auto find_float_offset(uintptr_t base_address, float value,
        size_t max_offset, size_t alignment, float tolerance)
        -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += alignment) {
            auto val = process::g_process.read<float>(base_address + offset);
            if (!val || std::isnan(*val) || std::isinf(*val)) continue;
            if (std::abs(*val - value) < tolerance) {
                return offset;
            }
        }
        return std::nullopt;
    }

    auto find_vec3_offset(uintptr_t base_address, float x, float y, float z,
        size_t max_offset, float tolerance) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += 4) {
            auto vx = process::g_process.read<float>(base_address + offset);
            auto vy = process::g_process.read<float>(base_address + offset + 4);
            auto vz = process::g_process.read<float>(base_address + offset + 8);

            if (!vx || !vy || !vz) continue;
            if (std::isnan(*vx) || std::isnan(*vy) || std::isnan(*vz)) continue;

            if (std::abs(*vx - x) < tolerance &&
                std::abs(*vy - y) < tolerance &&
                std::abs(*vz - z) < tolerance) {
                return offset;
            }
        }
        return std::nullopt;
    }

    auto find_vec2_offset(uintptr_t base_address, float x, float y,
        size_t max_offset, float tolerance) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset += 4) {
            auto vx = process::g_process.read<float>(base_address + offset);
            auto vy = process::g_process.read<float>(base_address + offset + 4);

            if (!vx || !vy) continue;
            if (std::isnan(*vx) || std::isnan(*vy)) continue;

            if (std::abs(*vx - x) < tolerance && std::abs(*vy - y) < tolerance) {
                return offset;
            }
        }
        return std::nullopt;
    }

    auto find_color3_offset(uintptr_t base_address, uint8_t r, uint8_t g, uint8_t b,
        size_t max_offset) -> std::optional<size_t> {
        for (size_t offset = 0; offset < max_offset; offset++) {
            auto cr = process::g_process.read<uint8_t>(base_address + offset);
            auto cg = process::g_process.read<uint8_t>(base_address + offset + 1);
            auto cb = process::g_process.read<uint8_t>(base_address + offset + 2);

            if (cr && cg && cb && *cr == r && *cg == g && *cb == b) {
                return offset;
            }
        }
        return std::nullopt;
    }

    template <typename T>
    auto find_offset_in_pointer(uintptr_t base_address, const T& value,
        size_t max_ptr_offset, size_t max_value_offset,
        size_t ptr_alignment, size_t value_alignment)
        -> std::optional<std::pair<size_t, size_t>> {
        for (size_t ptr_off = 0; ptr_off < max_ptr_offset; ptr_off += ptr_alignment) {
            auto ptr = process::g_process.read<uintptr_t>(base_address + ptr_off);
            if (!ptr || *ptr < 0x10000) continue;

            for (size_t val_off = 0; val_off < max_value_offset; val_off += value_alignment) {
                auto val = process::g_process.read<T>(*ptr + val_off);
                if (val && *val == value) {
                    return std::make_pair(ptr_off, val_off);
                }
            }
        }
        return std::nullopt;
    }

    template auto find_offset_in_pointer<int32_t>(uintptr_t, const int32_t&, size_t, size_t, size_t, size_t)
        ->std::optional<std::pair<size_t, size_t>>;
    template auto find_offset_in_pointer<uint32_t>(uintptr_t, const uint32_t&, size_t, size_t, size_t, size_t)
        ->std::optional<std::pair<size_t, size_t>>;
    template auto find_offset_in_pointer<int64_t>(uintptr_t, const int64_t&, size_t, size_t, size_t, size_t)
        ->std::optional<std::pair<size_t, size_t>>;

}