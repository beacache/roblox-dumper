#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace roblox {

    class Instance {
    public:
        Instance() = default;
        explicit Instance(uintptr_t address) : m_address(address) {}

        auto is_valid() const -> bool;
        auto get_address() const -> uintptr_t;
        auto get_name() const -> std::optional<std::string>;
        auto get_class_name() const -> std::optional<std::string>;
        auto get_children() const -> std::vector<Instance>;
        auto get_parent() const -> std::optional<Instance>;
        auto find_first_child(std::string_view name) const -> std::optional<Instance>;
        auto find_first_child_of_class(std::string_view class_name) const -> std::optional<Instance>;
        auto find_first_descendant_of_class(std::string_view class_name, int depth = 10) const -> std::optional<Instance>;

    private:
        uintptr_t m_address = 0;
    };

}