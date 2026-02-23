#include "instance.h"
#include "../offsets.h"
#include "../../core/process/process.h"

namespace roblox {

    auto Instance::is_valid() const -> bool { return m_address != 0; }
    auto Instance::get_address() const -> uintptr_t { return m_address; }

    auto Instance::get_name() const -> std::optional<std::string> {
        if (!is_valid() || offsets::Instance::Name == 0) return std::nullopt;

        auto ptr = process::g_process.read<uintptr_t>(m_address + offsets::Instance::Name);
        if (!ptr || *ptr < 0x10000) return std::nullopt;

        return process::g_process.read_sso_string(*ptr);
    }

    auto Instance::get_class_name() const -> std::optional<std::string> {
        if (!is_valid() || offsets::Instance::ClassDescriptor == 0) return std::nullopt;

        auto desc = process::g_process.read<uintptr_t>(m_address + offsets::Instance::ClassDescriptor);
        if (!desc || *desc < 0x10000) return std::nullopt;

        auto name_ptr = process::g_process.read<uintptr_t>(*desc + offsets::Instance::ClassName);
        if (!name_ptr || *name_ptr < 0x10000) return std::nullopt;

        return process::g_process.read_sso_string(*name_ptr);
    }

    auto Instance::get_children() const -> std::vector<Instance> {
        std::vector<Instance> children;
        if (!is_valid() || offsets::Instance::ChildrenStart == 0) return children;

        auto start = process::g_process.read<uintptr_t>(m_address + offsets::Instance::ChildrenStart);
        if (!start || *start < 0x10000) return children;

        auto end = process::g_process.read<uintptr_t>(*start + offsets::Instance::ChildrenEnd);
        if (!end || *end < 0x10000) return children;

        auto current = process::g_process.read<uintptr_t>(*start);
        if (!current) return children;

        children.reserve(64);
        uintptr_t addr = *current;
        for (size_t i = 0; i < 8192 && addr != *end; i++, addr += 0x10) {
            auto child = process::g_process.read<uintptr_t>(addr);
            if (child && *child > 0x10000) {
                children.emplace_back(*child);
            }
        }

        return children;
    }

    auto Instance::get_parent() const -> std::optional<Instance> {
        if (!is_valid() || offsets::Instance::Parent == 0) return std::nullopt;

        auto parent = process::g_process.read<uintptr_t>(m_address + offsets::Instance::Parent);
        if (!parent || *parent < 0x10000) return std::nullopt;

        return Instance(*parent);
    }

    auto Instance::find_first_child(std::string_view name) const -> std::optional<Instance> {
        for (const auto& child : get_children()) {
            auto n = child.get_name();
            if (n && *n == name) return child;
        }
        return std::nullopt;
    }

    auto Instance::find_first_child_of_class(std::string_view class_name) const -> std::optional<Instance> {
        for (const auto& child : get_children()) {
            auto cn = child.get_class_name();
            if (cn && *cn == class_name) return child;
        }
        return std::nullopt;
    }

    auto Instance::find_first_descendant_of_class(std::string_view class_name, int depth) const -> std::optional<Instance> {
        if (depth <= 0) return std::nullopt;

        for (const auto& child : get_children()) {
            auto cn = child.get_class_name();
            if (cn && *cn == class_name) return child;

            auto desc = child.find_first_descendant_of_class(class_name, depth - 1);
            if (desc) return desc;
        }
        return std::nullopt;
    }

}