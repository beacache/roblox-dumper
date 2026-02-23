#pragma once

#include "../roblox/instance/instance.h"
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dumper {

    struct OffsetEntry {
        std::string name;
        uintptr_t offset;
    };

    inline uintptr_t g_data_model_addr = 0;
    inline uintptr_t g_visual_engine_addr = 0;
    inline std::optional<roblox::Instance> g_data_model;
    inline std::optional<roblox::Instance> g_workspace;
    inline std::optional<roblox::Instance> g_players;
    inline std::optional<roblox::Instance> g_lighting;
    inline std::optional<roblox::Instance> g_replicated_storage;

    class Dumper {
    public:
        auto run() -> bool;
        auto add_offset(const std::string& ns, const std::string& name, uintptr_t offset) -> void;
        auto get_offset(const std::string& ns, const std::string& name) const -> std::optional<size_t>;

        std::unordered_map<std::string, std::vector<OffsetEntry>> m_offsets;
        std::chrono::milliseconds m_elapsed_time{};

    private:
        mutable std::mutex m_mutex;
    };

    inline Dumper g_dumper;

}