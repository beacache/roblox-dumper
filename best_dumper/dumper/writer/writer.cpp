#include "writer.h"
#include "../config.h"
#include "../dumper/dumper.h"
#include "../core/process/process.h"
#include "../core/logger/logger.h"
#include <algorithm>
#include <format>
#include <fstream>
#include <set>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace writer {

    static auto get_sorted_namespaces(bool exclude_fflags = true, bool exclude_internal = false)
        -> std::vector<std::pair<std::string, std::vector<dumper::OffsetEntry>>> {
        std::vector<std::pair<std::string, std::vector<dumper::OffsetEntry>>> sorted;

        for (const auto& [ns, entries] : dumper::g_dumper.m_offsets) {
            if (exclude_fflags && ns == "FFlags") continue;
            if (exclude_internal && ns == "Internal") continue;
            sorted.emplace_back(ns, entries);
        }

        std::sort(sorted.begin(), sorted.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

        for (auto& [ns, entries] : sorted) {
            std::set<std::string> seen;
            std::vector<dumper::OffsetEntry> unique;

            for (const auto& entry : entries) {
                if (seen.find(entry.name) == seen.end()) {
                    seen.insert(entry.name);
                    unique.push_back(entry);
                }
            }

            entries = unique;

            std::sort(entries.begin(), entries.end(),
                [](const auto& a, const auto& b) { return a.name < b.name; });
        }

        return sorted;
    }

    static auto get_fflags_sorted() -> std::vector<dumper::OffsetEntry> {
        auto it = dumper::g_dumper.m_offsets.find("FFlags");
        if (it == dumper::g_dumper.m_offsets.end()) return {};

        std::vector<dumper::OffsetEntry> entries = it->second;

        std::set<std::string> seen;
        std::vector<dumper::OffsetEntry> unique;
        for (const auto& entry : entries) {
            if (seen.find(entry.name) == seen.end()) {
                seen.insert(entry.name);
                unique.push_back(entry);
            }
        }

        std::sort(unique.begin(), unique.end(),
            [](const auto& a, const auto& b) { return a.name < b.name; });

        return unique;
    }

    static auto get_total_count(bool include_fflags = true, bool include_internal = true) -> size_t {
        size_t total = 0;
        for (const auto& [ns, entries] : dumper::g_dumper.m_offsets) {
            if (!include_fflags && ns == "FFlags") continue;
            if (!include_internal && ns == "Internal") continue;

            std::set<std::string> seen;
            for (const auto& entry : entries) {
                if (seen.find(entry.name) == seen.end()) {
                    seen.insert(entry.name);
                    total++;
                }
            }
        }
        return total;
    }

    static auto get_timestamp() -> std::string {
        auto now = std::time(nullptr);
        std::tm tm_buf;
        localtime_s(&tm_buf, &now);

        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%H:%M %d/%m/%Y") << " (GMT)";
        return oss.str();
    }

    void write_header(const std::string& filename, std::chrono::milliseconds elapsed) {
        auto version = process::g_process.get_version().value_or("unknown");
        auto total = get_total_count(false, false);
        auto timestamp = get_timestamp();

        std::string content;
        content += "#pragma once\n";
        content += "/* =============================================================\n";
        content += "                       " + std::string(config::PROJECT_NAME) + "                            \n";
        content += " -------------------------------------------------------------\n";
        content += "  Roblox Version  : " + version + "\n";
        content += "  Dumper Version  : " + std::string(config::PROJECT_VERSION) + "\n";
        content += "  Dumped At       : " + timestamp + "\n";
        content += "  Total Offsets   : " + std::to_string(total) + "\n";
        content += " -------------------------------------------------------------\n";
        content += " =============================================================\n";
        content += "*/\n\n";
        content += "#include <cstdint>\n";
        content += "#include <string>\n\n";
        content += "namespace Offsets {\n";
        content += "    inline std::string ClientVersion = \"" + version + "\";\n\n";

        for (const auto& [ns, entries] : get_sorted_namespaces(true, true)) {
            if (entries.empty()) continue;
            content += "    namespace " + ns + " {\n";
            for (const auto& e : entries) {
                content += std::format("        inline constexpr uintptr_t {} = 0x{:x};\n", e.name, e.offset);
            }
            content += "    }\n\n";
        }

        content += "}\n";

        std::ofstream(filename + ".hpp") << content;
        logger::info("wrote {}.hpp", filename);
    }

    void write_internal_header(const std::string& filename) {
        auto version = process::g_process.get_version().value_or("unknown");
        auto timestamp = get_timestamp();

        auto it = dumper::g_dumper.m_offsets.find("Internal");
        if (it == dumper::g_dumper.m_offsets.end()) return;

        auto internal = it->second;

        std::set<std::string> seen;
        std::vector<dumper::OffsetEntry> unique;
        for (const auto& entry : internal) {
            if (seen.find(entry.name) == seen.end()) {
                seen.insert(entry.name);
                unique.push_back(entry);
            }
        }

        std::sort(unique.begin(), unique.end(),
            [](const auto& a, const auto& b) { return a.name < b.name; });

        std::string content;
        content += "#pragma once\n";
        content += "/* =============================================================\n";
        content += "                       " + std::string(config::PROJECT_NAME) + "                            \n";
        content += " -------------------------------------------------------------\n";
        content += "  Roblox Version  : " + version + "\n";
        content += "  Dumper Version  : " + std::string(config::PROJECT_VERSION) + "\n";
        content += "  Dumped At       : " + timestamp + "\n";
        content += "  Total Offsets   : " + std::to_string(unique.size()) + "\n";
        content += " -------------------------------------------------------------\n";
        content += " =============================================================\n";
        content += "*/\n\n";
        content += "#include <cstdint>\n";
        content += "#include <string>\n\n";
        content += "namespace Internal {\n";
        content += "    inline std::string ClientVersion = \"" + version + "\";\n\n";

        for (const auto& e : unique) {
            content += std::format("    inline constexpr uintptr_t {} = 0x{:x};\n", e.name, e.offset);
        }

        content += "}\n";

        std::ofstream(filename + ".hpp") << content;
        logger::info("wrote {}.hpp ({} internal)", filename, unique.size());
    }

    void write_fflags_header(const std::string& filename) {
        auto version = process::g_process.get_version().value_or("unknown");
        auto timestamp = get_timestamp();
        auto fflags = get_fflags_sorted();

        if (fflags.empty()) return;

        std::string content;
        content += "#pragma once\n";
        content += "/* =============================================================\n";
        content += "                       " + std::string(config::PROJECT_NAME) + "                            \n";
        content += " -------------------------------------------------------------\n";
        content += "  Roblox Version  : " + version + "\n";
        content += "  Dumper Version  : " + std::string(config::PROJECT_VERSION) + "\n";
        content += "  Dumped At       : " + timestamp + "\n";
        content += "  Total Offsets   : " + std::to_string(fflags.size()) + "\n";
        content += " -------------------------------------------------------------\n";
        content += " =============================================================\n";
        content += "*/\n\n";
        content += "#include <cstdint>\n";
        content += "#include <string>\n\n";
        content += "namespace FFlags {\n";
        content += "    inline std::string ClientVersion = \"" + version + "\";\n\n";

        for (const auto& e : fflags) {
            content += std::format("    inline constexpr uintptr_t {} = 0x{:x};\n", e.name, e.offset);
        }

        content += "}\n";

        std::ofstream file(filename + ".hpp");
        if (!file.is_open()) return;

        file << content;
        file.close();

        logger::info("wrote {}.hpp ({} fflags)", filename, fflags.size());
    }

    void write_all(const std::string& filename, std::chrono::milliseconds elapsed) {
        write_header(filename, elapsed);
        write_internal_header("Internal");
        write_fflags_header("FFlags");
    }

}