#include "logger.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <mutex>
#include <vector>

namespace logger {

    static std::vector<std::string> g_errors;
    static std::mutex g_mutex;
    static std::ofstream g_file;

    static auto get_timestamp() -> std::string {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::tm tm_buf;
        localtime_s(&tm_buf, &time);

        char buffer[32];
        std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm_buf);
        return std::format("{}.{:03d}", buffer, ms.count());
    }

    void initialize() {
        g_file.open("dumper.log", std::ios::out | std::ios::trunc);
    }

    void log(const std::string& message) {
        std::lock_guard lock(g_mutex);

        auto formatted = std::format("[{}] {}", get_timestamp(), message);
        std::cout << formatted << std::endl;

        if (g_file.is_open()) {
            g_file << formatted << std::endl;
        }

        if (message.find("[error]") != std::string::npos) {
            g_errors.push_back(formatted);
        }
    }

    void print_error_summary() {
        if (g_errors.empty()) {
            info("no errors");
            return;
        }

        warn("{} error(s):", g_errors.size());
        for (const auto& err : g_errors) {
            std::cout << "  " << err << std::endl;
        }
    }

}