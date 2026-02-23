#pragma once

#include <string>
#include <format>

namespace logger {

    void initialize();
    void log(const std::string& message);
    void print_error_summary();

    template <typename... Args>
    inline void info(std::format_string<Args...> fmt, Args&&... args) {
        log(std::format(fmt, std::forward<Args>(args)...));
    }

    template <typename... Args>
    inline void error(std::format_string<Args...> fmt, Args&&... args) {
        log("[error] " + std::format(fmt, std::forward<Args>(args)...));
    }

    template <typename... Args>
    inline void warn(std::format_string<Args...> fmt, Args&&... args) {
        log("[warn] " + std::format(fmt, std::forward<Args>(args)...));
    }

}