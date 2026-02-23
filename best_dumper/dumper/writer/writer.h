#pragma once

#include <chrono>
#include <string>

namespace writer {

    void write_header(const std::string& file, std::chrono::milliseconds time);
    void write_internal_header(const std::string& file);
    void write_fflags_header(const std::string& file);
    void write_all(const std::string& file, std::chrono::milliseconds time);

}