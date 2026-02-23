#include "rtti.h"
#include "../process.h"
#include <cstring>

namespace rtti {

    struct col_t {
        uint32_t sig;
        uint32_t offset;
        uint32_t cd_offset;
        int type_desc_off;
        int class_desc_off;
        int self_off;
    };

    auto scan(uintptr_t addr) -> std::optional<info> {
        auto vt = process::g_process.read<uintptr_t>(addr);
        if (!vt || *vt < 0x10000) return std::nullopt;

        auto col_ptr = process::g_process.read<uintptr_t>(*vt - 8);
        if (!col_ptr || *col_ptr < 0x10000) return std::nullopt;

        auto sig = process::g_process.read<uint32_t>(*col_ptr);
        if (!sig || *sig != 1) return std::nullopt;

        auto self_off = process::g_process.read<int>(*col_ptr + 0x14);
        if (!self_off) return std::nullopt;

        uintptr_t mod_base = *col_ptr - *self_off;

        auto col_bytes = process::g_process.read_bytes(*col_ptr, sizeof(col_t));
        if (col_bytes.size() < sizeof(col_t)) return std::nullopt;

        col_t col;
        std::memcpy(&col, col_bytes.data(), sizeof(col));

        info i{};
        i.type_desc = mod_base + col.type_desc_off;
        i.class_desc = mod_base + col.class_desc_off;

        auto td_bytes = process::g_process.read_bytes(i.type_desc, 280);
        if (td_bytes.size() < 280) return std::nullopt;

        std::string raw((const char*)td_bytes.data() + 16, strnlen((const char*)td_bytes.data() + 16, 255));

        if (raw.size() > 4 && raw.substr(0, 4) == ".?AV") {
            raw = raw.substr(4);
        }

        auto at = raw.find("@@");
        if (at != std::string::npos) {
            raw = raw.substr(0, at);
        }

        i.name = raw;
        return i;
    }

    auto find(uintptr_t base, const std::string& target, size_t max, size_t align) -> std::optional<size_t> {
        for (size_t off = 0; off < max; off += align) {
            auto ptr = process::g_process.read<uintptr_t>(base + off);
            if (!ptr || *ptr < 0x10000) continue;

            auto i = scan(*ptr);
            if (i && i->name == target) return off;
        }
        return std::nullopt;
    }

    auto find_partial(uintptr_t base, const std::string& partial, size_t max, size_t align) -> std::optional<size_t> {
        for (size_t off = 0; off < max; off += align) {
            auto ptr = process::g_process.read<uintptr_t>(base + off);
            if (!ptr || *ptr < 0x10000) continue;

            auto i = scan(*ptr);
            if (i && i->name.find(partial) != std::string::npos) return off;
        }
        return std::nullopt;
    }

    auto find_all(uintptr_t base, const std::string& target, size_t max, size_t align) -> std::vector<size_t> {
        std::vector<size_t> results;
        for (size_t off = 0; off < max; off += align) {
            auto ptr = process::g_process.read<uintptr_t>(base + off);
            if (!ptr || *ptr < 0x10000) continue;

            auto i = scan(*ptr);
            if (i && i->name == target) {
                results.push_back(off);
            }
        }
        return results;
    }

    auto find_all_partial(uintptr_t base, const std::string& partial, size_t max, size_t align) -> std::vector<size_t> {
        std::vector<size_t> results;
        for (size_t off = 0; off < max; off += align) {
            auto ptr = process::g_process.read<uintptr_t>(base + off);
            if (!ptr || *ptr < 0x10000) continue;

            auto i = scan(*ptr);
            if (i && i->name.find(partial) != std::string::npos) {
                results.push_back(off);
            }
        }
        return results;
    }

}