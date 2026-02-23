#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

typedef CLIENT_ID* PCLIENT_ID;

namespace process {

    class NtDll {
    public:
        NtDll();

        template <typename T = uintptr_t>
        auto get_export(const std::string& function_name) -> T {
            if (m_cache.find(function_name) == m_cache.end()) {
                m_cache[function_name] = reinterpret_cast<uintptr_t>(
                    GetProcAddress(m_module, function_name.c_str()));
            }
            return reinterpret_cast<T>(m_cache[function_name]);
        }

    private:
        HMODULE m_module;
        std::unordered_map<std::string, uintptr_t> m_cache;
    };

    class Process {
    public:
        Process() = default;
        ~Process();

        auto attach(std::string_view process_name) -> bool;
        auto get_pid() const -> DWORD { return m_pid; }
        auto get_handle() const -> HANDLE { return m_handle; }
        auto get_module_base() const -> uintptr_t { return m_module_base; }

        auto get_section(std::string_view section_name) const
            -> std::optional<std::pair<uintptr_t, size_t>>;
        auto get_window_dimensions() const -> std::optional<std::pair<float, float>>;
        auto get_version() const -> std::optional<std::string>;

        template <typename T>
        auto read(uintptr_t address) const -> std::optional<T> {
            using tNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
            static auto fn = m_ntdll.get_export<tNtReadVirtualMemory>("NtReadVirtualMemory");

            T buffer{};
            SIZE_T bytes_read = 0;

            NTSTATUS status = fn(m_handle, reinterpret_cast<PVOID>(address),
                &buffer, sizeof(T), &bytes_read);

            if (!NT_SUCCESS(status) || bytes_read != sizeof(T)) return std::nullopt;
            return buffer;
        }

        template <typename T>
        auto write(uintptr_t address, const T& value) const -> bool {
            using tNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
            static auto fn = m_ntdll.get_export<tNtWriteVirtualMemory>("NtWriteVirtualMemory");

            SIZE_T bytes_written = 0;
            NTSTATUS status = fn(m_handle, reinterpret_cast<PVOID>(address),
                const_cast<T*>(&value), sizeof(T), &bytes_written);

            return NT_SUCCESS(status) && bytes_written == sizeof(T);
        }

        auto read_bytes(uintptr_t address, size_t size) const -> std::vector<uint8_t>;
        auto read_string(uintptr_t address, size_t max_length = 256) const -> std::optional<std::string>;
        auto read_sso_string(uintptr_t address) const -> std::optional<std::string>;

        mutable NtDll m_ntdll;

    private:
        auto nt_open_process(DWORD pid) -> HANDLE;
        auto find_process_by_id(std::string_view process_name) -> std::optional<DWORD>;
        auto cache_module_info() -> bool;
        auto get_window_handle() const -> HWND;

        HANDLE m_handle{};
        DWORD m_pid{};
        uintptr_t m_module_base{};
        bool m_attached{};
    };

    inline Process g_process;

}