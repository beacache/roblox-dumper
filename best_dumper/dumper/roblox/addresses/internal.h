#pragma once

#include <cstdint>

namespace addresses {

    namespace lua {
        inline std::uintptr_t print = 0;
        inline std::uintptr_t newstate = 0;
        inline std::uintptr_t newthread = 0;
        inline std::uintptr_t close = 0;
        inline std::uintptr_t getfield = 0;
        inline std::uintptr_t setfield = 0;
        inline std::uintptr_t pushvalue = 0;
        inline std::uintptr_t pushstring = 0;
        inline std::uintptr_t pushcclosure = 0;
        inline std::uintptr_t pcall = 0;
        inline std::uintptr_t rawcheckstack = 0;
        inline std::uintptr_t xmove = 0;
    }

    namespace luau {
        inline std::uintptr_t execute = 0;
        inline std::uintptr_t load = 0;
    }

    namespace luaL {
        inline std::uintptr_t argerrorL = 0;
        inline std::uintptr_t typeerrorL = 0;
        inline std::uintptr_t findtable = 0;
        inline std::uintptr_t where = 0;
        inline std::uintptr_t register_func = 0;
        inline std::uintptr_t checklstring = 0;
        inline std::uintptr_t checktype = 0;
    }

    namespace luaD {
        inline std::uintptr_t throw_error = 0;
        inline std::uintptr_t growstack = 0;
        inline std::uintptr_t rawrunprotected = 0;
    }

    namespace luaO {
        inline std::uintptr_t nilobject = 0;
        inline std::uintptr_t pushvfstring = 0;
    }

    namespace luaH {
        inline std::uintptr_t dummynode = 0;
    }

    namespace luaF {
        inline std::uintptr_t freeproto = 0;
        inline std::uintptr_t newproto = 0;
    }

    namespace luaG {
        inline std::uintptr_t runerrorL = 0;
    }

    namespace luaM {
        inline std::uintptr_t free_mem = 0;
        inline std::uintptr_t freegco = 0;
        inline std::uintptr_t visitgco = 0;
        inline std::uintptr_t toobig = 0;
    }

    namespace luaC {
        inline std::uintptr_t step = 0;
    }

    namespace luaA {
        inline std::uintptr_t toobject = 0;
    }

    namespace luaT {
        inline std::uintptr_t objtypename = 0;
    }

    namespace rbx {
        inline std::uintptr_t getscheduler = 0;
        inline std::uintptr_t getstate = 0;
        inline std::uintptr_t deserialize = 0;
        inline std::uintptr_t spawn = 0;
        inline std::uintptr_t console_print = 0;
    }

    namespace scriptcontext {
        inline std::uintptr_t resume = 0;
        inline std::uintptr_t getglobalstate = 0;
        inline std::uintptr_t getstate = 0;
    }

    namespace taskscheduler {
        inline std::uintptr_t singleton = 0;
        inline std::uintptr_t getscheduler = 0;
        inline std::uintptr_t fps_cap = 0;
    }

    namespace identity {
        inline std::uintptr_t ptr = 0;
        inline std::uintptr_t get_struct = 0;
        inline std::uintptr_t impersonator = 0;
        inline std::uintptr_t get_capabilities = 0;
    }

    namespace instance {
        inline std::uintptr_t push = 0;
        inline std::uintptr_t push2 = 0;
        inline std::uintptr_t get_property = 0;
        inline std::uintptr_t get_context_object = 0;
    }

    namespace fire {
        inline std::uintptr_t proximityprompt = 0;
        inline std::uintptr_t clickdetector = 0;
        inline std::uintptr_t touchinterest = 0;
        inline std::uintptr_t mouseclick = 0;
        inline std::uintptr_t rightmouseclick = 0;
        inline std::uintptr_t mousehoverenter = 0;
        inline std::uintptr_t mousehoverleave = 0;
    }

    namespace task {
        inline std::uintptr_t defer = 0;
        inline std::uintptr_t synchronize = 0;
        inline std::uintptr_t desynchronize = 0;
    }

    namespace module {
        inline std::uintptr_t get_from_vmstatemap = 0;
        inline std::uintptr_t get_values = 0;
    }

    namespace data {
        inline std::uintptr_t ktable = 0;
        inline std::uintptr_t appdata_info = 0;
        inline std::uintptr_t opcode_lookup = 0;
    }

    namespace fflags {
        inline std::uintptr_t get_fflag = 0;
        inline std::uintptr_t databank = 0;

        namespace internal {
            inline std::uintptr_t enable_load_module = 0;
            inline std::uintptr_t lock_violation_crash = 0;
            inline std::uintptr_t lock_violation_script_crash = 0;
            inline std::uintptr_t task_scheduler_target_fps = 0;
            inline std::uintptr_t physics_sender_max_bandwidth = 0;
        }
    }

    namespace misc {
        inline std::uintptr_t get_current_thread_id = 0;
        inline std::uintptr_t pseudo2addr = 0;
        inline std::uintptr_t auxopen = 0;
        inline std::uintptr_t currfuncname = 0;
    }

    namespace pointers {
        inline std::uintptr_t raw_scheduler = 0;
        inline std::uintptr_t fake_datamodel = 0;
    }

    namespace offsets {
        inline std::uintptr_t overlap = 0x288;
        inline std::uintptr_t primitive_touch = 0x178;
    }

}