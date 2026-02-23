#include "config.h"
#include "dumper/dumper.h"
#include "dumper/stages/stages.h"
#include "core/logger/logger.h"
#include "writer/writer.h"
#include "core/process/process.h"
#include <iostream>
#include "dumper/fflags/fflags.h"

int main() {
    logger::initialize();

    logger::info("{} {}", config::PROJECT_NAME, config::PROJECT_VERSION);

    if (!process::g_process.attach(config::PROCESS_NAME)) {
        logger::error("failed to attach to {}", config::PROCESS_NAME);
        std::cin.get();
        return 1;
    }

    logger::info("pid -> {}", process::g_process.get_pid());
    logger::info("base -> 0x{:X}", process::g_process.get_module_base());

    auto version = process::g_process.get_version();
    if (version) logger::info("version -> {}", *version);

    logger::info("starting fflag dumper...");
    fflags::fflags();

    logger::info("starting offset dumper...");
    if (!dumper::g_dumper.run()) {
        logger::error("dumping failed");
    }

    writer::write_all("offsets", dumper::g_dumper.m_elapsed_time);

    size_t total_offsets = 0;
    size_t total_internal = 0;
    size_t total_fflags = 0;

    for (const auto& [ns, entries] : dumper::g_dumper.m_offsets) {
        if (ns == "FFlags") {
            total_fflags = entries.size();
            continue;
        }
        if (ns == "Internal") {
            total_internal = entries.size();
            logger::info("  {}: {} addresses", ns, entries.size());
            continue;
        }
        //logger::info("  {}: {} offsets", ns, entries.size());
        total_offsets += entries.size();
    }

    logger::info("");
    logger::info("summary:");
    logger::info("  offsets  : {}", total_offsets);
    logger::info("  internal : {}", total_internal);
    logger::info("  fflags   : {}", total_fflags);
    logger::info("  time     : {} ms", dumper::g_dumper.m_elapsed_time.count());

    logger::print_error_summary();

    logger::info("press enter to exit...");
    std::cin.get();
    return 0;
}