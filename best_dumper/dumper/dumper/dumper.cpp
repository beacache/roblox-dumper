#include "dumper.h"
#include "stages/stages.h"
#include "../core/logger/logger.h"
#include "../roblox/offsets.h"
#include <chrono>
#include "internal/internal.h"

namespace dumper {

    auto Dumper::add_offset(const std::string& ns, const std::string& name, uintptr_t offset) -> void {
        std::lock_guard lock(m_mutex);
        for (const auto& e : m_offsets[ns]) {
            if (e.name == name) return;
        }
        m_offsets[ns].push_back({ name, offset });
    }

    auto Dumper::get_offset(const std::string& ns, const std::string& name) const -> std::optional<size_t> {
        std::lock_guard lock(m_mutex);
        auto it = m_offsets.find(ns);
        if (it == m_offsets.end()) return std::nullopt;
        for (const auto& e : it->second) {
            if (e.name == name) return e.offset;
        }
        return std::nullopt;
    }

    auto Dumper::run() -> bool {
        auto start = std::chrono::high_resolution_clock::now();

        std::vector<OffsetEntry> saved_fflags;
        auto fflag_it = m_offsets.find("FFlags");
        if (fflag_it != m_offsets.end()) {
            saved_fflags = fflag_it->second;
        }

        m_offsets.clear();

        if (!saved_fflags.empty()) {
            m_offsets["FFlags"] = saved_fflags;
        }

#define RUN_STAGE_CRITICAL(stage) \
    if (!stages::stage()) { \
        logger::error(#stage " failed"); \
        return false; \
    }

#define RUN_STAGE(stage) \
    if (!stages::stage()) { \
        logger::warn(#stage " failed"); \
    }

        RUN_STAGE(visual_engine);
        RUN_STAGE(task_scheduler);
        RUN_STAGE_CRITICAL(data_model);
        RUN_STAGE_CRITICAL(instance);

        g_data_model = roblox::Instance(g_data_model_addr);

        RUN_STAGE(workspace);
        RUN_STAGE(players);
        RUN_STAGE(lighting);
        RUN_STAGE(replicated_storage);
        RUN_STAGE(player);
        RUN_STAGE(camera);
        RUN_STAGE(humanoid);
        RUN_STAGE(base_part);
        RUN_STAGE(terrain);
        RUN_STAGE(sky);
        RUN_STAGE(team);
        RUN_STAGE(model);
        RUN_STAGE(scripts);
        RUN_STAGE(run_service);
        RUN_STAGE(mouse_service);
        RUN_STAGE(air_properties);
        RUN_STAGE(proximity_prompt);
        RUN_STAGE(click_detector);
        RUN_STAGE(seat);
        RUN_STAGE(sound);
        RUN_STAGE(post_effects);
        RUN_STAGE(mesh_part);
        RUN_STAGE(special_mesh);
        RUN_STAGE(decal_texture);
        RUN_STAGE(value_objects);
        RUN_STAGE(attachment);
        RUN_STAGE(spawn_location);
        RUN_STAGE(clothing);
        RUN_STAGE(tool);
        RUN_STAGE(character_mesh);
        RUN_STAGE(stats_item);
        RUN_STAGE(gui);
        RUN_STAGE(player_configurer);
        RUN_STAGE(highlight);
        RUN_STAGE(beam);
        RUN_STAGE(particle_emitter);
        RUN_STAGE(surface_gui);
        RUN_STAGE(billboard_gui);
        RUN_STAGE(weld_constraint);
        RUN_STAGE(body_velocity);
        RUN_STAGE(body_gyro);
        RUN_STAGE(force_field);
        RUN_STAGE(explosion);
        RUN_STAGE(fire);
        RUN_STAGE(smoke);
        RUN_STAGE(sparkles);
        RUN_STAGE(point_light);
        RUN_STAGE(starter_player);
        RUN_STAGE(backpack);
        RUN_STAGE(accessory);
        RUN_STAGE(head_accessory);

#undef RUN_STAGE
#undef RUN_STAGE_CRITICAL

        logger::info("starting internal offset dumper (8s)...");
        
        internal::internal();

        size_t total_offsets = 0;
        for (const auto& [ns, entries] : m_offsets) {
            if (ns != "FFlags" && ns != "Internal") {
                total_offsets += entries.size();
            }
        }
        logger::info("total offsets: {}", total_offsets);

        auto end = std::chrono::high_resolution_clock::now();
        m_elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        logger::info("dumping completed in {} ms", m_elapsed_time.count());
        return true;
    }


}
