#include "stages.h"
#include "../dumper.h"
#include "../helpers/helpers.h"
#include "../../core/process/process.h"
#include "../../core/logger/logger.h"
#include "../../core/process/rtti/rtti.h"
#include "../../roblox/offsets.h"
#include <cmath>
#include <functional>
#include <algorithm>
#include <cctype>

namespace stages {

    static std::function<std::optional<roblox::Instance>(const roblox::Instance&, const std::string&, int)> find_descendant;

    static void init_helpers() {
        find_descendant = [](const roblox::Instance& p, const std::string& cls, int d) -> std::optional<roblox::Instance> {
            if (d <= 0) return std::nullopt;
            for (const auto& c : p.get_children()) {
                auto cn = c.get_class_name();
                if (cn && *cn == cls) return c;
                auto r = find_descendant(c, cls, d - 1);
                if (r) return r;
            }
            return std::nullopt;
            };
    }

    static bool is_valid_float(float v) {
        return !std::isnan(v) && !std::isinf(v);
    }

    static bool is_valid_rotation_matrix(uintptr_t addr) {
        for (int i = 0; i < 9; i++) {
            auto v = process::g_process.read<float>(addr + i * 4);
            if (!v || !is_valid_float(*v) || std::abs(*v) > 1.1f) return false;
        }
        return true;
    }

    static bool is_valid_position(uintptr_t addr, float max_range = 50000.0f) {
        for (int i = 0; i < 3; i++) {
            auto v = process::g_process.read<float>(addr + i * 4);
            if (!v || !is_valid_float(*v) || std::abs(*v) > max_range) return false;
        }
        return true;
    }

    static bool is_valid_color3(uintptr_t addr) {
        for (int i = 0; i < 3; i++) {
            auto v = process::g_process.read<float>(addr + i * 4);
            if (!v || *v < 0.0f || *v > 1.0f) return false;
        }
        return true;
    }

    static bool is_valid_normalized_vector(uintptr_t addr) {
        float sum = 0.0f;
        for (int i = 0; i < 3; i++) {
            auto v = process::g_process.read<float>(addr + i * 4);
            if (!v || !is_valid_float(*v) || std::abs(*v) > 1.1f) return false;
            sum += (*v) * (*v);
        }
        return std::abs(sum - 1.0f) < 0.2f || sum < 1.2f;
    }

    static bool is_valid_udim2(uintptr_t addr, bool allow_negative = false) {
        auto sx = process::g_process.read<float>(addr);
        auto ox = process::g_process.read<int32_t>(addr + 4);
        auto sy = process::g_process.read<float>(addr + 8);
        auto oy = process::g_process.read<int32_t>(addr + 12);
        if (!sx || !ox || !sy || !oy) return false;
        if (*sx < -10.0f || *sx > 100.0f || *sy < -10.0f || *sy > 100.0f) return false;
        if (!allow_negative && (*ox < -10000 || *oy < -10000)) return false;
        if (std::abs(*ox) > 10000 || std::abs(*oy) > 10000) return false;
        return true;
    }

    static bool is_valid_guid(const std::string& str) {
        if (str.length() != 36) return false;
        for (size_t i = 0; i < str.length(); ++i) {
            char c = str[i];
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') return false;
            }
            else {
                if (!std::isxdigit(c)) return false;
            }
        }
        return true;
    }

    static std::optional<roblox::Instance> find_instance_by_class(const std::string& class_name, int depth = 6) {
        if (!dumper::g_workspace) return std::nullopt;
        for (const auto& c : dumper::g_workspace->get_children()) {
            auto cn = c.get_class_name();
            if (cn && *cn == class_name) return c;
        }
        return dumper::g_workspace->find_first_descendant_of_class(class_name, depth);
    }

    auto visual_engine() -> bool {
        init_helpers();

        auto results = helpers::find_pointer_by_rtti(".data", {
            "VisualEngine@Graphics@RBX",
            "DataModel@RBX"
            });

        auto ve_offset = results["VisualEngine@Graphics@RBX"];
        if (!ve_offset) return false;

        dumper::g_dumper.add_offset("VisualEngine", "Pointer", *ve_offset);
        offsets::VisualEngine::Pointer = *ve_offset;

        auto fake_dm_offset = results["DataModel@RBX"];
        if (fake_dm_offset) {
            dumper::g_dumper.add_offset("FakeDataModel", "Pointer", *fake_dm_offset);
        }

        auto module_base = process::g_process.get_module_base();
        auto ve_addr = process::g_process.read<uintptr_t>(module_base + *ve_offset);
        if (!ve_addr) return false;

        dumper::g_visual_engine_addr = *ve_addr;

        auto render_view = rtti::find(*ve_addr, "RenderView@Graphics@RBX", 0x1000);
        if (render_view) {
            dumper::g_dumper.add_offset("VisualEngine", "RenderView", *render_view);

            auto rv_addr = process::g_process.read<uintptr_t>(*ve_addr + *render_view);
            if (rv_addr) {
                for (size_t off = 0x140; off < 0x160; off += 4) {
                    auto val = process::g_process.read<uint16_t>(*rv_addr + off);
                    if (val && (*val == 257 || *val == 256)) {
                        dumper::g_dumper.add_offset("RenderView", "LightingValid", off);
                        break;
                    }
                }

                for (size_t off = 0x2CD; off < 0x2E8; off++) {
                    auto val = process::g_process.read<uint8_t>(*rv_addr + off);
                    auto next = process::g_process.read<uint8_t>(*rv_addr + off + 1);
                    if (val && next && (*val == 0 || *val == 1) && (*next == 0 || *next == 1)) {
                        dumper::g_dumper.add_offset("RenderView", "SkyValid", off);
                        break;
                    }
                }

                for (size_t off = 0x8; off < 0x18; off += 8) {
                    auto ptr = process::g_process.read<uintptr_t>(*rv_addr + off);
                    if (ptr && *ptr > 0x10000) {
                        if (off == 0x8) {
                            dumper::g_dumper.add_offset("RenderView", "DeviceD3D11", off);
                        }
                        else if (off == 0x10) {
                            dumper::g_dumper.add_offset("RenderView", "VisualEngine", off);
                        }
                    }
                }
            }
        }

        for (size_t offset = 0x118; offset < 0x140; offset += 0x4) {
            float mat[16];
            bool ok = true;
            for (int i = 0; i < 16 && ok; i++) {
                auto v = process::g_process.read<float>(*ve_addr + offset + i * 4);
                if (!v) ok = false;
                else mat[i] = *v;
            }
            if (ok && std::abs(mat[11] - 0.1f) < 0.1f && std::abs(mat[15]) >= 1.0f && std::abs(mat[15]) <= 10000.0f) {
                dumper::g_dumper.add_offset("VisualEngine", "ViewMatrix", offset);
                break;
            }
        }

        auto dims = process::g_process.get_window_dimensions();
        if (dims) {
            for (size_t off = 0x718; off < 0x740; off += 4) {
                auto w = process::g_process.read<float>(*ve_addr + off);
                auto h = process::g_process.read<float>(*ve_addr + off + 4);
                if (w && h && std::abs(*w - dims->first) < 10.0f && std::abs(*h - dims->second) < 10.0f) {
                    dumper::g_dumper.add_offset("VisualEngine", "Dimensions", off);
                    break;
                }
            }
        }

        auto fake_dm = rtti::find(*ve_addr, "DataModel@RBX", 0x800);
        if (fake_dm) {
            dumper::g_dumper.add_offset("VisualEngine", "FakeDataModel", *fake_dm);
            auto fdm = process::g_process.read<uintptr_t>(*ve_addr + *fake_dm);
            if (fdm) {
                auto real_dm = rtti::find(*fdm, "DataModel@RBX", 0x200);
                if (real_dm) dumper::g_dumper.add_offset("FakeDataModel", "RealDataModel", *real_dm);
            }
        }

        return true;
    }

    auto task_scheduler() -> bool {
        auto section = process::g_process.get_section(".data");
        if (!section) return false;

        auto [section_start, section_size] = *section;
        auto module_base = process::g_process.get_module_base();

        for (size_t offset = 0; offset < section_size; offset += 8) {
            auto ptr = process::g_process.read<uintptr_t>(section_start + offset);
            if (!ptr || *ptr < 0x10000) continue;

            auto info = rtti::scan(*ptr);
            if (!info || info->name.find("TaskScheduler") == std::string::npos) continue;

            dumper::g_dumper.add_offset("TaskScheduler", "Pointer", (section_start + offset) - module_base);

            for (size_t foff = 0x1B0; foff < 0x1C8; foff += 8) {
                auto val = process::g_process.read<double>(*ptr + foff);
                if (val && *val >= 30.0 && *val <= 1000.0) {
                    dumper::g_dumper.add_offset("TaskScheduler", "MaxFPS", foff);
                    break;
                }
            }

            for (size_t joff = 0x1D0; joff < 0x1F8; joff += 8) {
                auto start = process::g_process.read<uintptr_t>(*ptr + joff);
                auto end = process::g_process.read<uintptr_t>(*ptr + joff + 8);
                if (!start || !end || *end <= *start || *start < 0x10000) continue;

                size_t count = (*end - *start) / 8;
                if (count < 5 || count > 100) continue;

                dumper::g_dumper.add_offset("TaskScheduler", "JobStart", joff);
                dumper::g_dumper.add_offset("TaskScheduler", "JobEnd", joff + 8);

                auto first_job = process::g_process.read<uintptr_t>(*start);
                if (first_job && *first_job > 0x10000) {
                    for (size_t noff = 0x18; noff < 0x28; noff += 8) {
                        auto str = process::g_process.read_sso_string(*first_job + noff);
                        if (str && !str->empty() && str->length() < 64 && str->length() > 2) {
                            bool valid = true;
                            for (char c : *str) {
                                if (!std::isalnum(c) && c != '_' && c != ' ') { valid = false; break; }
                            }
                            if (valid) {
                                dumper::g_dumper.add_offset("TaskScheduler", "JobName", noff);
                                break;
                            }
                        }
                    }
                }
                break;
            }
            return true;
        }
        return false;
    }

    auto data_model() -> bool {
        auto results = helpers::find_pointer_by_rtti(".data", { "DataModel@RBX" });
        auto dm_offset = results["DataModel@RBX"];
        if (!dm_offset) return false;

        dumper::g_dumper.add_offset("DataModel", "Pointer", *dm_offset);
        offsets::DataModel::Pointer = *dm_offset;

        auto module_base = process::g_process.get_module_base();
        auto fake_dm = process::g_process.read<uintptr_t>(module_base + *dm_offset);
        if (!fake_dm) return false;

        uintptr_t real_dm = 0;
        for (size_t off = 0x1B8; off < 0x1D0; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(*fake_dm + off);
            if (!ptr || *ptr < 0x10000) continue;
            auto info = rtti::scan(*ptr);
            if (info && info->name == "DataModel@RBX") {
                real_dm = *ptr;
                dumper::g_dumper.add_offset("FakeDataModel", "RealDataModel", off);
                break;
            }
        }
        if (!real_dm) real_dm = *fake_dm;
        dumper::g_data_model_addr = real_dm;

        for (size_t off = 0x170; off < 0x190; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(real_dm + off);
            if (!ptr || *ptr < 0x10000) continue;
            auto info = rtti::scan(*ptr);
            if (info && info->name == "Workspace@RBX") {
                dumper::g_dumper.add_offset("DataModel", "Workspace", off);
                break;
            }
        }

        for (size_t off = 0x3E8; off < 0x410; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(real_dm + off);
            if (!ptr || *ptr < 0x10000) continue;
            auto info = rtti::scan(*ptr);
            if (info && info->name.find("ScriptContext") != std::string::npos) {
                dumper::g_dumper.add_offset("DataModel", "ScriptContext", off);
                break;
            }
        }

        for (size_t off = 0x130; off < 0x150; off += 8) {
            auto str = process::g_process.read_sso_string(real_dm + off);
            if (str && is_valid_guid(*str)) {
                dumper::g_dumper.add_offset("DataModel", "JobId", off);
                break;
            }
        }

        for (size_t off = 0x188; off < 0x190; off += 8) {
            auto val = process::g_process.read<int64_t>(real_dm + off);
            if (val && *val > 1000 && *val < 99999999999LL) {
                dumper::g_dumper.add_offset("DataModel", "CreatorId", off);
                break;
            }
        }

        for (size_t off = 0x190; off < 0x198; off += 8) {
            auto val = process::g_process.read<int64_t>(real_dm + off);
            if (val && *val > 1000 && *val < 99999999999LL) {
                dumper::g_dumper.add_offset("DataModel", "GameId", off);
                break;
            }
        }

        for (size_t off = 0x198; off < 0x1A8; off += 8) {
            auto val = process::g_process.read<int64_t>(real_dm + off);
            if (val && *val > 1000 && *val < 99999999999LL) {
                dumper::g_dumper.add_offset("DataModel", "PlaceId", off);
                break;
            }
        }

        for (size_t off = 0x1B0; off < 0x1C8; off += 4) {
            auto val = process::g_process.read<int32_t>(real_dm + off);
            if (val && *val > 0 && *val < 100000) {
                dumper::g_dumper.add_offset("DataModel", "PlaceVersion", off);
                break;
            }
        }

        for (size_t off = 0x430; off < 0x450; off += 4) {
            auto val = process::g_process.read<int32_t>(real_dm + off);
            if (val && *val > 100 && *val < 10000000) {
                dumper::g_dumper.add_offset("DataModel", "PrimitiveCount", off);
                break;
            }
        }

        for (size_t off = 0x5D8; off < 0x5F0; off += 8) {
            auto str = process::g_process.read_sso_string(real_dm + off);
            if (str && str->length() > 7 && str->length() < 50) {
                int dot_count = 0, digit_count = 0;
                for (char c : *str) {
                    if (c == '.') dot_count++;
                    if (std::isdigit(c)) digit_count++;
                }
                if (dot_count >= 3 && digit_count >= 4) {
                    dumper::g_dumper.add_offset("DataModel", "ServerIP", off);
                    break;
                }
            }
        }

        for (size_t off = 0x5F8; off < 0x610; off++) {
            auto val = process::g_process.read<uint8_t>(real_dm + off);
            if (val && *val == 1) {
                auto prev = process::g_process.read<uint8_t>(real_dm + off - 1);
                if (!prev || *prev != 1) {
                    dumper::g_dumper.add_offset("DataModel", "GameLoaded", off);
                    break;
                }
            }
        }

        return true;
    }

    auto instance() -> bool {
        auto ws_off = dumper::g_dumper.get_offset("DataModel", "Workspace");
        if (!ws_off) return false;

        auto ws_addr = process::g_process.read<uintptr_t>(dumper::g_data_model_addr + *ws_off);
        if (!ws_addr) return false;

        auto name = helpers::find_sso_string_offset(*ws_addr, "Workspace");
        if (!name) return false;

        dumper::g_dumper.add_offset("Instance", "Name", *name);
        offsets::Instance::Name = *name;

        auto cd = rtti::find(*ws_addr, "ClassDescriptor@Reflection@RBX", 0x80);
        if (!cd) return false;

        dumper::g_dumper.add_offset("Instance", "ClassDescriptor", *cd);
        offsets::Instance::ClassDescriptor = *cd;

        auto cd_addr = process::g_process.read<uintptr_t>(*ws_addr + *cd);
        if (cd_addr) {
            auto cn = helpers::find_sso_string_offset(*cd_addr, "Workspace");
            if (cn) {
                dumper::g_dumper.add_offset("Instance", "ClassName", *cn);
                offsets::Instance::ClassName = *cn;
            }
        }

        auto parent = rtti::find(*ws_addr, "DataModel@RBX", 0x100);
        if (parent) {
            dumper::g_dumper.add_offset("Instance", "Parent", *parent);
            offsets::Instance::Parent = *parent;
        }

        auto children = helpers::find_children_offsets(*ws_addr, parent.value_or(0));
        if (children) {
            dumper::g_dumper.add_offset("Instance", "ChildrenStart", children->first);
            dumper::g_dumper.add_offset("Instance", "ChildrenEnd", children->second);
            offsets::Instance::ChildrenStart = children->first;
            offsets::Instance::ChildrenEnd = children->second;
        }

        for (size_t off = 0x8; off < 0x18; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(*ws_addr + off);
            if (ptr && *ptr == *ws_addr) {
                dumper::g_dumper.add_offset("Instance", "This", off);
                break;
            }
        }

        for (size_t off = 0x40; off < 0x58; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(*ws_addr + off);
            if (ptr && *ptr > 0x10000) {
                auto inner = process::g_process.read<uintptr_t>(*ptr + 0x18);
                if (inner) {
                    dumper::g_dumper.add_offset("Instance", "AttributeContainer", off);
                    dumper::g_dumper.add_offset("Instance", "AttributeList", 0x18);
                    dumper::g_dumper.add_offset("Instance", "AttributeToNext", 0x58);
                    dumper::g_dumper.add_offset("Instance", "AttributeToValue", 0x18);
                    break;
                }
            }
        }

        dumper::g_workspace = roblox::Instance(*ws_addr);
        return true;
    }

    auto players() -> bool {
        if (!dumper::g_data_model) return false;

        auto p = dumper::g_data_model->find_first_child("Players");
        if (!p) return false;

        dumper::g_players = p;
        auto addr = p->get_address();

        auto local = rtti::find(addr, "Player@RBX", 0x150);
        if (local) dumper::g_dumper.add_offset("Player", "LocalPlayer", *local);

        return true;
    }

    auto player() -> bool {
        if (!dumper::g_players) return false;

        std::optional<roblox::Instance> pl;
        for (const auto& c : dumper::g_players->get_children()) {
            auto cn = c.get_class_name();
            if (cn && *cn == "Player") { pl = c; break; }
        }
        if (!pl) return false;

        auto addr = pl->get_address();

        auto character = rtti::find(addr, "Model@RBX", 0x3B0);
        if (character) dumper::g_dumper.add_offset("Player", "Character", *character);

        for (size_t off = 0x290; off < 0x2A8; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0) {
                dumper::g_dumper.add_offset("Player", "Team", off);
                break;
            }
            if (*ptr > 0x10000) {
                auto info = rtti::scan(*ptr);
                if (info && info->name.find("Team") != std::string::npos) {
                    dumper::g_dumper.add_offset("Player", "Team", off);
                    break;
                }
            }
        }

        for (size_t off = 0x110; off < 0x128; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && str->length() == 2) {
                bool valid = std::all_of(str->begin(), str->end(), [](char c) { return std::isupper(c); });
                if (valid) {
                    dumper::g_dumper.add_offset("Player", "Country", off);
                    break;
                }
            }
        }

        for (size_t off = 0x130; off < 0x150; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && str->length() >= 3 && str->length() <= 20) {
                bool valid = std::all_of(str->begin(), str->end(), [](char c) {
                    return std::isalnum(c) || c == '_';
                    });
                if (valid) {
                    dumper::g_dumper.add_offset("Player", "DisplayName", off);
                    break;
                }
            }
        }

        for (size_t off = 0x2B8; off < 0x2D0; off += 8) {
            auto val = process::g_process.read<int64_t>(addr + off);
            if (val && *val > 1000000 && *val < 99999999999LL) {
                dumper::g_dumper.add_offset("Player", "UserId", off);
                break;
            }
        }

        for (size_t off = 0x310; off < 0x328; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 100.0f && *val < 500.0f) {
                auto next = process::g_process.read<float>(addr + off + 4);
                if (next && *next > 0.0f && *next < *val) {
                    dumper::g_dumper.add_offset("Player", "MaxZoomDistance", off);
                    dumper::g_dumper.add_offset("Player", "MinZoomDistance", off + 4);
                    break;
                }
            }
        }

        for (size_t off = 0x318; off < 0x330; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 2) {
                dumper::g_dumper.add_offset("Player", "CameraMode", off);
                break;
            }
        }

        for (size_t off = 0x338; off < 0x360; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && std::abs(*val - 100.0f) < 10.0f) {
                if (!dumper::g_dumper.get_offset("Player", "HealthDisplayDistance")) {
                    dumper::g_dumper.add_offset("Player", "HealthDisplayDistance", off);
                }
                else {
                    dumper::g_dumper.add_offset("Player", "NameDisplayDistance", off);
                    break;
                }
            }
        }

        for (size_t off = 0x380; off < 0x3A0; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr || *ptr < 0x10000) continue;
            auto info = rtti::scan(*ptr);
            if (info && info->name == "Model@RBX") {
                dumper::g_dumper.add_offset("Player", "ModelInstance", off);
                break;
            }
        }

        auto mouse = rtti::find(addr, "PlayerMouse@RBX", 0x1000);
        if (mouse) dumper::g_dumper.add_offset("Player", "Mouse", *mouse);

        return true;
    }

    auto camera() -> bool {
        if (!dumper::g_workspace) return false;

        auto cam = dumper::g_workspace->find_first_child_of_class("Camera");
        if (!cam) return false;

        auto addr = cam->get_address();

        auto subject = rtti::find_partial(addr, "Humanoid", 0x100);
        if (!subject) subject = rtti::find_partial(addr, "Part", 0x100);
        if (subject) dumper::g_dumper.add_offset("Camera", "CameraSubject", *subject);

        for (size_t off = 0xF8; off < 0x118; off += 4) {
            if (is_valid_rotation_matrix(addr + off)) {
                dumper::g_dumper.add_offset("Camera", "Rotation", off);
                dumper::g_dumper.add_offset("Camera", "CFrame", off);

                for (size_t pos_off = off + 0x24; pos_off < off + 0x30; pos_off += 4) {
                    if (is_valid_position(addr + pos_off)) {
                        dumper::g_dumper.add_offset("Camera", "Position", pos_off);
                        break;
                    }
                }
                break;
            }
        }

        for (size_t off = 0x150; off < 0x168; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 10) {
                dumper::g_dumper.add_offset("Camera", "CameraType", off);
                break;
            }
        }

        auto cam_type = dumper::g_dumper.get_offset("Camera", "CameraType");
        for (size_t off = 0x160; off < 0x180; off += 4) {
            if (cam_type && off == *cam_type) continue;

            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 0.5f && *val < 3.5f) {
                dumper::g_dumper.add_offset("Camera", "FieldOfView", off);
                break;
            }
        }

        auto dims = process::g_process.get_window_dimensions();
        if (dims) {
            for (size_t off = 0x2A0; off < 0x2C0; off += 4) {
                auto vx = process::g_process.read<int16_t>(addr + off);
                auto vy = process::g_process.read<int16_t>(addr + off + 2);
                if (vx && vy && std::abs(*vx - static_cast<int16_t>(dims->first)) < 5 &&
                    std::abs(*vy - static_cast<int16_t>(dims->second)) < 5) {
                    dumper::g_dumper.add_offset("Camera", "Viewport", off);
                    break;
                }
            }

            for (size_t off = 0x2E0; off < 0x300; off += 4) {
                auto vx = process::g_process.read<float>(addr + off);
                auto vy = process::g_process.read<float>(addr + off + 4);
                if (vx && vy && std::abs(*vx - dims->first) < 20.0f && std::abs(*vy - dims->second) < 20.0f) {
                    dumper::g_dumper.add_offset("Camera", "ViewportSize", off);
                    break;
                }
            }
        }

        return true;
    }

    auto humanoid() -> bool {
        if (!dumper::g_workspace) return false;

        auto hum = dumper::g_workspace->find_first_descendant_of_class("Humanoid", 6);
        if (!hum) return false;

        auto addr = hum->get_address();

        for (size_t off = 0xD0; off < 0xE8; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && !str->empty() && str->length() <= 30) {
                bool valid = std::all_of(str->begin(), str->end(), [](char c) { return std::isprint(c); });
                if (valid) {
                    dumper::g_dumper.add_offset("Humanoid", "DisplayName", off);
                    break;
                }
            }
        }

        for (size_t off = 0x120; off < 0x128; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                dumper::g_dumper.add_offset("Humanoid", "SeatPart", off);
                break;
            }
        }

        for (size_t off = 0x130; off < 0x140; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                dumper::g_dumper.add_offset("Humanoid", "MoveToPart", off);
                break;
            }
        }

        for (size_t off = 0x140; off < 0x158; off += 4) {
            if (is_valid_position(addr + off, 50.0f)) {
                dumper::g_dumper.add_offset("Humanoid", "CameraOffset", off);
                break;
            }
        }

        for (size_t off = 0x158; off < 0x170; off += 4) {
            if (is_valid_normalized_vector(addr + off)) {
                dumper::g_dumper.add_offset("Humanoid", "MoveDirection", off);
                break;
            }
        }

        for (size_t off = 0x164; off < 0x178; off += 4) {
            if (is_valid_position(addr + off)) {
                dumper::g_dumper.add_offset("Humanoid", "TargetPoint", off);
                break;
            }
        }

        for (size_t off = 0x17C; off < 0x190; off += 4) {
            if (is_valid_position(addr + off)) {
                dumper::g_dumper.add_offset("Humanoid", "MoveToPoint", off);
                break;
            }
        }

        for (size_t off = 0x18C; off < 0x198; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 3) {
                dumper::g_dumper.add_offset("Humanoid", "DisplayDistanceType", off);
                break;
            }
        }

        for (size_t off = 0x190; off < 0x1A0; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 2048) {
                dumper::g_dumper.add_offset("Humanoid", "FloorMaterial", off);
                break;
            }
        }

        for (size_t off = 0x194; off < 0x1A4; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 0.0f && *val <= 10000.0f) {
                dumper::g_dumper.add_offset("Humanoid", "Health", off);
                break;
            }
        }

        for (size_t off = 0x198; off < 0x1A8; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 50.0f && *val < 200.0f) {
                dumper::g_dumper.add_offset("Humanoid", "HealthDisplayDistance", off);
                break;
            }
        }

        for (size_t off = 0x19C; off < 0x1AC; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 3) {
                dumper::g_dumper.add_offset("Humanoid", "HealthDisplayType", off);
                break;
            }
        }

        for (size_t off = 0x1A0; off < 0x1AC; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.5f && *val <= 10.0f) {
                dumper::g_dumper.add_offset("Humanoid", "HipHeight", off);
                break;
            }
        }

        for (size_t off = 0x1AC; off < 0x1B8; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 1.0f && *val <= 20.0f) {
                dumper::g_dumper.add_offset("Humanoid", "JumpHeight", off);
                break;
            }
        }

        for (size_t off = 0x1B0; off < 0x1BC; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 20.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("Humanoid", "JumpPower", off);
                break;
            }
        }

        for (size_t off = 0x1B4; off < 0x1C0; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 50.0f && *val <= 10000.0f) {
                dumper::g_dumper.add_offset("Humanoid", "MaxHealth", off);
                break;
            }
        }

        for (size_t off = 0x1B8; off < 0x1C4; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 30.0f && *val <= 90.0f) {
                dumper::g_dumper.add_offset("Humanoid", "MaxSlopeAngle", off);
                break;
            }
        }

        for (size_t off = 0x1BC; off < 0x1C8; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 50.0f && *val < 200.0f) {
                dumper::g_dumper.add_offset("Humanoid", "NameDisplayDistance", off);
                break;
            }
        }

        for (size_t off = 0x1C0; off < 0x1CC; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 2) {
                dumper::g_dumper.add_offset("Humanoid", "NameOcclusion", off);
                break;
            }
        }

        for (size_t off = 0x1C8; off < 0x1D4; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Humanoid", "RigType", off);
                break;
            }
        }

        for (size_t off = 0x1D4; off < 0x1E0; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f && std::abs(*val - 16.0f) < 5.0f) {
                dumper::g_dumper.add_offset("Humanoid", "Walkspeed", off);
                break;
            }
        }

        for (size_t off = 0x1D8; off < 0x1F0; off++) {
            int bool_count = 0;
            for (int i = 0; i < 12; i++) {
                auto b = process::g_process.read<uint8_t>(addr + off + i);
                if (b && (*b == 0 || *b == 1)) bool_count++;
            }
            if (bool_count >= 8) {
                dumper::g_dumper.add_offset("Humanoid", "AutoJumpEnabled", off);
                dumper::g_dumper.add_offset("Humanoid", "AutoRotate", off + 1);
                dumper::g_dumper.add_offset("Humanoid", "BreakJointsOnDeath", off + 3);
                dumper::g_dumper.add_offset("Humanoid", "EvaluateStateMachine", off + 4);
                dumper::g_dumper.add_offset("Humanoid", "Jump", off + 5);
                dumper::g_dumper.add_offset("Humanoid", "PlatformStand", off + 7);
                dumper::g_dumper.add_offset("Humanoid", "RequiresNeck", off + 8);
                dumper::g_dumper.add_offset("Humanoid", "Sit", off + 8);
                dumper::g_dumper.add_offset("Humanoid", "UseJumpPower", off + 10);
                dumper::g_dumper.add_offset("Humanoid", "AutomaticScalingEnabled", off + 11);
                break;
            }
        }

        auto ws_off = dumper::g_dumper.get_offset("Humanoid", "Walkspeed");
        if (ws_off) {
            auto ws_val = process::g_process.read<float>(addr + *ws_off);
            if (ws_val) {
                for (size_t off = 0x3C0; off < 0x3D8; off += 4) {
                    auto val = process::g_process.read<float>(addr + off);
                    if (val && std::abs(*val - *ws_val) < 0.01f) {
                        dumper::g_dumper.add_offset("Humanoid", "WalkspeedCheck", off);
                        break;
                    }
                }
            }
        }

        for (size_t off = 0x4C0; off < 0x4D8; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr || *ptr < 0x10000) continue;
            auto info = rtti::scan(*ptr);
            if (info && info->name.find("Part") != std::string::npos) {
                dumper::g_dumper.add_offset("Humanoid", "HumanoidRootPart", off);
                break;
            }
        }

        for (size_t off = 0x8D8; off < 0x8F8; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr || *ptr < 0x10000) continue;

            for (size_t sid_off = 0x20; sid_off < 0x30; sid_off += 4) {
                auto state_id = process::g_process.read<int32_t>(*ptr + sid_off);
                if (state_id && *state_id >= 0 && *state_id <= 20) {
                    dumper::g_dumper.add_offset("Humanoid", "HumanoidState", off);
                    dumper::g_dumper.add_offset("Humanoid", "HumanoidStateID", sid_off);
                    goto found_state;
                }
            }
        }
    found_state:

        for (size_t off = 0x956; off < 0x968; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Humanoid", "IsWalking", off);
                break;
            }
        }

        return true;
    }

    auto base_part() -> bool {
        if (!dumper::g_workspace) return false;

        std::optional<roblox::Instance> part;
        auto bp = dumper::g_workspace->find_first_child("Baseplate");
        if (bp) part = bp;
        else {
            for (const auto& c : dumper::g_workspace->get_children()) {
                auto cn = c.get_class_name();
                if (cn && (*cn == "Part" || *cn == "SpawnLocation" || *cn == "MeshPart")) {
                    part = c;
                    break;
                }
            }
        }
        if (!part) {
            part = dumper::g_workspace->find_first_descendant_of_class("Part", 4);
        }
        if (!part) return false;

        auto addr = part->get_address();

        for (size_t off = 0x148; off < 0x160; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr || *ptr < 0x10000) continue;

            if (is_valid_rotation_matrix(*ptr + 0xC0) && is_valid_position(*ptr + 0xE4)) {
                dumper::g_dumper.add_offset("BasePart", "Primitive", off);
                dumper::g_dumper.add_offset("Primitive", "Rotation", 0xC0);
                dumper::g_dumper.add_offset("Primitive", "Position", 0xE4);

                for (size_t voff = 0xF0; voff < 0x108; voff += 4) {
                    if (is_valid_position(*ptr + voff, 1000.0f)) {
                        auto next_valid = is_valid_position(*ptr + voff + 12, 1000.0f);
                        if (next_valid) {
                            dumper::g_dumper.add_offset("Primitive", "AssemblyLinearVelocity", voff);
                            dumper::g_dumper.add_offset("Primitive", "AssemblyAngularVelocity", voff + 12);
                            break;
                        }
                    }
                }

                for (size_t foff = 0x1AE; foff < 0x1B8; foff++) {
                    auto flags = process::g_process.read<uint8_t>(*ptr + foff);
                    if (flags && (*flags & 0x1E) != 0) {
                        dumper::g_dumper.add_offset("Primitive", "Flags", foff);
                        dumper::g_dumper.add_offset("PrimitiveFlags", "Anchored", 0x2);
                        dumper::g_dumper.add_offset("PrimitiveFlags", "CanCollide", 0x8);
                        dumper::g_dumper.add_offset("PrimitiveFlags", "CanTouch", 0x10);
                        break;
                    }
                }

                for (size_t soff = 0x1B0; soff < 0x1C8; soff += 4) {
                    auto sx = process::g_process.read<float>(*ptr + soff);
                    auto sy = process::g_process.read<float>(*ptr + soff + 4);
                    auto sz = process::g_process.read<float>(*ptr + soff + 8);
                    if (sx && sy && sz && *sx > 0.0f && *sy > 0.0f && *sz > 0.0f &&
                        *sx < 10000.0f && *sy < 10000.0f && *sz < 10000.0f) {
                        dumper::g_dumper.add_offset("Primitive", "Size", soff);
                        break;
                    }
                }

                for (size_t ooff = 0x210; ooff < 0x228; ooff += 8) {
                    auto owner = process::g_process.read<uintptr_t>(*ptr + ooff);
                    if (owner && (*owner == 0 || *owner > 0x10000)) {
                        dumper::g_dumper.add_offset("Primitive", "Owner", ooff);
                        break;
                    }
                }

                for (size_t moff = 0x248; moff < 0x260; moff += 4) {
                    auto mat = process::g_process.read<int32_t>(*ptr + moff);
                    if (mat && *mat >= 256 && *mat <= 2048) {
                        dumper::g_dumper.add_offset("Primitive", "Material", moff);
                        break;
                    }
                }

                dumper::g_dumper.add_offset("Primitive", "Validate", 0x6);
                break;
            }
        }

        for (size_t off = 0xF0; off < 0x108; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1.0f) {
                dumper::g_dumper.add_offset("BasePart", "Transparency", off);
                break;
            }
        }

        for (size_t off = 0x194; off < 0x1B0; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("BasePart", "Color3", off);
                break;
            }
        }

        for (size_t off = 0x1B1; off < 0x1C8; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && *val >= 1 && *val <= 5) {
                dumper::g_dumper.add_offset("BasePart", "Shape", off);
                break;
            }
        }

        return true;
    }

    auto workspace() -> bool {
        if (!dumper::g_workspace) return false;
        auto addr = dumper::g_workspace->get_address();

        auto cam = rtti::find(addr, "Camera@RBX", 0x4B0);
        if (cam) dumper::g_dumper.add_offset("Workspace", "CurrentCamera", *cam);

        auto ter = rtti::find(addr, "Terrain@RBX", 0x4C0);
        if (ter) dumper::g_dumper.add_offset("Workspace", "Terrain", *ter);

        for (size_t off = 0x4C0; off < 0x4E0; off += 8) {
            auto val = process::g_process.read<double>(addr + off);
            if (val && *val > 0.0 && *val < 100000000.0) {
                dumper::g_dumper.add_offset("Workspace", "DistributedGameTime", off);
                break;
            }
        }

        for (size_t off = 0xA28; off < 0xA40; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && std::abs(*val - 196.2f) < 2.0f) {
                dumper::g_dumper.add_offset("Workspace", "ReadOnlyGravity", off);
                break;
            }
        }

        for (size_t off = 0x3D8; off < 0x3F8; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr || *ptr < 0x10000) continue;

            for (size_t goff = 0x1D0; goff < 0x1E0; goff += 4) {
                auto gval = process::g_process.read<float>(*ptr + goff);
                if (gval && std::abs(*gval - 196.2f) < 2.0f) {
                    dumper::g_dumper.add_offset("Workspace", "World", off);
                    dumper::g_dumper.add_offset("World", "Gravity", goff);

                    for (size_t fpoff = 0x1C8; fpoff < 0x1D8; fpoff += 8) {
                        auto fpval = process::g_process.read<double>(*ptr + fpoff);
                        if (fpval && *fpval < -100.0 && *fpval > -10000.0) {
                            dumper::g_dumper.add_offset("World", "FallenPartsDestroyHeight", fpoff);
                            logger::info(" fpsh -> ", fpoff);
                            break;
                        }
                    }

                    for (size_t poff = 0x240; poff < 0x258; poff += 8) {
                        auto pval = process::g_process.read<uintptr_t>(*ptr + poff);
                        if (pval && *pval > 0x10000) {
                            dumper::g_dumper.add_offset("World", "Primitives", poff);
                            break;
                        }
                    }

                    for (size_t wsoff = 0x658; wsoff < 0x678; wsoff += 8) {
                        auto wsval = process::g_process.read<double>(*ptr + wsoff);
                        if (wsval && *wsval > 200.0 && *wsval < 300.0) {
                            //dumper::g_dumper.add_offset("World", "worldStepsPerSec", wsoff);
                            logger::info(" wsps -> ", wsoff);
                            break;
                        }
                    }

                    for (size_t aoff = 0x1D8; aoff < 0x1F8; aoff += 8) {
                        auto air_ptr = process::g_process.read<uintptr_t>(*ptr + aoff);
                        if (!air_ptr || *air_ptr < 0x10000) continue;

                        for (size_t doff = 0x18; doff < 0x24; doff += 4) {
                            auto density = process::g_process.read<float>(*air_ptr + doff);
                            if (density && *density >= 0.0f && *density <= 10.0f && *density > 0.001f) {
                                dumper::g_dumper.add_offset("World", "AirProperties", aoff);
                                dumper::g_dumper.add_offset("AirProperties", "AirDensity", doff);

                                for (size_t woff = 0x3C; woff < 0x50; woff += 4) {
                                    auto wx = process::g_process.read<float>(*air_ptr + woff);
                                    auto wy = process::g_process.read<float>(*air_ptr + woff + 4);
                                    auto wz = process::g_process.read<float>(*air_ptr + woff + 8);
                                    if (wx && wy && wz &&
                                        std::abs(*wx) < 10000.0f && std::abs(*wy) < 10000.0f && std::abs(*wz) < 10000.0f) {
                                        dumper::g_dumper.add_offset("AirProperties", "GlobalWind", woff);
                                        break;
                                    }
                                }
                                goto found_air;
                            }
                        }
                    }
                found_air:
                    goto found_world;
                }
            }
        }
    found_world:

        return true;
    }

    auto lighting() -> bool {
        if (!dumper::g_data_model) return false;

        auto lit = dumper::g_data_model->find_first_child("Lighting");
        if (!lit) return false;

        dumper::g_lighting = lit;
        auto addr = lit->get_address();

        size_t color_offsets[5] = { 0 };
        int color_count = 0;
        for (size_t off = 0xD8; off < 0x118 && color_count < 5; off += 4) {
            if (is_valid_color3(addr + off)) {
                color_offsets[color_count++] = off;
                off += 8;
            }
        }
        if (color_count >= 1) dumper::g_dumper.add_offset("Lighting", "Ambient", color_offsets[0]);
        if (color_count >= 2) dumper::g_dumper.add_offset("Lighting", "ColorShift_Top", color_offsets[1]);
        if (color_count >= 3) dumper::g_dumper.add_offset("Lighting", "ColorShift_Bottom", color_offsets[2]);
        if (color_count >= 4) dumper::g_dumper.add_offset("Lighting", "FogColor", color_offsets[3]);
        if (color_count >= 5) dumper::g_dumper.add_offset("Lighting", "OutdoorAmbient", color_offsets[4]);

        for (size_t off = 0x118; off < 0x130; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 10.0f && *val > 0.0f) {
                dumper::g_dumper.add_offset("Lighting", "Brightness", off);
                break;
            }
        }

        auto bright = dumper::g_dumper.get_offset("Lighting", "Brightness");
        for (size_t off = 0x120; off < 0x138; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1.0f) {
                if (!bright || off != *bright) {
                    if (!dumper::g_dumper.get_offset("Lighting", "EnvironmentDiffuseScale")) {
                        dumper::g_dumper.add_offset("Lighting", "EnvironmentDiffuseScale", off);
                    }
                    else if (!dumper::g_dumper.get_offset("Lighting", "EnvironmentSpecularScale")) {
                        dumper::g_dumper.add_offset("Lighting", "EnvironmentSpecularScale", off);
                    }
                    else if (!dumper::g_dumper.get_offset("Lighting", "ExposureCompensation")) {
                        dumper::g_dumper.add_offset("Lighting", "ExposureCompensation", off);
                        break;
                    }
                }
            }
        }

        for (size_t off = 0x130; off < 0x148; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 1000.0f && *val < 1000000.0f) {
                auto next = process::g_process.read<float>(addr + off + 4);
                if (next && *next >= 0.0f && *next < *val) {
                    dumper::g_dumper.add_offset("Lighting", "FogEnd", off);
                    dumper::g_dumper.add_offset("Lighting", "FogStart", off + 4);
                    break;
                }
            }
        }

        for (size_t off = 0x144; off < 0x158; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Lighting", "GlobalShadows", off);
                break;
            }
        }

        for (size_t off = 0x150; off < 0x170; off += 4) {
            if (is_valid_color3(addr + off)) {
                if (!dumper::g_dumper.get_offset("Lighting", "GradientTop")) {
                    dumper::g_dumper.add_offset("Lighting", "GradientTop", off);
                }
                else if (!dumper::g_dumper.get_offset("Lighting", "LightColor")) {
                    dumper::g_dumper.add_offset("Lighting", "LightColor", off);
                    break;
                }
                off += 8;
            }
        }

        for (size_t off = 0x168; off < 0x188; off += 4) {
            if (is_valid_normalized_vector(addr + off)) {
                dumper::g_dumper.add_offset("Lighting", "LightDirection", off);
                break;
            }
        }

        for (size_t off = 0x174; off < 0x190; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 10) {
                dumper::g_dumper.add_offset("Lighting", "Source", off);
                break;
            }
        }

        auto ld = dumper::g_dumper.get_offset("Lighting", "LightDirection");
        for (size_t off = 0x178; off < 0x1A0; off += 4) {
            if (is_valid_position(addr + off, 1000000.0f)) {
                if (!ld || (off < *ld || off >= *ld + 12)) {
                    if (!dumper::g_dumper.get_offset("Lighting", "SunPosition")) {
                        dumper::g_dumper.add_offset("Lighting", "SunPosition", off);
                    }
                    else if (!dumper::g_dumper.get_offset("Lighting", "MoonPosition")) {
                        dumper::g_dumper.add_offset("Lighting", "MoonPosition", off);
                        break;
                    }
                }
            }
        }

        for (size_t off = 0x190; off < 0x1A8; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= -90.0f && *val <= 90.0f) {
                dumper::g_dumper.add_offset("Lighting", "GeographicLatitude", off);
                break;
            }
        }

        for (size_t off = 0x194; off < 0x1B0; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("Lighting", "GradientBottom", off);
                break;
            }
        }

        for (size_t off = 0x1B8; off < 0x1D0; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 24.0f) {
                dumper::g_dumper.add_offset("Lighting", "ClockTime", off);
                break;
            }
        }

        for (size_t off = 0x1D0; off < 0x1F0; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr || *ptr < 0x10000) continue;
            auto info = rtti::scan(*ptr);
            if (info && info->name.find("Sky") != std::string::npos) {
                dumper::g_dumper.add_offset("Lighting", "Sky", off);
                break;
            }
        }

        return true;
    }

    auto terrain() -> bool {
        if (!dumper::g_workspace) return false;

        auto ter = dumper::g_workspace->find_first_child_of_class("Terrain");
        if (!ter) return false;

        auto addr = ter->get_address();

        for (size_t off = 0x1E0; off < 0x1F8; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("Terrain", "WaterColor", off);
                break;
            }
        }

        for (size_t off = 0x1F0; off < 0x208; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.1f && *val <= 2.0f) {
                dumper::g_dumper.add_offset("Terrain", "GrassLength", off);
                break;
            }
        }

        for (size_t off = 0x1FC; off < 0x218; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1.0f) {
                auto wc = dumper::g_dumper.get_offset("Terrain", "WaterColor");
                if (!wc || (off < *wc || off > *wc + 8)) {
                    if (!dumper::g_dumper.get_offset("Terrain", "WaterReflectance")) {
                        dumper::g_dumper.add_offset("Terrain", "WaterReflectance", off);
                    }
                    else if (!dumper::g_dumper.get_offset("Terrain", "WaterTransparency")) {
                        dumper::g_dumper.add_offset("Terrain", "WaterTransparency", off);
                        break;
                    }
                }
            }
        }

        for (size_t off = 0x204; off < 0x220; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                auto wt = dumper::g_dumper.get_offset("Terrain", "WaterTransparency");
                if (!wt || off != *wt) {
                    if (!dumper::g_dumper.get_offset("Terrain", "WaterWaveSize")) {
                        dumper::g_dumper.add_offset("Terrain", "WaterWaveSize", off);
                    }
                    else if (!dumper::g_dumper.get_offset("Terrain", "WaterWaveSpeed")) {
                        dumper::g_dumper.add_offset("Terrain", "WaterWaveSpeed", off);
                        break;
                    }
                }
            }
        }

        for (size_t off = 0x278; off < 0x298; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (ptr && *ptr > 0x10000) {
                auto b = process::g_process.read<uint8_t>(*ptr);
                if (b && *b <= 255) {
                    dumper::g_dumper.add_offset("Terrain", "MaterialColors", off);

                    const char* materials[] = { "Grass", "Slate", "Concrete", "Brick", "Sand",
                        "WoodPlanks", "Rock", "Glacier", "Snow", "Sandstone", "Mud", "Basalt",
                        "Ground", "CrackedLava", "Asphalt", "Cobblestone", "Ice", "LeafyGrass",
                        "Salt", "Limestone", "Pavement" };
                    for (int i = 0; i < 21; i++) {
                        dumper::g_dumper.add_offset("MaterialColors", materials[i], 6 + i * 3);
                    }
                    break;
                }
            }
        }

        return true;
    }

    auto sky() -> bool {
        if (!dumper::g_lighting) return false;

        auto s = dumper::g_lighting->find_first_child_of_class("Sky");
        if (!s) return false;

        auto addr = s->get_address();

        auto find_texture = [&](size_t start, size_t end) -> std::optional<size_t> {
            for (size_t off = start; off < end; off += 8) {
                auto str = process::g_process.read_sso_string(addr + off);
                if (str && (str->empty() || str->find("rbxasset") != std::string::npos || str->find("Sky") != std::string::npos)) {
                    return off;
                }
            }
            return std::nullopt;
            };

        if (auto off = find_texture(0xD8, 0xF0))   dumper::g_dumper.add_offset("Sky", "MoonTextureId", *off);
        if (auto off = find_texture(0x108, 0x120)) dumper::g_dumper.add_offset("Sky", "SkyboxBk", *off);
        if (auto off = find_texture(0x138, 0x150)) dumper::g_dumper.add_offset("Sky", "SkyboxDn", *off);
        if (auto off = find_texture(0x168, 0x180)) dumper::g_dumper.add_offset("Sky", "SkyboxFt", *off);
        if (auto off = find_texture(0x198, 0x1B0)) dumper::g_dumper.add_offset("Sky", "SkyboxLf", *off);
        if (auto off = find_texture(0x1C8, 0x1E0)) dumper::g_dumper.add_offset("Sky", "SkyboxRt", *off);
        if (auto off = find_texture(0x1F8, 0x210)) dumper::g_dumper.add_offset("Sky", "SkyboxUp", *off);
        if (auto off = find_texture(0x228, 0x240)) dumper::g_dumper.add_offset("Sky", "SunTextureId", *off);

        for (size_t off = 0x248; off < 0x260; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= -180 && *val <= 180) {
                dumper::g_dumper.add_offset("Sky", "SkyboxOrientation", off);
                break;
            }
        }

        for (size_t off = 0x250; off < 0x268; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                if (!dumper::g_dumper.get_offset("Sky", "SunAngularSize")) {
                    dumper::g_dumper.add_offset("Sky", "SunAngularSize", off);
                }
                else if (!dumper::g_dumper.get_offset("Sky", "MoonAngularSize")) {
                    dumper::g_dumper.add_offset("Sky", "MoonAngularSize", off);
                    break;
                }
            }
        }

        for (size_t off = 0x25C; off < 0x270; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 10000) {
                dumper::g_dumper.add_offset("Sky", "StarCount", off);
                break;
            }
        }

        return true;
    }

    auto team() -> bool {
        if (!dumper::g_data_model) return false;

        auto teams = dumper::g_data_model->find_first_child("Teams");
        if (!teams) return false;

        std::optional<roblox::Instance> t;
        for (const auto& c : teams->get_children()) {
            auto cn = c.get_class_name();
            if (cn && *cn == "Team") { t = c; break; }
        }
        if (!t) return false;

        auto addr = t->get_address();

        for (size_t off = 0xC8; off < 0xE0; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 1 && *val <= 1032) {
                dumper::g_dumper.add_offset("Team", "BrickColor", off);
                break;
            }
        }

        return true;
    }

    auto model() -> bool {
        if (!dumper::g_workspace) return false;

        std::optional<roblox::Instance> mdl;
        for (const auto& c : dumper::g_workspace->get_children()) {
            auto cn = c.get_class_name();
            if (cn && *cn == "Model") { mdl = c; break; }
        }
        if (!mdl) {
            mdl = dumper::g_workspace->find_first_descendant_of_class("Model", 4);
        }
        if (!mdl) return false;

        auto addr = mdl->get_address();

        for (size_t off = 0x278; off < 0x298; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0) {
                dumper::g_dumper.add_offset("Model", "PrimaryPart", off);
                break;
            }
            if (*ptr > 0x10000) {
                auto info = rtti::scan(*ptr);
                if (info && info->name.find("Part") != std::string::npos) {
                    dumper::g_dumper.add_offset("Model", "PrimaryPart", off);
                    break;
                }
            }
        }

        for (size_t off = 0x160; off < 0x178; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.001f && *val <= 1000.0f && std::abs(*val - 1.0f) < 0.5f) {
                dumper::g_dumper.add_offset("Model", "Scale", off);
                break;
            }
        }

        return true;
    }

    auto scripts() -> bool {
        if (!dumper::g_data_model) return false;

        std::optional<roblox::Instance> ms, ls;

        auto rs = dumper::g_data_model->find_first_child("ReplicatedStorage");
        if (rs) {
            ms = find_descendant(*rs, "ModuleScript", 6);
            ls = find_descendant(*rs, "LocalScript", 6);
        }

        if (!ms || !ls) {
            for (const auto& name : { "StarterGui", "StarterPlayer", "Workspace" }) {
                auto container = dumper::g_data_model->find_first_child(name);
                if (!container) continue;
                if (!ms) ms = find_descendant(*container, "ModuleScript", 6);
                if (!ls) ls = find_descendant(*container, "LocalScript", 6);
                if (ms && ls) break;
            }
        }

        bool found_any = false;

        if (ms) {
            auto addr = ms->get_address();

            for (size_t off = 0x148; off < 0x168; off += 8) {
                auto container = process::g_process.read<uintptr_t>(addr + off);
                if (!container || *container < 0x10000) continue;

                auto size = process::g_process.read<int32_t>(*container + 0x20);
                if (size && *size > 10 && *size < 10000000) {
                    dumper::g_dumper.add_offset("ModuleScript", "ByteCode", off);
                    found_any = true;
                    break;
                }
            }

            for (size_t off = 0xE0; off < 0x100; off += 8) {
                auto str = process::g_process.read_sso_string(addr + off);
                if (str && is_valid_guid(*str)) {
                    dumper::g_dumper.add_offset("ModuleScript", "GUID", off);
                    found_any = true;
                    break;
                }
            }

            auto bytecode_off = dumper::g_dumper.get_offset("ModuleScript", "ByteCode");
            for (size_t off = 0x158; off < 0x178; off += 8) {
                if (bytecode_off && off == *bytecode_off) continue;

                auto ptr = process::g_process.read<uintptr_t>(addr + off);
                if (!ptr || *ptr < 0x10000) continue;

                auto hash = process::g_process.read<int32_t>(*ptr);
                if (hash && *hash != 0) {
                    dumper::g_dumper.add_offset("ModuleScript", "Hash", off);
                    found_any = true;
                    break;
                }
            }
        }

        if (ls) {
            auto addr = ls->get_address();

            for (size_t off = 0x1A0; off < 0x1C0; off += 8) {
                auto container = process::g_process.read<uintptr_t>(addr + off);
                if (!container || *container < 0x10000) continue;

                auto size = process::g_process.read<int32_t>(*container + 0x20);
                if (size && *size > 10 && *size < 10000000) {
                    dumper::g_dumper.add_offset("LocalScript", "ByteCode", off);
                    found_any = true;
                    break;
                }
            }

            for (size_t off = 0xE0; off < 0x100; off += 8) {
                auto str = process::g_process.read_sso_string(addr + off);
                if (str && is_valid_guid(*str)) {
                    dumper::g_dumper.add_offset("LocalScript", "GUID", off);
                    found_any = true;
                    break;
                }
            }

            auto bytecode_off = dumper::g_dumper.get_offset("LocalScript", "ByteCode");
            for (size_t off = 0x1B0; off < 0x1D0; off += 8) {
                if (bytecode_off && off == *bytecode_off) continue;

                auto ptr = process::g_process.read<uintptr_t>(addr + off);
                if (!ptr || *ptr < 0x10000) continue;

                auto hash = process::g_process.read<int32_t>(*ptr);
                if (hash && *hash != 0) {
                    dumper::g_dumper.add_offset("LocalScript", "Hash", off);
                    found_any = true;
                    break;
                }
            }
        }

        if (found_any) {
            dumper::g_dumper.add_offset("ByteCode", "Pointer", 0x10);
            dumper::g_dumper.add_offset("ByteCode", "Size", 0x20);
        }

        return found_any;
    }

    auto run_service() -> bool {
        if (!dumper::g_data_model) return false;

        auto rs = dumper::g_data_model->find_first_child_of_class("RunService");
        if (!rs) {
            rs = dumper::g_data_model->find_first_child("RunService");
        }
        if (!rs) return false;

        auto addr = rs->get_address();

        for (size_t off = 0xC0; off < 0xD8; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 30.0f && *val <= 1000.0f) {
                dumper::g_dumper.add_offset("RunService", "HeartbeatFPS", off);
                break;
            }
        }

        for (size_t off = 0xE8; off < 0x108; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (ptr && *ptr > 0x10000) {
                dumper::g_dumper.add_offset("RunService", "HeartbeatTask", off);
                break;
            }
        }

        return true;
    }

    auto mouse_service() -> bool {
        if (!dumper::g_data_model) return false;

        auto ms = dumper::g_data_model->find_first_child_of_class("MouseService");
        if (!ms) return false;

        auto addr = ms->get_address();

        auto input_objects = rtti::find_all(addr, "InputObject@RBX", 0x400, 0x8);
        if (input_objects.size() < 2) return false;

        for (size_t off = 0xF8; off < 0x118; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr || *ptr < 0x10000) continue;
            auto info = rtti::scan(*ptr);
            if (info && info->name.find("InputObject") != std::string::npos) {
                dumper::g_dumper.add_offset("MouseService", "InputObject", off);

                for (size_t moff = 0xE0; moff < 0x100; moff += 4) {
                    auto x = process::g_process.read<float>(*ptr + moff);
                    auto y = process::g_process.read<float>(*ptr + moff + 4);
                    if (x && y && *x >= 0.0f && *x < 10000.0f && *y >= 0.0f && *y < 10000.0f) {
                        dumper::g_dumper.add_offset("InputObject", "MousePosition", moff);
                        dumper::g_dumper.add_offset("MouseService", "MousePosition", moff);
                        break;
                    }
                }
                break;
            }
        }

        return true;
    }

    auto proximity_prompt() -> bool {
        if (!dumper::g_workspace) return false;

        auto pp = dumper::g_workspace->find_first_descendant_of_class("ProximityPrompt", 6);
        if (!pp) return false;

        auto addr = pp->get_address();

        for (size_t off = 0xD0; off < 0xE8; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && str->length() < 50) {
                dumper::g_dumper.add_offset("ProximityPrompt", "ActionText", off);
                break;
            }
        }

        for (size_t off = 0xF0; off < 0x108; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && str->length() < 50) {
                dumper::g_dumper.add_offset("ProximityPrompt", "ObjectText", off);
                break;
            }
        }

        for (size_t off = 0x13C; off < 0x148; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 500) {
                dumper::g_dumper.add_offset("ProximityPrompt", "GamepadKeyCode", off);
                break;
            }
        }

        for (size_t off = 0x140; off < 0x14C; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("ProximityPrompt", "HoldDuration", off);
                break;
            }
        }

        for (size_t off = 0x144; off < 0x150; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 500) {
                dumper::g_dumper.add_offset("ProximityPrompt", "KeyboardKeyCode", off);
                break;
            }
        }

        for (size_t off = 0x148; off < 0x158; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1000.0f && *val > 1.0f) {
                dumper::g_dumper.add_offset("ProximityPrompt", "MaxActivationDistance", off);
                break;
            }
        }

        for (size_t off = 0x156; off < 0x160; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            auto next = process::g_process.read<uint8_t>(addr + off + 1);
            if (val && next && (*val == 0 || *val == 1) && (*next == 0 || *next == 1)) {
                dumper::g_dumper.add_offset("ProximityPrompt", "Enabled", off);
                dumper::g_dumper.add_offset("ProximityPrompt", "RequiresLineOfSight", off + 1);
                break;
            }
        }

        return true;
    }

    auto click_detector() -> bool {
        if (!dumper::g_workspace) return false;

        auto cd = dumper::g_workspace->find_first_descendant_of_class("ClickDetector", 6);
        if (!cd) return false;

        auto addr = cd->get_address();

        for (size_t off = 0xD8; off < 0xF0; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("ClickDetector", "MouseIcon", off);
                break;
            }
        }

        for (size_t off = 0xF8; off < 0x110; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 0.0f && *val <= 10000.0f) {
                dumper::g_dumper.add_offset("ClickDetector", "MaxActivationDistance", off);
                break;
            }
        }

        return true;
    }

    auto seat() -> bool {
        if (!dumper::g_workspace) return false;

        auto s = dumper::g_workspace->find_first_descendant_of_class("Seat", 6);
        if (!s) s = dumper::g_workspace->find_first_descendant_of_class("VehicleSeat", 6);
        if (!s) return false;

        auto addr = s->get_address();

        for (size_t off = 0x220; off < 0x240; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0) {
                dumper::g_dumper.add_offset("Seat", "Occupant", off);
                break;
            }
            if (*ptr > 0x10000) {
                auto info = rtti::scan(*ptr);
                if (info && info->name.find("Humanoid") != std::string::npos) {
                    dumper::g_dumper.add_offset("Seat", "Occupant", off);
                    break;
                }
            }
        }

        return true;
    }

    auto sound() -> bool {
        if (!dumper::g_workspace) return false;

        auto snd = dumper::g_workspace->find_first_descendant_of_class("Sound", 6);
        if (!snd && dumper::g_data_model) {
            snd = find_descendant(*dumper::g_data_model, "Sound", 6);
        }
        if (!snd) return false;

        auto addr = snd->get_address();

        for (size_t off = 0xD8; off < 0xF0; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("Sound", "SoundId", off);
                break;
            }
        }

        for (size_t off = 0xF8; off < 0x110; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                dumper::g_dumper.add_offset("Sound", "SoundGroup", off);
                break;
            }
        }

        for (size_t off = 0x128; off < 0x140; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f && std::abs(*val - 1.0f) < 0.5f) {
                dumper::g_dumper.add_offset("Sound", "PlaybackSpeed", off);
                break;
            }
        }

        for (size_t off = 0x130; off < 0x148; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val > 100.0f && *val < 100000.0f) {
                auto next = process::g_process.read<float>(addr + off + 4);
                if (next && *next >= 0.0f && *next < *val) {
                    dumper::g_dumper.add_offset("Sound", "RollOffMaxDistance", off);
                    dumper::g_dumper.add_offset("Sound", "RollOffMinDistance", off + 4);
                    break;
                }
            }
        }

        for (size_t off = 0x140; off < 0x158; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 10.0f) {
                auto rmax = dumper::g_dumper.get_offset("Sound", "RollOffMaxDistance");
                auto rmin = dumper::g_dumper.get_offset("Sound", "RollOffMinDistance");
                if ((!rmax || off != *rmax) && (!rmin || off != *rmin)) {
                    dumper::g_dumper.add_offset("Sound", "Volume", off);
                    break;
                }
            }
        }

        for (size_t off = 0x14C; off < 0x160; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Sound", "Looped", off);
                break;
            }
        }

        return true;
    }

    auto post_effects() -> bool {
        if (!dumper::g_lighting) return true;

        auto bloom = dumper::g_lighting->find_first_child_of_class("BloomEffect");
        if (bloom) {
            auto addr = bloom->get_address();
            for (size_t off = 0xC8; off < 0xD0; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("BloomEffect", "Enabled", off);
                    break;
                }
            }
            for (size_t off = 0xD0; off < 0xE8; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= 0.0f && *val <= 10.0f) {
                    dumper::g_dumper.add_offset("BloomEffect", "Intensity", off);
                    dumper::g_dumper.add_offset("BloomEffect", "Size", off + 4);
                    dumper::g_dumper.add_offset("BloomEffect", "Threshold", off + 8);
                    break;
                }
            }
        }

        auto blur = dumper::g_lighting->find_first_child_of_class("BlurEffect");
        if (blur) {
            auto addr = blur->get_address();
            for (size_t off = 0xC8; off < 0xD0; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("BlurEffect", "Enabled", off);
                    break;
                }
            }
            for (size_t off = 0xD0; off < 0xE8; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= 0.0f && *val <= 100.0f) {
                    dumper::g_dumper.add_offset("BlurEffect", "Size", off);
                    break;
                }
            }
        }

        auto cc = dumper::g_lighting->find_first_child_of_class("ColorCorrectionEffect");
        if (cc) {
            auto addr = cc->get_address();
            for (size_t off = 0xC8; off < 0xD0; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("ColorCorrectionEffect", "Enabled", off);
                    break;
                }
            }
            for (size_t off = 0xD0; off < 0xE8; off += 4) {
                if (is_valid_color3(addr + off)) {
                    dumper::g_dumper.add_offset("ColorCorrectionEffect", "TintColor", off);
                    break;
                }
            }
            for (size_t off = 0xDC; off < 0xF8; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= -1.0f && *val <= 1.0f) {
                    dumper::g_dumper.add_offset("ColorCorrectionEffect", "Brightness", off);
                    dumper::g_dumper.add_offset("ColorCorrectionEffect", "Contrast", off + 4);
                    break;
                }
            }
        }

        auto cg = dumper::g_lighting->find_first_child_of_class("ColorGradingEffect");
        if (cg) {
            auto addr = cg->get_address();
            for (size_t off = 0xC8; off < 0xD0; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("ColorGradingEffect", "Enabled", off);
                    break;
                }
            }
            for (size_t off = 0xD0; off < 0xE8; off += 4) {
                auto val = process::g_process.read<int32_t>(addr + off);
                if (val && *val >= 0 && *val <= 10) {
                    dumper::g_dumper.add_offset("ColorGradingEffect", "TonemapperPreset", off);
                    break;
                }
            }
        }

        auto dof = dumper::g_lighting->find_first_child_of_class("DepthOfFieldEffect");
        if (dof) {
            auto addr = dof->get_address();
            for (size_t off = 0xC8; off < 0xD0; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("DepthOfFieldEffect", "Enabled", off);
                    break;
                }
            }
            for (size_t off = 0xD0; off < 0xF8; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= 0.0f && *val <= 1.0f) {
                    dumper::g_dumper.add_offset("DepthOfFieldEffect", "FarIntensity", off);
                    dumper::g_dumper.add_offset("DepthOfFieldEffect", "FocusDistance", off + 4);
                    dumper::g_dumper.add_offset("DepthOfFieldEffect", "InFocusRadius", off + 8);
                    dumper::g_dumper.add_offset("DepthOfFieldEffect", "NearIntensity", off + 12);
                    break;
                }
            }
        }

        auto sr = dumper::g_lighting->find_first_child_of_class("SunRaysEffect");
        if (sr) {
            auto addr = sr->get_address();
            for (size_t off = 0xC8; off < 0xD0; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("SunRaysEffect", "Enabled", off);
                    break;
                }
            }
            for (size_t off = 0xD0; off < 0xE8; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= 0.0f && *val <= 1.0f) {
                    dumper::g_dumper.add_offset("SunRaysEffect", "Intensity", off);
                    dumper::g_dumper.add_offset("SunRaysEffect", "Spread", off + 4);
                    break;
                }
            }
        }

        auto atm = dumper::g_lighting->find_first_child_of_class("Atmosphere");
        if (atm) {
            auto addr = atm->get_address();
            for (size_t off = 0xD0; off < 0xF8; off += 4) {
                if (is_valid_color3(addr + off)) {
                    if (!dumper::g_dumper.get_offset("Atmosphere", "Color")) {
                        dumper::g_dumper.add_offset("Atmosphere", "Color", off);
                    }
                    else if (!dumper::g_dumper.get_offset("Atmosphere", "Decay")) {
                        dumper::g_dumper.add_offset("Atmosphere", "Decay", off);
                        break;
                    }
                    off += 8;
                }
            }
            for (size_t off = 0xE8; off < 0x108; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= 0.0f && *val <= 1.0f) {
                    dumper::g_dumper.add_offset("Atmosphere", "Density", off);
                    dumper::g_dumper.add_offset("Atmosphere", "Glare", off + 4);
                    dumper::g_dumper.add_offset("Atmosphere", "Haze", off + 8);
                    dumper::g_dumper.add_offset("Atmosphere", "Offset", off + 12);
                    break;
                }
            }
        }

        return true;
    }

    auto mesh_part() -> bool {
        if (!dumper::g_workspace) return false;

        auto mp = dumper::g_workspace->find_first_descendant_of_class("MeshPart", 6);
        if (!mp) return false;

        auto addr = mp->get_address();

        for (size_t off = 0x2E8; off < 0x320; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("MeshPart", "MeshId", off);
                break;
            }
        }

        for (size_t off = 0x318; off < 0x340; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("MeshPart", "Texture", off);
                break;
            }
        }

        return true;
    }

    auto character_mesh() -> bool {
        if (!dumper::g_workspace) return false;

        auto cm = find_descendant(*dumper::g_workspace, "CharacterMesh", 6);
        if (!cm) return false;

        auto addr = cm->get_address();

        for (size_t off = 0xE0; off < 0x160; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos ||
                std::all_of(str->begin(), str->end(), ::isdigit))) {
                if (!dumper::g_dumper.get_offset("CharacterMesh", "BaseTextureId")) {
                    dumper::g_dumper.add_offset("CharacterMesh", "BaseTextureId", off);
                }
                else if (!dumper::g_dumper.get_offset("CharacterMesh", "MeshId")) {
                    dumper::g_dumper.add_offset("CharacterMesh", "MeshId", off);
                }
                else if (!dumper::g_dumper.get_offset("CharacterMesh", "OverlayTextureId")) {
                    dumper::g_dumper.add_offset("CharacterMesh", "OverlayTextureId", off);
                    break;
                }
            }
        }

        for (size_t off = 0x160; off < 0x178; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 6) {
                dumper::g_dumper.add_offset("CharacterMesh", "BodyPart", off);
                break;
            }
        }

        return true;
    }

    auto decal_texture() -> bool {
        if (!dumper::g_workspace) return false;

        auto decal = find_descendant(*dumper::g_workspace, "Decal", 6);
        if (!decal) decal = find_descendant(*dumper::g_workspace, "Texture", 6);
        if (!decal) return false;

        auto addr = decal->get_address();

        for (size_t off = 0x190; off < 0x1A8; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("Textures", "Decal_Texture", off);
                dumper::g_dumper.add_offset("Textures", "Texture_Texture", off);
                break;
            }
        }

        return true;
    }

    auto value_objects() -> bool {
        if (!dumper::g_data_model) return false;

        for (const auto& type : { "StringValue", "IntValue", "NumberValue", "BoolValue" }) {
            auto val = find_descendant(*dumper::g_data_model, type, 6);
            if (val) {
                auto addr = val->get_address();
                for (size_t off = 0xC8; off < 0xE0; off += 8) {
                    auto ptr = process::g_process.read<uintptr_t>(addr + off);
                    auto num = process::g_process.read<double>(addr + off);
                    if ((ptr && *ptr != 0) || (num && *num != 0.0)) {
                        dumper::g_dumper.add_offset("Misc", "Value", off);
                        goto found_value;
                    }
                }
            }
        }
    found_value:

        auto anim = find_descendant(*dumper::g_data_model, "Animation", 6);
        if (anim) {
            auto addr = anim->get_address();
            for (size_t off = 0xC8; off < 0xE0; off += 8) {
                auto str = process::g_process.read_sso_string(addr + off);
                if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                    dumper::g_dumper.add_offset("Misc", "AnimationId", off);
                    break;
                }
            }
        }

        auto bb = find_descendant(*dumper::g_workspace, "BillboardGui", 6);
        if (!bb) bb = find_descendant(*dumper::g_workspace, "Highlight", 6);
        if (bb) {
            auto addr = bb->get_address();
            for (size_t off = 0x100; off < 0x118; off += 8) {
                auto ptr = process::g_process.read<uintptr_t>(addr + off);
                if (!ptr) continue;
                if (*ptr == 0 || *ptr > 0x10000) {
                    dumper::g_dumper.add_offset("Misc", "Adornee", off);
                    break;
                }
            }
        }

        dumper::g_dumper.add_offset("Misc", "StringLength", 0x10);

        return true;
    }

    auto attachment() -> bool {
        if (!dumper::g_workspace) return false;

        auto att = find_descendant(*dumper::g_workspace, "Attachment", 6);
        if (!att) return false;

        auto addr = att->get_address();

        for (size_t off = 0xDC; off < 0xF8; off += 4) {
            if (is_valid_position(addr + off, 10000.0f)) {
                dumper::g_dumper.add_offset("Attachment", "Position", off);
                break;
            }
        }

        return true;
    }

    auto spawn_location() -> bool {
        if (!dumper::g_workspace) return false;

        auto sl = dumper::g_workspace->find_first_descendant_of_class("SpawnLocation", 6);
        if (!sl) return false;

        auto addr = sl->get_address();

        for (size_t off = 0x40; off < 0x50; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("SpawnLocation", "AllowTeamChangeOnTouch", off);
                break;
            }
        }

        for (size_t off = 0x1E8; off < 0x200; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("SpawnLocation", "ForcefieldDuration", off);
                break;
            }
        }

        for (size_t off = 0x1F0; off < 0x208; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 1 && *val <= 1032) {
                dumper::g_dumper.add_offset("SpawnLocation", "TeamColor", off);
                break;
            }
        }

        for (size_t off = 0x1F4; off < 0x208; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            auto next = process::g_process.read<uint8_t>(addr + off + 1);
            if (val && next && (*val == 0 || *val == 1) && (*next == 0 || *next == 1)) {
                dumper::g_dumper.add_offset("SpawnLocation", "Enabled", off);
                dumper::g_dumper.add_offset("SpawnLocation", "Neutral", off + 1);
                break;
            }
        }

        return true;
    }

    auto clothing() -> bool {
        if (!dumper::g_workspace) return false;

        auto cloth = find_descendant(*dumper::g_workspace, "Shirt", 6);
        if (!cloth) cloth = find_descendant(*dumper::g_workspace, "Pants", 6);
        if (!cloth) return false;

        auto addr = cloth->get_address();

        for (size_t off = 0x100; off < 0x118; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("Clothing", "Template", off);
                break;
            }
        }

        for (size_t off = 0x120; off < 0x138; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("Clothing", "Color3", off);
                break;
            }
        }

        return true;
    }

    auto special_mesh() -> bool {
        if (!dumper::g_workspace) return false;

        auto sm = find_descendant(*dumper::g_workspace, "SpecialMesh", 6);
        if (!sm) return false;

        auto addr = sm->get_address();

        for (size_t off = 0xD8; off < 0xF0; off += 4) {
            auto sx = process::g_process.read<float>(addr + off);
            auto sy = process::g_process.read<float>(addr + off + 4);
            auto sz = process::g_process.read<float>(addr + off + 8);
            if (sx && sy && sz && *sx > 0.0f && *sy > 0.0f && *sz > 0.0f) {
                dumper::g_dumper.add_offset("SpecialMesh", "Scale", off);
                break;
            }
        }

        for (size_t off = 0x100; off < 0x118; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("SpecialMesh", "MeshId", off);
                break;
            }
        }

        return true;
    }

    auto tool() -> bool {
        if (!dumper::g_workspace) return false;

        auto t = find_descendant(*dumper::g_workspace, "Tool", 6);
        if (!t && dumper::g_players) {
            for (const auto& p : dumper::g_players->get_children()) {
                auto bp = p.find_first_child("Backpack");
                if (bp) {
                    t = find_descendant(*bp, "Tool", 4);
                    if (t) break;
                }
            }
        }
        if (!t) return false;

        auto addr = t->get_address();

        for (size_t off = 0x2B0; off < 0x2C0; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Tool", "ManualActivationOnly", off);
                break;
            }
        }

        for (size_t off = 0x348; off < 0x368; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("Tool", "TextureId", off);
                break;
            }
        }

        for (size_t off = 0x34D; off < 0x360; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Tool", "Enabled", off);
                break;
            }
        }

        for (size_t off = 0x450; off < 0x470; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && str->length() < 256) {
                dumper::g_dumper.add_offset("Tool", "Tooltip", off);
                break;
            }
        }

        for (size_t off = 0x494; off < 0x4B0; off += 4) {
            if (is_valid_rotation_matrix(addr + off)) {
                dumper::g_dumper.add_offset("Tool", "Grip", off);
                break;
            }
        }

        for (size_t off = 0x4A0; off < 0x4B8; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Tool", "CanBeDropped", off);
                auto next = process::g_process.read<uint8_t>(addr + off + 3);
                if (next && (*next == 0 || *next == 1)) {
                    dumper::g_dumper.add_offset("Tool", "RequiresHandle", off + 3);
                }
                break;
            }
        }

        return true;
    }

    auto stats_item() -> bool {
        if (!dumper::g_data_model) return false;

        auto stats = dumper::g_data_model->find_first_child("Stats");
        if (!stats) return false;

        std::optional<roblox::Instance> item;
        for (const auto& c : stats->get_children()) {
            auto cn = c.get_class_name();
            if (cn && cn->find("Stats") != std::string::npos) {
                item = c;
                break;
            }
        }
        if (!item) return false;

        auto addr = item->get_address();

        for (size_t off = 0x1C0; off < 0x1D8; off += 8) {
            auto val = process::g_process.read<double>(addr + off);
            if (val && *val >= 0.0 && *val < 1000000.0) {
                dumper::g_dumper.add_offset("StatsItem", "Value", off);
                break;
            }
        }

        return true;
    }

    auto gui() -> bool {
        if (!dumper::g_players) return false;

        std::optional<roblox::Instance> pl;
        for (const auto& c : dumper::g_players->get_children()) {
            auto cn = c.get_class_name();
            if (cn && *cn == "Player") { pl = c; break; }
        }
        if (!pl) return false;

        auto pg = pl->find_first_child("PlayerGui");
        if (!pg) return false;

        std::optional<roblox::Instance> screen_gui, frame, text_label, text_button;

        for (const auto& c : pg->get_children()) {
            auto cn = c.get_class_name();
            if (cn && *cn == "ScreenGui") { screen_gui = c; break; }
        }

        if (screen_gui) {
            frame = find_descendant(*screen_gui, "Frame", 5);
            if (!frame) frame = find_descendant(*screen_gui, "ImageLabel", 5);
            text_label = find_descendant(*screen_gui, "TextLabel", 5);
            text_button = find_descendant(*screen_gui, "TextButton", 5);
        }

        if (screen_gui) {
            auto addr = screen_gui->get_address();

            for (size_t off = 0x108; off < 0x120; off += 4) {
                auto x = process::g_process.read<float>(addr + off);
                auto y = process::g_process.read<float>(addr + off + 4);
                if (x && y && *x >= 0.0f && *x < 4096.0f && *y >= 0.0f && *y < 4096.0f) {
                    dumper::g_dumper.add_offset("GuiBase2D", "AbsolutePosition", off);
                    break;
                }
            }

            auto pos = dumper::g_dumper.get_offset("GuiBase2D", "AbsolutePosition");
            for (size_t off = 0x110; off < 0x128; off += 4) {
                auto w = process::g_process.read<float>(addr + off);
                auto h = process::g_process.read<float>(addr + off + 4);
                if (w && h && *w > 0.0f && *w < 4096.0f && *h > 0.0f && *h < 4096.0f) {
                    if (!pos || off != *pos) {
                        dumper::g_dumper.add_offset("GuiBase2D", "AbsoluteSize", off);
                        break;
                    }
                }
            }

            for (size_t off = 0x188; off < 0x1A0; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= -360.0f && *val <= 360.0f) {
                    dumper::g_dumper.add_offset("GuiBase2D", "AbsoluteRotation", off);
                    break;
                }
            }

            for (size_t off = 0x4C8; off < 0x4D8; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("GuiObject", "ScreenGui_Enabled", off);
                    break;
                }
            }
        }

        if (frame) {
            auto addr = frame->get_address();

            for (size_t off = 0x510; off < 0x538; off += 4) {
                if (is_valid_udim2(addr + off, true)) {
                    dumper::g_dumper.add_offset("GuiObject", "Position", off);
                    break;
                }
            }

            auto pos_off = dumper::g_dumper.get_offset("GuiObject", "Position");
            for (size_t off = 0x530; off < 0x558; off += 4) {
                if (is_valid_udim2(addr + off, true)) {
                    if (!pos_off || off != *pos_off) {
                        dumper::g_dumper.add_offset("GuiObject", "Size", off);
                        break;
                    }
                }
            }

            for (size_t off = 0x540; off < 0x560; off += 4) {
                if (is_valid_color3(addr + off)) {
                    dumper::g_dumper.add_offset("GuiObject", "BackgroundColor3", off);
                    break;
                }
            }

            auto bg = dumper::g_dumper.get_offset("GuiObject", "BackgroundColor3");
            for (size_t off = 0x550; off < 0x568; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= 0.0f && *val <= 1.0f) {
                    if (!bg || off < *bg || off >= *bg + 12) {
                        dumper::g_dumper.add_offset("GuiObject", "BackgroundTransparency", off);
                        break;
                    }
                }
            }

            for (size_t off = 0x550; off < 0x570; off += 4) {
                if (is_valid_color3(addr + off)) {
                    if (!bg || off != *bg) {
                        dumper::g_dumper.add_offset("GuiObject", "BorderColor3", off);
                        break;
                    }
                }
            }

            for (size_t off = 0x580; off < 0x598; off += 4) {
                auto val = process::g_process.read<int32_t>(addr + off);
                if (val && *val >= -1000000 && *val <= 1000000) {
                    dumper::g_dumper.add_offset("GuiObject", "LayoutOrder", off);
                    break;
                }
            }

            for (size_t off = 0x5A0; off < 0x5B8; off += 4) {
                auto val = process::g_process.read<int32_t>(addr + off);
                if (val && *val >= 0 && *val <= 1000000) {
                    dumper::g_dumper.add_offset("GuiObject", "ZIndex", off);
                    break;
                }
            }

            for (size_t off = 0x188; off < 0x1A0; off += 4) {
                auto val = process::g_process.read<float>(addr + off);
                if (val && *val >= -360.0f && *val <= 360.0f) {
                    dumper::g_dumper.add_offset("GuiObject", "Rotation", off);
                    break;
                }
            }

            for (size_t off = 0x5AD; off < 0x5C0; off++) {
                auto val = process::g_process.read<uint8_t>(addr + off);
                if (val && (*val == 0 || *val == 1)) {
                    dumper::g_dumper.add_offset("GuiObject", "Visible", off);
                    break;
                }
            }
        }

        return true;
    }

    auto air_properties() -> bool {
        auto world_off = dumper::g_dumper.get_offset("Workspace", "World");
        if (!world_off || !dumper::g_workspace) return false;

        auto world_addr = process::g_process.read<uintptr_t>(dumper::g_workspace->get_address() + *world_off);
        if (!world_addr || *world_addr < 0x10000) return false;

        for (size_t off = 0x1D0; off < 0x1F0; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(*world_addr + off);
            if (!ptr || *ptr < 0x10000) continue;

            for (size_t doff = 0x14; doff < 0x20; doff += 4) {
                auto density = process::g_process.read<float>(*ptr + doff);
                if (density && *density >= 0.0f && *density <= 10.0f && *density > 0.001f) {
                    dumper::g_dumper.add_offset("World", "AirProperties", off);
                    dumper::g_dumper.add_offset("AirProperties", "AirDensity", doff);

                    for (size_t woff = 0x3c; woff < 0x50; woff += 4) {
                        auto wind_x = process::g_process.read<float>(*ptr + woff);
                        auto wind_y = process::g_process.read<float>(*ptr + woff + 4);
                        auto wind_z = process::g_process.read<float>(*ptr + woff + 8);
                        if (wind_x && wind_y && wind_z) {
                            if (std::abs(*wind_x) < 10000.0f && std::abs(*wind_y) < 10000.0f && std::abs(*wind_z) < 10000.0f) {
                                dumper::g_dumper.add_offset("AirProperties", "GlobalWind", woff);
                                return true;
                            }
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

    auto player_configurer() -> bool {
        auto section = process::g_process.get_section(".data");
        if (!section) return false;

        auto [section_start, section_size] = *section;
        auto module_base = process::g_process.get_module_base();

        for (size_t offset = 0; offset < section_size; offset += 8) {
            auto ptr = process::g_process.read<uintptr_t>(section_start + offset);
            if (!ptr || *ptr < 0x10000) continue;

            auto info = rtti::scan(*ptr);
            if (info && info->name.find("PlayerConfigurer") != std::string::npos) {
                auto calculated_offset = (section_start + offset) - module_base;
                dumper::g_dumper.add_offset("PlayerConfigurer", "Pointer", calculated_offset);
                return true;
            }
        }
        return false;
    }

    auto highlight() -> bool {
        if (!dumper::g_workspace) return false;

        auto hl = find_descendant(*dumper::g_workspace, "Highlight", 6);
        if (!hl) return false;

        auto addr = hl->get_address();

        for (size_t off = 0x100; off < 0x118; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                dumper::g_dumper.add_offset("Highlight", "Adornee", off);
                break;
            }
        }

        for (size_t off = 0x110; off < 0x130; off += 4) {
            if (is_valid_color3(addr + off)) {
                if (!dumper::g_dumper.get_offset("Highlight", "FillColor")) {
                    dumper::g_dumper.add_offset("Highlight", "FillColor", off);
                }
                else if (!dumper::g_dumper.get_offset("Highlight", "OutlineColor")) {
                    dumper::g_dumper.add_offset("Highlight", "OutlineColor", off);
                    break;
                }
                off += 8;
            }
        }

        for (size_t off = 0x128; off < 0x140; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1.0f) {
                if (!dumper::g_dumper.get_offset("Highlight", "FillTransparency")) {
                    dumper::g_dumper.add_offset("Highlight", "FillTransparency", off);
                }
                else if (!dumper::g_dumper.get_offset("Highlight", "OutlineTransparency")) {
                    dumper::g_dumper.add_offset("Highlight", "OutlineTransparency", off);
                    break;
                }
            }
        }

        for (size_t off = 0x134; off < 0x148; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Highlight", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto beam() -> bool {
        if (!dumper::g_workspace) return false;

        auto b = find_descendant(*dumper::g_workspace, "Beam", 6);
        if (!b) return false;

        auto addr = b->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                if (!dumper::g_dumper.get_offset("Beam", "Attachment0")) {
                    dumper::g_dumper.add_offset("Beam", "Attachment0", off);
                }
                else if (!dumper::g_dumper.get_offset("Beam", "Attachment1")) {
                    dumper::g_dumper.add_offset("Beam", "Attachment1", off);
                    break;
                }
            }
        }

        for (size_t off = 0x100; off < 0x118; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("Beam", "Color", off);
                break;
            }
        }

        for (size_t off = 0x118; off < 0x130; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("Beam", "Width0", off);
                dumper::g_dumper.add_offset("Beam", "Width1", off + 4);
                break;
            }
        }

        for (size_t off = 0x128; off < 0x140; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Beam", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto particle_emitter() -> bool {
        if (!dumper::g_workspace) return false;

        auto pe = find_descendant(*dumper::g_workspace, "ParticleEmitter", 6);
        if (!pe) return false;

        auto addr = pe->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 8) {
            auto str = process::g_process.read_sso_string(addr + off);
            if (str && (str->empty() || str->find("rbxasset") != std::string::npos)) {
                dumper::g_dumper.add_offset("ParticleEmitter", "Texture", off);
                break;
            }
        }

        for (size_t off = 0x100; off < 0x118; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("ParticleEmitter", "Color", off);
                break;
            }
        }

        for (size_t off = 0x118; off < 0x130; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1000.0f) {
                dumper::g_dumper.add_offset("ParticleEmitter", "Rate", off);
                break;
            }
        }

        for (size_t off = 0x128; off < 0x140; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("ParticleEmitter", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto surface_gui() -> bool {
        if (!dumper::g_workspace) return false;

        auto sg = find_descendant(*dumper::g_workspace, "SurfaceGui", 6);
        if (!sg) return false;

        auto addr = sg->get_address();

        for (size_t off = 0x100; off < 0x118; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                dumper::g_dumper.add_offset("SurfaceGui", "Adornee", off);
                break;
            }
        }

        for (size_t off = 0x118; off < 0x130; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 5) {
                dumper::g_dumper.add_offset("SurfaceGui", "Face", off);
                break;
            }
        }

        for (size_t off = 0x128; off < 0x140; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("SurfaceGui", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto billboard_gui() -> bool {
        if (!dumper::g_workspace) return false;

        auto bg = find_descendant(*dumper::g_workspace, "BillboardGui", 6);
        if (!bg) return false;

        auto addr = bg->get_address();

        for (size_t off = 0x100; off < 0x118; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                dumper::g_dumper.add_offset("BillboardGui", "Adornee", off);
                break;
            }
        }

        for (size_t off = 0x118; off < 0x130; off += 4) {
            if (is_valid_udim2(addr + off, true)) {
                dumper::g_dumper.add_offset("BillboardGui", "Size", off);
                break;
            }
        }

        for (size_t off = 0x128; off < 0x140; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 10000.0f) {
                dumper::g_dumper.add_offset("BillboardGui", "MaxDistance", off);
                break;
            }
        }

        for (size_t off = 0x138; off < 0x150; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("BillboardGui", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto weld_constraint() -> bool {
        if (!dumper::g_workspace) return false;

        auto wc = find_descendant(*dumper::g_workspace, "WeldConstraint", 6);
        if (!wc) wc = find_descendant(*dumper::g_workspace, "Weld", 6);
        if (!wc) return false;

        auto addr = wc->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                if (!dumper::g_dumper.get_offset("WeldConstraint", "Part0")) {
                    dumper::g_dumper.add_offset("WeldConstraint", "Part0", off);
                }
                else if (!dumper::g_dumper.get_offset("WeldConstraint", "Part1")) {
                    dumper::g_dumper.add_offset("WeldConstraint", "Part1", off);
                    break;
                }
            }
        }

        for (size_t off = 0xF8; off < 0x110; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("WeldConstraint", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto body_velocity() -> bool {
        if (!dumper::g_workspace) return false;

        auto bv = find_descendant(*dumper::g_workspace, "BodyVelocity", 6);
        if (!bv) bv = find_descendant(*dumper::g_workspace, "LinearVelocity", 6);
        if (!bv) return false;

        auto addr = bv->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            if (is_valid_position(addr + off, 10000.0f)) {
                dumper::g_dumper.add_offset("BodyVelocity", "Velocity", off);
                break;
            }
        }

        for (size_t off = 0xE8; off < 0x100; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1000000.0f) {
                dumper::g_dumper.add_offset("BodyVelocity", "MaxForce", off);
                break;
            }
        }

        return true;
    }

    auto body_gyro() -> bool {
        if (!dumper::g_workspace) return false;

        auto bg = find_descendant(*dumper::g_workspace, "BodyGyro", 6);
        if (!bg) bg = find_descendant(*dumper::g_workspace, "AlignOrientation", 6);
        if (!bg) return false;

        auto addr = bg->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            if (is_valid_rotation_matrix(addr + off)) {
                dumper::g_dumper.add_offset("BodyGyro", "CFrame", off);
                break;
            }
        }

        for (size_t off = 0x100; off < 0x118; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1000000.0f) {
                dumper::g_dumper.add_offset("BodyGyro", "MaxTorque", off);
                break;
            }
        }

        return true;
    }

    auto force_field() -> bool {
        if (!dumper::g_workspace) return false;

        auto ff = find_descendant(*dumper::g_workspace, "ForceField", 6);
        if (!ff) return false;

        auto addr = ff->get_address();

        for (size_t off = 0xC8; off < 0xE0; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("ForceField", "Visible", off);
                break;
            }
        }

        return true;
    }

    auto explosion() -> bool {
        if (!dumper::g_workspace) return false;

        std::optional<roblox::Instance> exp;

        for (const auto& child : dumper::g_workspace->get_children()) {
            auto cn = child.get_class_name();
            if (cn && *cn == "Explosion") {
                exp = child;
                break;
            }

            auto found = child.find_first_child_of_class("Explosion");
            if (found) {
                exp = found;
                break;
            }
        }

        if (!exp) {
            exp = find_descendant(*dumper::g_workspace, "Explosion", 8);
        }

        if (!exp) return false;

        auto addr = exp->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            if (is_valid_position(addr + off)) {
                dumper::g_dumper.add_offset("Explosion", "Position", off);
                break;
            }
        }

        for (size_t off = 0xE8; off < 0x108; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1000.0f && *val > 0.1f) {
                dumper::g_dumper.add_offset("Explosion", "BlastRadius", off);
                break;
            }
        }

        auto br = dumper::g_dumper.get_offset("Explosion", "BlastRadius");
        for (size_t off = 0xEC; off < 0x110; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1000000.0f) {
                if (!br || off != *br) {
                    dumper::g_dumper.add_offset("Explosion", "BlastPressure", off);
                    break;
                }
            }
        }

        for (size_t off = 0xF8; off < 0x118; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 1.0f) {
                dumper::g_dumper.add_offset("Explosion", "DestroyJointRadiusPercent", off);
                break;
            }
        }

        for (size_t off = 0x100; off < 0x118; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Explosion", "Visible", off);
                break;
            }
        }

        return true;
    }

    auto fire() -> bool {
        if (!dumper::g_workspace) return false;

        auto f = find_descendant(*dumper::g_workspace, "Fire", 6);
        if (!f) return false;

        auto addr = f->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("Fire", "Color", off);
                break;
            }
        }

        for (size_t off = 0xE8; off < 0x100; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("Fire", "Size", off);
                break;
            }
        }

        for (size_t off = 0xF8; off < 0x110; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Fire", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto smoke() -> bool {
        if (!dumper::g_workspace) return false;

        auto s = find_descendant(*dumper::g_workspace, "Smoke", 6);
        if (!s) return false;

        auto addr = s->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("Smoke", "Color", off);
                break;
            }
        }

        for (size_t off = 0xE8; off < 0x100; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("Smoke", "Size", off);
                break;
            }
        }

        for (size_t off = 0xF8; off < 0x110; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Smoke", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto sparkles() -> bool {
        if (!dumper::g_workspace) return false;

        auto sp = find_descendant(*dumper::g_workspace, "Sparkles", 6);
        if (!sp) return false;

        auto addr = sp->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("Sparkles", "SparkleColor", off);
                break;
            }
        }

        for (size_t off = 0xF8; off < 0x110; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("Sparkles", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto point_light() -> bool {
        if (!dumper::g_workspace) return false;

        auto pl = find_descendant(*dumper::g_workspace, "PointLight", 6);
        if (!pl) pl = find_descendant(*dumper::g_workspace, "SpotLight", 6);
        if (!pl) pl = find_descendant(*dumper::g_workspace, "SurfaceLight", 6);
        if (!pl) return false;

        auto addr = pl->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            if (is_valid_color3(addr + off)) {
                dumper::g_dumper.add_offset("PointLight", "Color", off);
                break;
            }
        }

        for (size_t off = 0xE8; off < 0x100; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 10.0f) {
                dumper::g_dumper.add_offset("PointLight", "Brightness", off);
                break;
            }
        }

        for (size_t off = 0xF0; off < 0x108; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("PointLight", "Range", off);
                break;
            }
        }

        for (size_t off = 0xF8; off < 0x110; off++) {
            auto val = process::g_process.read<uint8_t>(addr + off);
            if (val && (*val == 0 || *val == 1)) {
                dumper::g_dumper.add_offset("PointLight", "Enabled", off);
                break;
            }
        }

        return true;
    }

    auto replicated_storage() -> bool {
        if (!dumper::g_data_model) return false;

        auto rs = dumper::g_data_model->find_first_child("ReplicatedStorage");
        if (!rs) return false;

        dumper::g_replicated_storage = rs;
        return true;
    }

    auto starter_player() -> bool {
        if (!dumper::g_data_model) return false;

        auto sp = dumper::g_data_model->find_first_child("StarterPlayer");
        if (!sp) return false;

        auto addr = sp->get_address();

        for (size_t off = 0x100; off < 0x120; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 0.0f && *val <= 100.0f && std::abs(*val - 16.0f) < 5.0f) {
                dumper::g_dumper.add_offset("StarterPlayer", "CharacterWalkSpeed", off);
                break;
            }
        }

        for (size_t off = 0x108; off < 0x128; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 20.0f && *val <= 100.0f) {
                dumper::g_dumper.add_offset("StarterPlayer", "CharacterJumpPower", off);
                break;
            }
        }

        for (size_t off = 0x110; off < 0x130; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 1.0f && *val <= 20.0f) {
                dumper::g_dumper.add_offset("StarterPlayer", "CharacterJumpHeight", off);
                break;
            }
        }

        for (size_t off = 0x128; off < 0x148; off += 4) {
            auto val = process::g_process.read<float>(addr + off);
            if (val && *val >= 50.0f && *val <= 10000.0f) {
                dumper::g_dumper.add_offset("StarterPlayer", "CharacterMaxHealth", off);
                break;
            }
        }

        return true;
    }

    auto backpack() -> bool {
        if (!dumper::g_players) return false;

        std::optional<roblox::Instance> pl;
        for (const auto& c : dumper::g_players->get_children()) {
            auto cn = c.get_class_name();
            if (cn && *cn == "Player") { pl = c; break; }
        }
        if (!pl) return false;

        auto bp = pl->find_first_child("Backpack");
        if (!bp) return false;

        auto addr = bp->get_address();

        for (size_t off = 0xC8; off < 0xE8; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                dumper::g_dumper.add_offset("Backpack", "Player", off);
                break;
            }
        }

        return true;
    }

    auto accessory() -> bool {
        if (!dumper::g_workspace) return false;

        auto acc = find_descendant(*dumper::g_workspace, "Accessory", 6);
        if (!acc) acc = find_descendant(*dumper::g_workspace, "Hat", 6);
        if (!acc) return false;

        auto addr = acc->get_address();

        for (size_t off = 0x100; off < 0x120; off += 8) {
            auto ptr = process::g_process.read<uintptr_t>(addr + off);
            if (!ptr) continue;
            if (*ptr == 0 || *ptr > 0x10000) {
                auto info = rtti::scan(*ptr);
                if (info && info->name.find("Part") != std::string::npos) {
                    dumper::g_dumper.add_offset("Accessory", "Handle", off);
                    break;
                }
            }
        }

        for (size_t off = 0x110; off < 0x130; off += 4) {
            auto val = process::g_process.read<int32_t>(addr + off);
            if (val && *val >= 0 && *val <= 10) {
                dumper::g_dumper.add_offset("Accessory", "AccessoryType", off);
                break;
            }
        }

        return true;
    }

    auto head_accessory() -> bool {
        if (!dumper::g_workspace) return false;

        auto ha = find_descendant(*dumper::g_workspace, "Accessory", 6);
        if (!ha) return false;

        auto handle = ha->find_first_child("Handle");
        if (!handle) return false;

        auto mesh = handle->find_first_child_of_class("SpecialMesh");
        if (!mesh) mesh = handle->find_first_child_of_class("FileMesh");
        if (!mesh) return false;

        auto addr = mesh->get_address();

        for (size_t off = 0xD8; off < 0xF8; off += 4) {
            auto sx = process::g_process.read<float>(addr + off);
            auto sy = process::g_process.read<float>(addr + off + 4);
            auto sz = process::g_process.read<float>(addr + off + 8);
            if (sx && sy && sz && *sx > 0.0f && *sy > 0.0f && *sz > 0.0f) {
                dumper::g_dumper.add_offset("HeadAccessory", "Scale", off);
                break;
            }
        }

        for (size_t off = 0xE8; off < 0x108; off += 4) {
            if (is_valid_position(addr + off, 1000.0f)) {
                dumper::g_dumper.add_offset("HeadAccessory", "Offset", off);
                break;
            }
        }

        return true;
    }
} // namespace stages