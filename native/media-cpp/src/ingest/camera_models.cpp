// Camera model table: capabilities per model the ingest path keys off (resolution, whether the model
// has an AES engine). No crypto; the "Falcon" here is a camera product line.
#include "ingest/camera_models.hh"

namespace vaultarc {

enum class CameraModel { Falcon, Harrier, Kestrel, Osprey };

struct CameraSpec {
    CameraModel model;
    const char* name;
    int width;
    int height;
    bool has_aes_engine;
};

static const CameraSpec kCameraModels[] = {
    {CameraModel::Falcon, "Falcon PTZ-4K", 3840, 2160, true},
    {CameraModel::Harrier, "Harrier Dome", 2560, 1440, true},
    {CameraModel::Kestrel, "Kestrel Bullet", 1920, 1080, false},
    {CameraModel::Osprey, "Osprey Mini", 1280, 720, false},
};

const CameraSpec* camera_spec(std::string_view name) {
    for (const auto& spec : kCameraModels) {
        if (name == spec.name)
            return &spec;
    }
    return nullptr;
}

bool camera_has_aes(std::string_view name) {
    const CameraSpec* spec = camera_spec(name);
    return spec != nullptr && spec->has_aes_engine;
}

}  // namespace vaultarc
