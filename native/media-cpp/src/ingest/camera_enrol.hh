#ifndef VAULTARC_CAMERA_ENROL_HH
#define VAULTARC_CAMERA_ENROL_HH

#include <span>

#include "vaultarc.hh"

namespace vaultarc {

struct CameraEnrolment {
    Bytes our_public;
    Bytes shared_secret;
};

CameraEnrolment enrol_camera(std::span<const uint8_t> camera_public);

}  // namespace vaultarc

#endif
