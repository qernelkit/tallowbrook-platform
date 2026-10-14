// Proxy transcode settings for the review UI. These are H.264 encoder knobs; "key" here is the
// key-frame (I-frame) interval, nothing cryptographic.
#include "transcode/encoder_settings.hh"

namespace vaultarc {

EncoderSettings proxy_settings(int height) {
    EncoderSettings settings;
    settings.height = height;
    settings.bitrate_kbps = height >= 1080 ? 4000 : 1500;
    settings.key_int_max = 250;
    settings.crf = 23;
    settings.preset = "veryfast";
    return settings;
}

}  // namespace vaultarc
