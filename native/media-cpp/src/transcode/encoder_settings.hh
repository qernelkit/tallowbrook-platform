#ifndef VAULTARC_ENCODER_SETTINGS_HH
#define VAULTARC_ENCODER_SETTINGS_HH

#include <string>

namespace vaultarc {

struct EncoderSettings {
    int height = 0;
    int bitrate_kbps = 0;
    int key_int_max = 0;
    int crf = 0;
    std::string preset;
};

EncoderSettings proxy_settings(int height);

}  // namespace vaultarc

#endif
