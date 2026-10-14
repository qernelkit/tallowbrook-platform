#ifndef VAULTARC_KEY_WRAP_HH
#define VAULTARC_KEY_WRAP_HH

#include <span>

#include "vaultarc.hh"

namespace vaultarc {

struct ArchiveKek {
    Bytes public_bytes;
    Bytes private_bytes;
};

struct WrappedKey {
    Bytes encapsulation;
    Bytes shared_secret;
};

ArchiveKek new_archive_kek();
WrappedKey wrap_content_key(std::span<const uint8_t> kek_public, std::span<const uint8_t> content_key);

}  // namespace vaultarc

#endif
