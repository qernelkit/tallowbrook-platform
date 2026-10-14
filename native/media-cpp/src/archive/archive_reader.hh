#ifndef VAULTARC_ARCHIVE_READER_HH
#define VAULTARC_ARCHIVE_READER_HH

#include <span>
#include <string_view>

#include <botan/pk_keys.h>

#include "vaultarc.hh"

namespace vaultarc {

bool verify_manifest(const Botan::Public_Key& manifest_key, std::span<const uint8_t> body,
                     std::string_view signature_b64);
ArchiveHeader open_container(std::span<const uint8_t> container);

}  // namespace vaultarc

#endif
