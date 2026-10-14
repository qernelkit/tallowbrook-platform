#ifndef VAULTARC_ARCHIVE_WRITER_HH
#define VAULTARC_ARCHIVE_WRITER_HH

#include <span>

#include "vaultarc.hh"

namespace vaultarc {

Bytes write_container(const ArchiveHeader& header, std::span<const uint8_t> sealed_payload,
                      std::span<const uint8_t> manifest);
bool read_header(std::span<const uint8_t> container, ArchiveHeader& out);

}  // namespace vaultarc

#endif
