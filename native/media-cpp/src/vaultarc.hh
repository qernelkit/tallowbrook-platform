// Shared types for vaultarc.
#ifndef VAULTARC_HH
#define VAULTARC_HH

#include <cstdint>
#include <stdexcept>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vaultarc {

using Bytes = std::vector<uint8_t>;

enum class Format { kFormat1 = 1, kFormat2 = 2 };

struct ArchiveHeader {
    std::string archive_id;
    Format format = Format::kFormat2;
    uint64_t original_size = 0;
    uint32_t chunk_count = 0;
};

// Thrown on any archive-level failure; main() turns it into a message and an exit code.
class ArchiveError : public std::runtime_error {
public:
    explicit ArchiveError(const std::string& what) : std::runtime_error(what) {}
};

Bytes seal_archive(std::span<const uint8_t> plaintext, std::span<const uint8_t> key,
                   std::span<const uint8_t> nonce, std::string_view archive_id);
Bytes open_archive(std::span<const uint8_t> container, std::span<const uint8_t> key, std::string_view archive_id);

Bytes seal_drive_image(std::span<const uint8_t> plaintext, std::span<const uint8_t> key,
                       std::span<const uint8_t> tweak);

}  // namespace vaultarc

#endif
