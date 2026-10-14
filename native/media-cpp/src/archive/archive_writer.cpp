// Container layout: a header, the chunk table, the sealed payload and the manifest. This module only
// packs and unpacks the byte layout; the crypto is in crypto/.
#include "archive/archive_writer.hh"

#include <cstring>

namespace vaultarc {
namespace {
constexpr uint32_t kMagic = 0x56415243;  // 'VARC'
constexpr uint16_t kVersion = 2;
}  // namespace

static void put_u32(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

static void put_u64(Bytes& out, uint64_t v) {
    put_u32(out, static_cast<uint32_t>(v >> 32));
    put_u32(out, static_cast<uint32_t>(v));
}

Bytes write_container(const ArchiveHeader& header, std::span<const uint8_t> sealed_payload,
                      std::span<const uint8_t> manifest) {
    Bytes out;
    put_u32(out, kMagic);
    out.push_back(static_cast<uint8_t>(kVersion >> 8));
    out.push_back(static_cast<uint8_t>(kVersion));
    out.push_back(static_cast<uint8_t>(header.format));
    out.push_back(0);
    put_u64(out, header.original_size);
    put_u32(out, header.chunk_count);

    put_u32(out, static_cast<uint32_t>(header.archive_id.size()));
    out.insert(out.end(), header.archive_id.begin(), header.archive_id.end());

    put_u64(out, sealed_payload.size());
    out.insert(out.end(), sealed_payload.begin(), sealed_payload.end());

    put_u32(out, static_cast<uint32_t>(manifest.size()));
    out.insert(out.end(), manifest.begin(), manifest.end());
    return out;
}

bool read_header(std::span<const uint8_t> container, ArchiveHeader& out) {
    if (container.size() < 20)
        return false;
    uint32_t magic = static_cast<uint32_t>(container[0]) << 24 | static_cast<uint32_t>(container[1]) << 16 |
                     static_cast<uint32_t>(container[2]) << 8 | container[3];
    if (magic != kMagic)
        return false;
    out.format = static_cast<Format>(container[6]);
    out.original_size = 0;
    for (int i = 0; i < 8; i++)
        out.original_size = out.original_size << 8 | container[8 + i];
    out.chunk_count = static_cast<uint32_t>(container[16]) << 24 | static_cast<uint32_t>(container[17]) << 16 |
                      static_cast<uint32_t>(container[18]) << 8 | container[19];
    return true;
}

}  // namespace vaultarc
