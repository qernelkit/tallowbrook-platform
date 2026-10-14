// Clip fingerprints for the evidence catalogue: a SHA3-256 over the clip bytes, so two copies of the
// same clip collapse to one catalogue entry. Crypto++ for the SHA-3 implementation.
#include "catalog/clip_fingerprint.hh"

#include <cryptopp/sha3.h>

namespace vaultarc {

std::array<uint8_t, 32> clip_fingerprint(std::span<const uint8_t> frame) {
    std::array<uint8_t, 32> fp{};
    CryptoPP::SHA3_256().CalculateDigest(fp.data(), frame.data(), frame.size());
    return fp;
}

}  // namespace vaultarc
