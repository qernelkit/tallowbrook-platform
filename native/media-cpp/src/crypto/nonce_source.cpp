// Deterministic nonce source for a seal run: an HMAC_DRBG seeded from the system RNG, so the many
// chunk nonces in one archive never collide even if the OS RNG stutters mid-run.
#include "crypto/nonce_source.hh"

#include <botan/hmac_drbg.h>
#include <botan/mac.h>
#include <botan/system_rng.h>

namespace vaultarc {

NonceSource::NonceSource()
    : drbg_(std::make_unique<Botan::HMAC_DRBG>(
          Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)"),
          Botan::system_rng())) {}

NonceSource::~NonceSource() = default;

Bytes NonceSource::next(size_t len) {
    Bytes nonce(len);
    drbg_->randomize(nonce.data(), nonce.size());
    return nonce;
}

}  // namespace vaultarc
