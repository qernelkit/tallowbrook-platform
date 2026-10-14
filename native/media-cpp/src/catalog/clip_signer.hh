#ifndef VAULTARC_CLIP_SIGNER_HH
#define VAULTARC_CLIP_SIGNER_HH

#include <span>

#include <cryptopp/rsa.h>

#include "vaultarc.hh"

namespace vaultarc {

Bytes sign_evidence_clip(const CryptoPP::RSA::PrivateKey& clip_key, std::span<const uint8_t> clip);

}  // namespace vaultarc

#endif
