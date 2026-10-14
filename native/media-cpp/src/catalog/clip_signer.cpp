// Evidence clips handed to insurers are signed so the insurer can prove the clip is the one the
// depot produced. RSA-PSS with SHA-256 via Crypto++, to match the insurer's verification tool.
#include "catalog/clip_signer.hh"

#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

namespace vaultarc {

Bytes sign_evidence_clip(const CryptoPP::RSA::PrivateKey& clip_key, std::span<const uint8_t> clip) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(clip_key);

    Bytes signature(signer.MaxSignatureLength());
    size_t len = signer.SignMessage(rng, clip.data(), clip.size(), signature.data());
    signature.resize(len);
    return signature;
}

}  // namespace vaultarc
