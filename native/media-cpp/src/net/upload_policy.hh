// TLS policy for uploads to the archive object store: TLS 1.3 only, a short AEAD cipher list, and a
// a hybrid key-exchange group preferred over X25519.
#ifndef VAULTARC_UPLOAD_POLICY_HH
#define VAULTARC_UPLOAD_POLICY_HH

#include <string>
#include <vector>

#include <botan/tls_policy.h>

namespace vaultarc {

class ArchiveUploadPolicy final : public Botan::TLS::Policy {
public:
    std::vector<std::string> allowed_ciphers() const override {
        return {"AES-256/GCM", "ChaCha20Poly1305"};
    }

    std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
        return {Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768, Botan::TLS::Group_Params::X25519};
    }

    bool allow_tls12() const override { return false; }
};

}  // namespace vaultarc

#endif
