#ifndef VAULTARC_NONCE_SOURCE_HH
#define VAULTARC_NONCE_SOURCE_HH

#include <memory>

#include "vaultarc.hh"

namespace Botan {
class HMAC_DRBG;
}

namespace vaultarc {

class NonceSource {
public:
    NonceSource();
    ~NonceSource();
    Bytes next(size_t len);

private:
    std::unique_ptr<Botan::HMAC_DRBG> drbg_;
};

}  // namespace vaultarc

#endif
