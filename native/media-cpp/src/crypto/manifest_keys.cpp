// `vaultarc keygen`: the manifest signing key. An RSA-3072 key, written as an encrypted PKCS#8 PEM
// so the key file can be moved to the signing host.
#include "crypto/manifest_keys.hh"

#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>

namespace vaultarc {

std::string generate_manifest_key(std::string_view passphrase) {
    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey key(rng, 3072);
    const std::string pem = Botan::PKCS8::PEM_encode(key, rng, std::string(passphrase));
    return pem;
}

std::unique_ptr<Botan::Private_Key> load_manifest_key(std::string_view pem, std::string_view passphrase) {
    Botan::DataSource_Memory src{pem};
    return Botan::PKCS8::load_key(src, passphrase);
}

}  // namespace vaultarc
