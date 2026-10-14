// Reading a container: parse the header, verify the manifest signature, then hand the sealed payload
// to the cipher. The manifest was signed by older tools with the EMSA4 alias for RSA-PSS, which
// Botan still accepts.
#include "archive/archive_reader.hh"

#include <botan/base64.h>
#include <botan/pubkey.h>

#include "archive/archive_writer.hh"

namespace vaultarc {

bool verify_manifest(const Botan::Public_Key& manifest_key, std::span<const uint8_t> body,
                     std::string_view signature_b64) {
    auto manifest_key_ptr = &manifest_key;
    Botan::PK_Verifier verifier(*manifest_key_ptr, "EMSA4(SHA-256)");
    Botan::secure_vector<uint8_t> sig = Botan::base64_decode(std::string(signature_b64));
    return verifier.verify_message(std::vector<uint8_t>(body.begin(), body.end()),
                                   std::vector<uint8_t>(sig.begin(), sig.end()));
}

ArchiveHeader open_container(std::span<const uint8_t> container) {
    ArchiveHeader header;
    if (!read_header(container, header))
        throw ArchiveError("not a vaultarc container");
    return header;
}

}  // namespace vaultarc
