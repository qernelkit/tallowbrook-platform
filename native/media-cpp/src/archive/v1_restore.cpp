// Format-1 archive restore. The first generation of the tool protected small archives with
// Crypto++'s DefaultEncryptorWithMAC, a password-based envelope. `vaultarc restore` still opens
// those so old evidence can be read back.
#include "archive/v1_restore.hh"

#include <iostream>

#include <cryptopp/default.h>
#include <cryptopp/filters.h>

namespace vaultarc {

Bytes restore_v1(std::string_view path, std::string_view passphrase, std::span<const uint8_t> container) {
    std::string plain;
    std::clog << "restoring " << path << " (format 1, passphrase)\n";
    try {
        CryptoPP::DefaultDecryptorWithMAC decryptor(passphrase.data(), new CryptoPP::StringSink(plain));
        decryptor.Put(container.data(), container.size());
        decryptor.MessageEnd();
    } catch (const CryptoPP::Exception& e) {
        throw ArchiveError(std::string("format-1 restore failed: ") + e.what());
    }
    return Bytes(plain.begin(), plain.end());
}

}  // namespace vaultarc
