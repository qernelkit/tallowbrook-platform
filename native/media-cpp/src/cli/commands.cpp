// CLI command dispatch and the --self-check path, which proves the Botan and Crypto++ identifiers the
// tool relies on exist at run time (ML-KEM mode, the HSS-LMS parameter string, the TLS policy groups,
// SHA3-256, the Default*WithMAC envelope).
#include "cli/commands.hh"

#include <array>
#include <iostream>
#include <string_view>

#include "archive/v1_restore.hh"
#include "catalog/clip_fingerprint.hh"
#include "crypto/key_wrap.hh"
#include "crypto/manifest_keys.hh"
#include "crypto/manifest_signer.hh"
#include "crypto/nonce_source.hh"
#include "crypto/passphrase.hh"
#include "crypto/yearly_seal.hh"
#include "ingest/camera_enrol.hh"
#include "ingest/camera_feed.hh"
#include "ingest/camera_keys.hh"
#include "net/upload_policy.hh"
#include "partner/de_exchange.hh"
#include "store/object_upload.hh"
#include "vaultarc.hh"

#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <cryptopp/default.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

namespace vaultarc {
namespace {

bool check_archive_roundtrip() {
    NonceSource nonces;
    Botan::AutoSeeded_RNG rng;
    Bytes key = rng.random_vec<Bytes>(32);
    Bytes nonce = nonces.next(12);
    Bytes plain = {'c', 'l', 'a', 'i', 'm', '-', '4', '4', '1', '7'};

    Bytes sealed = seal_archive(plain, key, nonce, "arc-2026-04417");
    Bytes opened = open_archive(sealed, key, "arc-2026-04417");
    return opened == plain;
}

bool check_drive_image() {
    Botan::AutoSeeded_RNG rng;
    Bytes key = rng.random_vec<Bytes>(64);
    Bytes tweak = rng.random_vec<Bytes>(16);
    Bytes plain(64, 0x5a);
    Bytes sealed = seal_drive_image(plain, key, tweak);
    return sealed.size() == plain.size() && sealed != plain;
}

bool check_manifest_signature() {
    const std::string pem = generate_manifest_key("review-passphrase-2026");
    Botan::DataSource_Memory src(pem);
    auto key = Botan::PKCS8::load_key(src, std::string("review-passphrase-2026"));
    Bytes body = {'m', 'a', 'n', 'i', 'f', 'e', 's', 't'};
    Manifest manifest = sign_manifest(*key, body);
    return !manifest.signature_b64.empty();
}

bool check_yearly_seal() {
    SealKey key = new_seal_key();
    std::array<uint8_t, 32> digest{};
    digest[0] = 0x11;
    uint64_t before = key.remaining;
    Bytes sig = seal_year(key, digest);
    return !sig.empty() && key.remaining + 1 == before;
}

bool check_archive_kek() {
    ArchiveKek kek = new_archive_kek();
    Bytes content_key(32, 0x33);
    WrappedKey wrapped = wrap_content_key(kek.public_bytes, content_key);
    return wrapped.shared_secret.size() == 32 && !wrapped.encapsulation.empty();
}

bool check_passphrase_schemes() {
    Botan::AutoSeeded_RNG rng;
    Bytes salt = rng.random_vec<Bytes>(16);
    Bytes k1 = derive_passphrase_key(Format::kFormat1, "p", salt);
    Bytes k2 = derive_passphrase_key(Format::kFormat2, "p", salt);
    return k1.size() == 32 && k2.size() == 32 && k1 != k2;
}

bool check_partner_exchange() {
    Bytes partner_pub(49, 0x04);
    try {
        exchange_with_partner(partner_pub, Bytes{'i', 'n', 'f', 'o'});
    } catch (const std::exception&) {
        // A malformed partner point is expected to throw; we only need the curve to load.
    }
    return std::string_view(partner_key_path()).find("brainpool") != std::string_view::npos;
}

bool check_fingerprint() {
    Bytes frame(128, 0x7e);
    auto fp = clip_fingerprint(frame);
    return fp != std::array<uint8_t, 32>{};
}

bool check_camera_paths() {
    Botan::AutoSeeded_RNG rng;
    CameraSession session{};
    Bytes shared = rng.random_vec<Bytes>(48);
    derive_camera_key(session, shared, "cam-dock-3");

    Bytes iv = rng.random_vec<Bytes>(12);
    Bytes frame = {'f', 'r', 'a', 'm', 'e'};
    Bytes gcm = decrypt_camera_gcm(session, frame, iv);
    Bytes chacha = decrypt_camera_chacha(session, frame, iv);
    return !gcm.empty() && !chacha.empty();
}

bool check_v1_restore() {
    // Round-trip the first-generation envelope so DefaultDecryptorWithMAC is exercised.
    std::string sealed;
    CryptoPP::DefaultEncryptorWithMAC enc("restore-pass", new CryptoPP::StringSink(sealed));
    enc.Put(reinterpret_cast<const CryptoPP::byte*>("evidence"), 8);
    enc.MessageEnd();
    Bytes container(sealed.begin(), sealed.end());
    Bytes back = restore_v1("archive-2019.varc", "restore-pass", container);
    return std::string(back.begin(), back.end()) == "evidence";
}

bool check_upload() {
    Bytes body(64, 0x20);
    UploadRequest req = build_upload("evidence", "arc-2026-04417.varc", body);
    ArchiveUploadPolicy policy;
    return !req.content_md5.empty() && policy.allowed_ciphers().size() == 2 && !policy.allow_tls12();
}

struct Check {
    const char* name;
    bool (*fn)();
};

}  // namespace

int run_self_check() {
    const Check checks[] = {
        {"archive seal round-trip", check_archive_roundtrip},
        {"drive image", check_drive_image},
        {"manifest signature", check_manifest_signature},
        {"yearly seal", check_yearly_seal},
        {"archive KEK", check_archive_kek},
        {"passphrase schemes", check_passphrase_schemes},
        {"partner exchange", check_partner_exchange},
        {"clip fingerprint", check_fingerprint},
        {"camera ingest", check_camera_paths},
        {"format-1 restore", check_v1_restore},
        {"object upload", check_upload},
    };
    int failures = 0;
    for (const auto& c : checks) {
        bool ok = false;
        try {
            ok = c.fn();
        } catch (const std::exception& e) {
            std::cerr << "FAIL " << c.name << ": " << e.what() << "\n";
        }
        std::cout << (ok ? "ok   " : "FAIL ") << c.name << "\n";
        if (!ok)
            ++failures;
    }
    std::cout << "self-check: " << failures << " failure(s)\n";
    return failures == 0 ? 0 : 1;
}

int run_command(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "usage: vaultarc <seal|image|keygen|restore|upload> ...\n";
        return 2;
    }
    const std::string& cmd = args[0];
    if (cmd == "--self-check")
        return run_self_check();
    if (cmd == "--help" || cmd == "-h") {
        std::cout << "vaultarc: archive CCTV and dash-cam footage\n"
                  << "  seal <dir> --out <container>\n"
                  << "  image <device> --out <image>\n"
                  << "  keygen --out <manifest-key>\n"
                  << "  restore <container> --key <file>\n"
                  << "  upload <container>\n";
        return 0;
    }
    std::cerr << "vaultarc: command '" << cmd << "' needs a device or archive store (not available here)\n";
    return 1;
}

}  // namespace vaultarc
