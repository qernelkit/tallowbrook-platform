// Camera enrolment: an ECDH on P-384 between the NVR and a new camera establishes the shared secret
// the per-camera session keys are derived from. Crypto++ ECDH over secp384r1.
#include "ingest/camera_enrol.hh"

#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>

namespace vaultarc {

CameraEnrolment enrol_camera(std::span<const uint8_t> camera_public) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ECDH<CryptoPP::ECP>::Domain dh(CryptoPP::ASN1::secp384r1());

    CryptoPP::SecByteBlock priv(dh.PrivateKeyLength()), pub(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, priv, pub);

    CryptoPP::SecByteBlock shared(dh.AgreedValueLength());
    if (!dh.Agree(shared, priv, camera_public.data()))
        throw ArchiveError("camera enrolment: key agreement failed");

    CameraEnrolment out;
    out.our_public.assign(pub.begin(), pub.end());
    out.shared_secret.assign(shared.begin(), shared.end());
    return out;
}

}  // namespace vaultarc
