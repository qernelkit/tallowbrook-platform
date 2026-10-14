import CryptoKit
import Foundation
import SyncProtocol

/// Signs the manifest each device uploads after applying sync messages, so the sync
/// server cannot hand a device a manifest that another device never sent. Devices on
/// systems before iOS 26 upload unsigned manifests, which the server still accepts.
struct SyncManifestSigner {
    struct Signed: Encodable {
        let manifest: SyncManifest
        let signature: Data?
    }

    func sign(_ manifest: SyncManifest) throws -> Signed {
        guard #available(iOS 26.0, *) else {
            return Signed(manifest: manifest, signature: nil)
        }
        let signature = try manifestKey().signature(for: manifest.canonicalBytes())
        return Signed(manifest: manifest, signature: signature)
    }

    /// Registered with the sync server once, when the device first signs a manifest.
    @available(iOS 26.0, *)
    func publicKey() throws -> Data {
        try manifestKey().publicKey.rawRepresentation
    }

    @available(iOS 26.0, *)
    private func manifestKey() throws -> MLDSA65.PrivateKey {
        if let stored = try KeychainStore.load(account: KeychainStore.Account.syncManifestKey) {
            return try MLDSA65.PrivateKey(integrityCheckedRepresentation: stored)
        }
        let key = try MLDSA65.PrivateKey()
        try KeychainStore.save(key.integrityCheckedRepresentation, account: KeychainStore.Account.syncManifestKey)
        return key
    }
}
