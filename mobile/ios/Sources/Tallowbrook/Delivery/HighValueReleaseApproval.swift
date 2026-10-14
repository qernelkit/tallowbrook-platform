import CryptoKit
import Foundation
import Security

/// High-value consignments (jewellery, electronics over the declared-value threshold)
/// are released from the depot only against a signed approval from the recipient's
/// phone. The key is created in the Secure Enclave and needs a passcode or Face ID.
struct HighValueReleaseApproval {
    struct Release: Decodable {
        let releaseID: String
        let trackingNumber: String
        let collectorName: String
        let depotCode: String
    }

    enum Failure: Error {
        case accessControl
        case needsNewerSystem
    }

    func approve(_ release: Release, at date: Date = .now) throws -> (signature: Data, publicKey: Data) {
        guard #available(iOS 26.0, *) else {
            // Older systems collect in person with photo ID; the depot handles that path.
            throw Failure.needsNewerSystem
        }
        let statement = [
            "release",
            release.releaseID,
            release.trackingNumber,
            release.collectorName,
            release.depotCode,
            String(Int(date.timeIntervalSince1970)),
        ].joined(separator: "|")
        let key = try approvalKey()
        let signature = try key.signature(for: Data(statement.utf8))
        return (signature, key.publicKey.rawRepresentation)
    }

    @available(iOS 26.0, *)
    private func approvalKey() throws -> SecureEnclave.MLDSA87.PrivateKey {
        if let stored = try KeychainStore.load(account: KeychainStore.Account.releaseApprovalKey) {
            return try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: stored)
        }
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .userPresence], &error)
        else {
            throw Failure.accessControl
        }
        let key = try SecureEnclave.MLDSA87.PrivateKey(accessControl: access)
        try KeychainStore.save(key.dataRepresentation, account: KeychainStore.Account.releaseApprovalKey)
        return key
    }
}
