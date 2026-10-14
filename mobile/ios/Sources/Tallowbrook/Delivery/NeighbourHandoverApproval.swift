import CryptoKit
import Foundation
import Security

/// When the courier finds nobody home, the app asks the customer whether the parcel
/// may go to a neighbour. The answer is signed with a Secure Enclave key behind Face ID,
/// so the courier app can show "approved by the recipient" with confidence.
struct NeighbourHandoverApproval {
    struct Request: Decodable {
        let handoverID: String
        let trackingNumber: String
        let neighbourAddress: String
        let requestedAt: Date
    }

    enum Failure: Error {
        case accessControl
    }

    func approve(_ request: Request, approvedAt: Date = .now) throws -> Data {
        let statement = [
            "handover",
            request.handoverID,
            request.trackingNumber,
            request.neighbourAddress,
            String(Int(approvedAt.timeIntervalSince1970)),
        ].joined(separator: "|")
        let key = try approvalKey()
        return try key.signature(for: Data(statement.utf8)).derRepresentation
    }

    /// The public key the delivery API checks approvals against.
    func registrationKey() throws -> Data {
        try approvalKey().publicKey.x963Representation
    }

    private func approvalKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        if let stored = try KeychainStore.load(account: KeychainStore.Account.neighbourApprovalKey) {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored)
        }
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error)
        else {
            throw Failure.accessControl
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try KeychainStore.save(key.dataRepresentation, account: KeychainStore.Account.neighbourApprovalKey)
        return key
    }
}
