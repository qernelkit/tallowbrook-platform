import Foundation
import Security

/// Generic-password items in the app's keychain service. Every secret the app keeps
/// (refresh token, guest key, share-link key, sync keys, cache keys) goes through here.
enum KeychainStore {
    enum Account {
        static let refreshToken = "auth.refresh-token"
        static let guestKey = "tracking.guest-key"
        static let shareLinkKey = "sharing.link-key"
        static let syncAgreementKey = "sync.agreement-key"
        static let syncKEMKey = "sync.kem-key"
        static let syncManifestKey = "sync.manifest-key"
        static let historyCacheKey = "cache.history-key"
        static let photoCacheKey = "cache.photo-key"
        static let neighbourApprovalKey = "delivery.neighbour-approval-key"
        static let releaseApprovalKey = "delivery.release-approval-key"
        static let loyaltyFeedKey = "loyalty.feed-key"
        static let favouritesV1Key = "favourites.v1-key"
    }

    struct Failure: Error, CustomStringConvertible {
        let status: OSStatus
        let operation: String

        var description: String {
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
            return "\(operation) failed (\(status)): \(message)"
        }
    }

    private static let service = "example.tallowbrook.app"

    static func save(_ data: Data, account: String) throws {
        try delete(account: account)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Failure(status: status, operation: "save \(account)")
        }
    }

    static func load(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw Failure(status: status, operation: "load \(account)")
        }
    }

    static func delete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure(status: status, operation: "delete \(account)")
        }
    }

    /// Removes everything on sign-out.
    static func deleteAll() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure(status: status, operation: "delete all")
        }
    }
}
