import Foundation
import Security
import os

/// A key that never leaves this device. Sign-in registers its public half; every token
/// refresh answers a server challenge with it, so a copied refresh token is useless on
/// another phone.
enum DeviceBindingKey {
    enum Failure: Error {
        case unavailable(String)
        case unsupported
    }

    private static let tag = Data("example.tallowbrook.app.device-binding".utf8)
    private static let logger = Logger(subsystem: "example.tallowbrook.app", category: "auth")

    /// The public key in X9.63 form, sent once when the device registers.
    static func publicKeyData() throws -> Data {
        let key = try loadOrCreate()
        guard let publicKey = SecKeyCopyPublicKey(key),
            let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            throw Failure.unavailable("no public key")
        }
        return data
    }

    /// Answers a refresh challenge. Prompts for Face ID or Touch ID.
    static func signChallenge(_ challenge: Data) throws -> Data {
        let key = try loadOrCreate()
        guard SecKeyIsAlgorithmSupported(key, .sign, KeyAlgorithms.deviceBinding) else {
            throw Failure.unsupported
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, KeyAlgorithms.deviceBinding, challenge as CFData, &error) as Data? else {
            throw error?.takeRetainedValue() ?? Failure.unavailable("signing failed")
        }
        return signature
    }

    /// Forgets the key, for example after the customer signs out of every device.
    static func reset() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            logger.error("Could not remove the device key: \(status)")
        }
    }

    private static func loadOrCreate() throws -> SecKey {
        if let existing = try lookup() {
            return existing
        }
        logger.info("Creating the device key")
        return try create()
    }

    private static func lookup() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw Failure.unavailable("lookup failed (\(status))")
        }
    }

    private static func create() throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error)
        else {
            throw error?.takeRetainedValue() ?? Failure.unavailable("access control")
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? Failure.unavailable("key creation")
        }
        return key
    }
}
