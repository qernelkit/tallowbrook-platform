import Foundation
import Security

/// Customs declarations for imports the customer pays duty on. The broker files them
/// with the customs authority and needs them signed by the importer, so each customer
/// has a signing key kept in this device's keychain.
struct CustomsDeclarationSigner {
    enum Failure: Error {
        case keyUnavailable(String)
        case signingFailed(String)
    }

    private static let tag = Data("example.tallowbrook.app.customs-declaration".utf8)

    /// Signs the canonical JSON of a declaration.
    func sign(_ declaration: Data) throws -> Data {
        let privateKey = try loadOrCreateKey()
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, KeyAlgorithms.customsDeclaration, declaration as CFData, &error) as Data?
        else {
            throw Failure.signingFailed(error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")
        }
        return signature
    }

    /// DER public key, registered with the broker the first time the customer declares.
    func publicKeyData() throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(try loadOrCreateKey()),
            let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            throw Failure.keyUnavailable("no public key")
        }
        return data
    }

    private func loadOrCreateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item {
            return (item as! SecKey)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 3072,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Self.tag,
            ] as [String: Any],
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Failure.keyUnavailable(error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")
        }
        return key
    }
}

/// What the broker needs for a duty declaration.
struct CustomsDeclaration: Codable {
    let trackingNumber: String
    let importerName: String
    let goodsDescription: String
    let originCountry: String
    let declaredValueMinor: Int
    let currency: String
    let declaredAt: Date

    func canonicalJSON() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(self)
    }
}
