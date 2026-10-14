import CryptoKit
import Foundation

/// Proof-of-delivery photos downloaded for the parcel history. They show the customer's
/// front door, so they are encrypted on disk with a key that stays in the keychain.
final class ProofOfDeliveryCache {
    private let directory: URL
    private let fileManager = FileManager.default

    init(directory: URL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("ProofOfDelivery"))
    {
        self.directory = directory
        try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    func store(_ photo: Data, photoID: String) throws {
        let cacheKey = try Self.cacheKey()
        let box = try ChaChaPoly.seal(photo, using: cacheKey)
        try box.combined.write(to: fileURL(for: photoID), options: [.atomic, .completeFileProtection])
    }

    func photo(photoID: String) throws -> Data? {
        let url = fileURL(for: photoID)
        guard fileManager.fileExists(atPath: url.path) else { return nil }
        let cacheKey = try Self.cacheKey()
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: Data(contentsOf: url)), using: cacheKey)
    }

    func removeAll() throws {
        for url in try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
            try fileManager.removeItem(at: url)
        }
    }

    private func fileURL(for photoID: String) -> URL {
        let safe = photoID.filter { $0.isLetter || $0.isNumber || $0 == "-" }
        return directory.appendingPathComponent(safe).appendingPathExtension("pod")
    }

    private static func cacheKey() throws -> SymmetricKey {
        if let stored = try KeychainStore.load(account: KeychainStore.Account.photoCacheKey) {
            return SymmetricKey(data: stored)
        }
        let fresh = SymmetricKey(size: .bits256)
        try KeychainStore.save(fresh.withUnsafeBytes { Data($0) }, account: KeychainStore.Account.photoCacheKey)
        return fresh
    }
}
