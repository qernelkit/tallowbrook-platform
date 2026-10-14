import CryptoSwift
import Foundation

/// A parcel as the parcel list shows it while the app is offline.
public struct CachedParcel: Codable, Equatable, Sendable {
    public let trackingNumber: String
    public let nickname: String?
    public let status: String
    public let lastEvent: String?
    public let lastEventAt: Date?
    public let estimatedDelivery: Date?

    public init(
        trackingNumber: String,
        nickname: String?,
        status: String,
        lastEvent: String?,
        lastEventAt: Date?,
        estimatedDelivery: Date?
    ) {
        self.trackingNumber = trackingNumber
        self.nickname = nickname
        self.status = status
        self.lastEvent = lastEvent
        self.lastEventAt = lastEventAt
        self.estimatedDelivery = estimatedDelivery
    }
}

public enum TrackingHistoryCacheError: Error, Equatable {
    case badHeader
    case staleFormat(Int)
}

/// The tracking-history file behind the offline parcel list. It has been encrypted
/// since the first offline-mode release; the key lives in the keychain and is passed in.
public final class TrackingHistoryCache: @unchecked Sendable {
    private struct Header: Codable {
        let format: Int
        let iv: String
        let savedAt: Date
    }

    private static let format = 3
    private static let ivCharacters = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")

    private let fileURL: URL
    private let cacheKey: String
    private let lock = NSLock()

    /// `cacheKey` is the 32-character key stored in the keychain at first launch.
    public init(directory: URL, cacheKey: String) {
        self.fileURL = directory.appendingPathComponent("tracking-history.bin")
        self.cacheKey = cacheKey
    }

    public func save(_ parcels: [CachedParcel]) throws {
        lock.lock()
        defer { lock.unlock() }

        let header = Header(format: Self.format, iv: Self.makeIV(), savedAt: .now)
        let body = try JSONEncoder().encode(parcels)
        let sealed = try cipher(iv: header.iv).encrypt(Array(body))

        var file = try JSONEncoder().encode(header)
        file.append(0x0A)
        file.append(contentsOf: sealed)
        try file.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    public func load() throws -> [CachedParcel] {
        lock.lock()
        defer { lock.unlock() }

        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        let file = try Data(contentsOf: fileURL)
        guard let newline = file.firstIndex(of: 0x0A) else { throw TrackingHistoryCacheError.badHeader }
        let header = try JSONDecoder().decode(Header.self, from: file[file.startIndex..<newline])
        guard header.format == Self.format else { throw TrackingHistoryCacheError.staleFormat(header.format) }

        let sealed = file[file.index(after: newline)...]
        let body = try cipher(iv: header.iv).decrypt(Array(sealed))
        return try JSONDecoder().decode([CachedParcel].self, from: Data(body))
    }

    public func clear() throws {
        lock.lock()
        defer { lock.unlock() }
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
    }

    private func cipher(iv: String) throws -> AES {
        try AES(key: cacheKey, iv: iv)
    }

    /// Sixteen characters, one per byte of the block.
    private static func makeIV() -> String {
        var generator = SystemRandomNumberGenerator()
        return String((0..<16).map { _ in ivCharacters.randomElement(using: &generator)! })
    }
}
