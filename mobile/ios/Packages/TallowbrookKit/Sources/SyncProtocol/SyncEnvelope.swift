import Crypto
import Foundation

/// A sync message as the sync server stores and relays it. The server only routes
/// envelopes; the customer's devices are the only ones holding the session key.
///
/// The server builds this target on Linux too, which is why it imports Crypto
/// (swift-crypto) rather than CryptoKit.
public struct SyncEnvelope: Codable, Equatable, Sendable {
    public static let currentVersion = 2

    public let version: Int
    public let sessionID: Data
    public let senderDeviceID: String
    public let sequence: UInt64
    public let payload: Data

    /// Session key for one pairing of two devices, from the key-exchange secret.
    public static func channelKey(sharedSecret: SymmetricKey, sessionID: Data) -> SymmetricKey {
        let channelKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecret, salt: sessionID, info: Data("tallowbrook-sync-v2".utf8), outputByteCount: 32)
        return channelKey
    }

    public init(
        message: SyncMessage,
        senderDeviceID: String,
        sequence: UInt64,
        sessionID: Data,
        channelKey: SymmetricKey
    ) throws {
        let body = try JSONEncoder.sync.encode(message)
        let header = Self.associatedData(sessionID: sessionID, senderDeviceID: senderDeviceID, sequence: sequence)
        let box = try ChaChaPoly.seal(body, using: channelKey, authenticating: header)
        self.version = Self.currentVersion
        self.sessionID = sessionID
        self.senderDeviceID = senderDeviceID
        self.sequence = sequence
        self.payload = box.combined
    }

    public func message(channelKey: SymmetricKey) throws -> SyncMessage {
        guard version == Self.currentVersion else {
            throw SyncError.unsupportedVersion(version)
        }
        let header = Self.associatedData(sessionID: sessionID, senderDeviceID: senderDeviceID, sequence: sequence)
        let body = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: payload), using: channelKey, authenticating: header)
        return try JSONDecoder.sync.decode(SyncMessage.self, from: body)
    }

    /// Binds the routing fields to the payload so the server cannot replay a message
    /// under another sender or sequence number.
    private static func associatedData(sessionID: Data, senderDeviceID: String, sequence: UInt64) -> Data {
        var data = sessionID
        data.append(contentsOf: Array(senderDeviceID.utf8))
        withUnsafeBytes(of: sequence.bigEndian) { data.append(contentsOf: $0) }
        return data
    }
}

public enum SyncError: Error, Equatable {
    case unsupportedVersion(Int)
    case unknownSender(String)
    case outOfOrder(expected: UInt64, got: UInt64)
}
