import CryptoKit
import Foundation
import Security
import SyncProtocol

/// What another of the customer's devices publishes through the sync server.
struct PeerDevice: Decodable, Equatable {
    let deviceID: String
    let name: String
    /// Present on devices running iOS 26 or later.
    let kemKey: Data?
    /// Present on every device.
    let classicalKey: Data
}

/// A sync session with one peer: the channel key, and what the peer needs to derive it.
struct SyncSession {
    enum Handshake: Equatable {
        case encapsulated(Data)
        case classical
    }

    let sessionID: Data
    let channelKey: SymmetricKey
    let handshake: Handshake
}

/// Agrees a channel key with another of the customer's devices. Devices on iOS 26 and
/// later use key encapsulation when the peer supports it; otherwise both sides use their
/// long-term Curve25519 keys, and the session ID keeps each session's key distinct.
struct SyncKeyExchange {
    enum Failure: Error {
        case noEntropy
        case kemUnavailable
    }

    func startSession(with peer: PeerDevice) throws -> SyncSession {
        let sessionID = try Self.newSessionID()
        if #available(iOS 26.0, *), let kemKey = peer.kemKey {
            let encapsulation = try SyncKEM.PublicKey(rawRepresentation: kemKey).encapsulate()
            let channelKey = SyncEnvelope.channelKey(sharedSecret: encapsulation.sharedSecret, sessionID: sessionID)
            return SyncSession(sessionID: sessionID, channelKey: channelKey, handshake: .encapsulated(encapsulation.encapsulated))
        } else {
            let channelKey = try classicalChannelKey(with: peer, sessionID: sessionID)
            return SyncSession(sessionID: sessionID, channelKey: channelKey, handshake: .classical)
        }
    }

    /// The responder's side of `startSession`.
    func acceptSession(from peer: PeerDevice, sessionID: Data, handshake: SyncSession.Handshake) throws -> SymmetricKey {
        switch handshake {
        case .encapsulated(let encapsulated):
            guard #available(iOS 26.0, *) else { throw Failure.kemUnavailable }
            let shared = try kemPrivateKey().decapsulate(encapsulated)
            return SyncEnvelope.channelKey(sharedSecret: shared, sessionID: sessionID)
        case .classical:
            return try classicalChannelKey(with: peer, sessionID: sessionID)
        }
    }

    /// The public keys this device publishes for its peers.
    func publishedKeys() throws -> (kemKey: Data?, classicalKey: Data) {
        let classical = try classicalPrivateKey().publicKey.rawRepresentation
        if #available(iOS 26.0, *) {
            return (try kemPrivateKey().publicKey.rawRepresentation, classical)
        }
        return (nil, classical)
    }

    private func classicalChannelKey(with peer: PeerDevice, sessionID: Data) throws -> SymmetricKey {
        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.classicalKey)
        let shared = try classicalPrivateKey().sharedSecretFromKeyAgreement(with: peerKey)
        let secret = shared.withUnsafeBytes { SymmetricKey(data: $0) }
        return SyncEnvelope.channelKey(sharedSecret: secret, sessionID: sessionID)
    }

    private func classicalPrivateKey() throws -> Curve25519.KeyAgreement.PrivateKey {
        if let stored = try KeychainStore.load(account: KeychainStore.Account.syncAgreementKey) {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: stored)
        }
        let ours = Curve25519.KeyAgreement.PrivateKey()
        try KeychainStore.save(ours.rawRepresentation, account: KeychainStore.Account.syncAgreementKey)
        return ours
    }

    @available(iOS 26.0, *)
    private func kemPrivateKey() throws -> SyncKEM.PrivateKey {
        if let stored = try KeychainStore.load(account: KeychainStore.Account.syncKEMKey) {
            return try SyncKEM.PrivateKey(integrityCheckedRepresentation: stored)
        }
        let key = try SyncKEM.PrivateKey()
        try KeychainStore.save(key.integrityCheckedRepresentation, account: KeychainStore.Account.syncKEMKey)
        return key
    }

    private static func newSessionID() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw Failure.noEntropy
        }
        return Data(bytes)
    }
}
