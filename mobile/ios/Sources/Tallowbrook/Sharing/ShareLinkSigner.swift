import CryptoKit
import Foundation

/// "Share my delivery" links. Anyone with the link can follow the parcel until it
/// expires; the tracking host checks the signature against the key this device
/// registered, so links cannot be forged or extended.
struct ShareLinkSigner {
    static let base = URL(string: "https://track.tallowbrook.example/s/")!

    func link(for trackingNumber: String, validFor seconds: TimeInterval, now: Date = .now) throws -> URL {
        let expires = Int(now.addingTimeInterval(seconds).timeIntervalSince1970)
        let claims = "\(trackingNumber).\(expires)"
        let key = try deviceKey()
        let signature = try key.signature(for: Data(claims.utf8))
        var components = URLComponents(url: Self.base.appendingPathComponent(trackingNumber), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "e", value: String(expires)),
            URLQueryItem(name: "s", value: signature.base64URLEncodedString()),
        ]
        return components.url!
    }

    /// The public key the tracking host needs, registered once per device.
    func registrationKey() throws -> Data {
        try deviceKey().publicKey.rawRepresentation
    }

    private func deviceKey() throws -> Curve25519.Signing.PrivateKey {
        if let stored = try KeychainStore.load(account: KeychainStore.Account.shareLinkKey) {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: stored)
        }
        let key = Curve25519.Signing.PrivateKey()
        try KeychainStore.save(key.rawRepresentation, account: KeychainStore.Account.shareLinkKey)
        return key
    }
}
