import CryptoKit
import Foundation

/// Signs lookups made without an account (tracking number plus postcode), so the
/// tracking host can rate-limit per install instead of per IP address.
struct GuestTrackingSigner {
    let keyID: String
    let guestKey: SymmetricKey

    func sign(_ request: inout URLRequest, trackingNumber: String, postcode: String, at date: Date = .now) {
        let timestamp = String(Int(date.timeIntervalSince1970))
        let normalizedPostcode = postcode.uppercased().filter { !$0.isWhitespace }
        let canonicalRequest = [
            request.httpMethod ?? "GET",
            TrackingAPI.guestLookupPath,
            trackingNumber.uppercased(),
            normalizedPostcode,
            timestamp,
        ].joined(separator: "\n")
        let mac = GuestRequestMAC.authenticationCode(for: Data(canonicalRequest.utf8), using: guestKey)
        request.setValue(Data(mac).base64EncodedString(), forHTTPHeaderField: TrackingAPI.guestSignatureHeader)
        request.setValue(timestamp, forHTTPHeaderField: TrackingAPI.guestTimestampHeader)
        request.setValue(keyID, forHTTPHeaderField: TrackingAPI.guestKeyIDHeader)
    }
}

extension GuestTrackingSigner {
    /// The signer for this install, if the tracking host has issued a guest key yet.
    static func current() throws -> GuestTrackingSigner? {
        guard let stored = try KeychainStore.load(account: KeychainStore.Account.guestKey),
            let separator = stored.firstIndex(of: 0x3A)
        else { return nil }
        let keyID = String(decoding: stored[stored.startIndex..<separator], as: UTF8.self)
        let keyBytes = stored[stored.index(after: separator)...]
        return GuestTrackingSigner(keyID: keyID, guestKey: SymmetricKey(data: keyBytes))
    }
}
