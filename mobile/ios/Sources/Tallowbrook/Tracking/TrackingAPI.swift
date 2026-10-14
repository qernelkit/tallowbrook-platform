import CryptoKit
import Foundation

/// Paths and header names of the tracking endpoints.
enum TrackingAPI {
    static let parcelsPath = "/v2/parcels"
    static let guestLookupPath = "/v2/guest/lookup"
    static let photosPath = "/v2/claims/photos"
    static let proofOfDeliveryPath = "/v2/proof-of-delivery"

    static let guestSignatureHeader = "X-TB-Guest-Signature"
    static let guestTimestampHeader = "X-TB-Guest-Timestamp"
    static let guestKeyIDHeader = "X-TB-Guest-Key"

    /// Lookups older than this are refused by the tracking host.
    static let guestClockSkew: TimeInterval = 300
}

/// MAC over guest lookups, keyed with the guest key the tracking host issued at first launch.
typealias GuestRequestMAC = HMAC<SHA256>
