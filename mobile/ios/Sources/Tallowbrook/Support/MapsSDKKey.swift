import Foundation

/// The maps SDK key ships scrambled so it does not appear in a plain `strings` dump of the
/// binary. The vendor also restricts the key to our bundle identifier, which is what it
/// is scrambled with.
enum MapsSDKKey {
    // swift-format-ignore
    private static let scrambled: [UInt8] = [0x11, 0x1A, 0x0C, 0x40, 0x19, 0x03, 0x16, 0x03, 0x4D, 0x30, 0x16, 0x27, 0x5B, 0x01, 0x3A, 0x00, 0x5D, 0x23, 0x08, 0x66, 0x56, 0x00, 0x27, 0x01, 0x4D, 0x2F, 0x0B, 0x24, 0x54, 0x1C, 0x64, 0x16]

    static func value(bundleIdentifier: String? = Bundle.main.bundleIdentifier) -> String? {
        guard let bundleIdentifier, !bundleIdentifier.isEmpty else { return nil }
        let mask = Array(bundleIdentifier.utf8)
        let plain = scrambled.enumerated().map { $0.element ^ mask[$0.offset % mask.count] }
        return String(bytes: plain, encoding: .utf8)
    }
}
