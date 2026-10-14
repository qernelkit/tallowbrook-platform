import CryptoKit
import Foundation
import os

/// Server-trust handling for track.tallowbrook.example. The tracking host is pinned to
/// our issuing CA's key, so a reissued leaf does not need an app release; the API host
/// is pinned in Info.plist instead (NSPinnedDomains).
nonisolated final class PinnedSessionDelegate: NSObject, URLSessionDelegate {
    static let pinnedHost = "track.tallowbrook.example"

    private static let pinnedKeyHashes: Set<String> = ["4kV6UdjvNuNQhyP4aZmVCfbojXgD6WM8r2zF7O6m0/s="]
    // swift-format-ignore
    private static let p256SPKIHeader: [UInt8] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]

    private let logger = Logger(subsystem: "example.tallowbrook.app", category: "network")

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let space = challenge.protectionSpace
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            space.host == Self.pinnedHost,
            let trust = space.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let host = space.host

        guard SecTrustEvaluateWithError(trust, nil),
            let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate]
        else {
            logger.error("Trust evaluation failed for \(host, privacy: .public)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        for certificate in chain {
            guard let key = SecCertificateCopyKey(certificate),
                let keyBytes = SecKeyCopyExternalRepresentation(key, nil) as Data?
            else { continue }
            let spkiHash = Data(SHA256.hash(data: Data(Self.p256SPKIHeader) + keyBytes)).base64EncodedString()
            if Self.pinnedKeyHashes.contains(spkiHash) {
                logger.notice("Certificate pin matched for \(host, privacy: .public)")
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
        }

        logger.fault("No pinned key in the chain for \(host, privacy: .public)")
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
