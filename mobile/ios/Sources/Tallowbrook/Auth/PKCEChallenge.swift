import CryptoKit
import Foundation
import Security

/// Proof key for the sign-in redirect (RFC 7636). A new one for every sign-in attempt.
struct PKCEChallenge: Equatable {
    let verifier: String
    let challenge: String

    init() {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "system random source unavailable")
        verifier = Data(bytes).base64URLEncodedString()
        let digest = SHA256.hash(data: Data(verifier.utf8))
        challenge = Data(digest).base64URLEncodedString()
    }
}
