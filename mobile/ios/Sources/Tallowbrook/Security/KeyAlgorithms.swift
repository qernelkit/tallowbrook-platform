import Security

/// The SecKey algorithms the app uses, kept together so a server-side change is a
/// one-line change here.
enum KeyAlgorithms {
    /// Login challenges signed with the Secure Enclave device key.
    static let deviceBinding: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
    /// Customs declarations, checked by the customs broker.
    static let customsDeclaration: SecKeyAlgorithm = .rsaSignatureMessagePSSSHA256
    /// Wraps the per-payment data key to the processor's key.
    static let cardKeyWrap: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
}
