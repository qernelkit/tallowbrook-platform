import CryptoKit
import Foundation
import Security

struct CardDetails: Codable {
    let number: String
    let expiryMonth: Int
    let expiryYear: Int
    let securityCode: String
    let holderName: String
}

/// Card details on their way to the payment processor. Our API only relays the
/// result: the processor holds the key that opens it.
struct CardEnvelope {
    enum Failure: Error {
        case badProcessorKey
        case wrapFailed(String)
    }

    private struct Payload: Encodable {
        let keyID: String
        let wrappedKey: Data
        let box: Data
    }

    /// From GET /v2/payments/processor-key: key id and DER (PKCS #1) public key.
    let processorKeyID: String
    let processorKeyData: Data

    func seal(_ card: CardDetails) throws -> String {
        let cardJSON = try JSONEncoder().encode(card)
        let dataKey = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal(cardJSON, using: dataKey)
        let wrappedKey = try wrap(dataKey)
        let envelopeData = try JSONEncoder().encode(Payload(keyID: processorKeyID, wrappedKey: wrappedKey, box: sealed.combined!))
        let body = envelopeData.base64EncodedString()
        return body
    }

    private func wrap(_ dataKey: SymmetricKey) throws -> Data {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let processorKey = SecKeyCreateWithData(processorKeyData as CFData, attributes as CFDictionary, &error) else {
            throw Failure.badProcessorKey
        }
        let rawKey = dataKey.withUnsafeBytes { Data($0) }
        guard let wrapped = SecKeyCreateEncryptedData(processorKey, KeyAlgorithms.cardKeyWrap, rawKey as CFData, &error) as Data? else {
            throw Failure.wrapFailed(error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")
        }
        return wrapped
    }
}
