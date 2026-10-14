import CryptoKit
import Foundation

/// The courier assigned to a delivery, as the delivery API returns it.
struct AssignedCourier: Decodable {
    let id: String
    let firstName: String
    let publicKey: Data
}

struct SealedGateCode: Encodable {
    let courierID: String
    let encapsulatedKey: Data
    let ciphertext: Data
}

/// Building and gate codes go only to the courier who delivers: sealed on the phone to
/// the courier device's key, opened by the courier app on the day. Our servers relay
/// the sealed code and never see it.
@available(iOS 26.0, *)
struct GateCodeSealer {
    func seal(gateCode: String, for courier: AssignedCourier) throws -> SealedGateCode {
        let courierKey = try XWingMLKEM768X25519.PublicKey(rawRepresentation: courier.publicKey)
        var sender = try HPKE.Sender(
            recipientKey: courierKey, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256, info: Data("gate-code".utf8))
        let ciphertext = try sender.seal(Data(gateCode.utf8))
        return SealedGateCode(courierID: courier.id, encapsulatedKey: sender.encapsulatedKey, ciphertext: ciphertext)
    }
}
