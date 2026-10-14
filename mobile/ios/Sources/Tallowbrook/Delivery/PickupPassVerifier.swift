import CryptoKit
import Foundation

/// A pickup pass: what the customer shows at a depot or locker bank to collect a parcel.
struct PickupPass: Decodable, Equatable {
    let trackingNumber: String
    let collectionPoint: String
    let holderName: String
    let validUntil: Date
}

/// Pickup passes arrive as compact JWS tokens from the parcel service. The app checks
/// them before showing the QR code, so a pass that expired or was edited is never shown
/// at the counter, even with no signal in the depot.
struct PickupPassVerifier {
    enum Failure: Error, Equatable {
        case malformed
        case unknownKey
        case badSignature
        case expired
    }

    static let passKeyID = "pickup-2026"

    static let passSigningKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQKomyBVpBNpmoaISQ8Cu2ZbQRyv5
        dRaF1lQZvjYI6/jb0HlcAO1n5Zp1VchZMKdzA3GYtzjiuKersi0RmnY6Uw==
        -----END PUBLIC KEY-----
        """

    private struct Header: Decodable {
        let kid: String
    }

    func verify(_ token: String, now: Date = .now) throws -> PickupPass {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
            let headerData = Data(base64URLEncoded: parts[0]),
            let payloadData = Data(base64URLEncoded: parts[1]),
            let signatureBytes = Data(base64URLEncoded: parts[2])
        else { throw Failure.malformed }

        let header = try JSONDecoder().decode(Header.self, from: headerData)
        guard header.kid == Self.passKeyID else { throw Failure.unknownKey }

        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        let key = try P256.Signing.PublicKey(pemRepresentation: Self.passSigningKeyPEM)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
        guard key.isValidSignature(signature, for: signingInput) else { throw Failure.badSignature }

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .secondsSince1970
        let pass = try decoder.decode(PickupPass.self, from: payloadData)
        guard pass.validUntil > now else { throw Failure.expired }
        return pass
    }
}
