import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Saved addresses exported to a file the customer can keep, or import on the web
/// account page. The file is protected with a password the customer chooses.
struct AddressBookExport {
    enum Failure: Error, Equatable {
        case passwordTooShort
        case derivationFailed(Int32)
        case noEntropy
    }

    static let fileExtension = "tbaddresses"
    private static let magic = "TBADDR1"
    private static let exportRounds: UInt32 = 310_000

    func export(_ addresses: [Address], password: String) throws -> Data {
        guard password.count >= 8 else { throw Failure.passwordTooShort }
        let salt = try Self.randomBytes(count: 16)
        let key = try deriveKey(password: password, salt: salt)
        let csv = (["label,lines,postcode,country,safe_place"] + addresses.map(\.csvRow)).joined(separator: "\n")
        let sealed = try PayloadSealer.seal(Data(csv.utf8), using: SymmetricKey(data: key), authenticating: Data(Self.magic.utf8))
        var file = Data(Self.magic.utf8)
        file.append(salt)
        file.append(sealed)
        return file
    }

    func suggestedFileName(on date: Date = .now) -> String {
        "Tallowbrook addresses \(date.formatted(.iso8601.year().month().day())).\(Self.fileExtension)"
    }

    private func deriveKey(password: String, salt: Data) throws -> Data {
        var key = Data(count: 32)
        let passwordLength = password.utf8.count
        let status = key.withUnsafeMutableBytes { keyBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, passwordLength,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), Self.exportRounds,
                    keyBytes.bindMemory(to: UInt8.self).baseAddress, keyBytes.count
                )
            }
        }
        guard status == kCCSuccess else { throw Failure.derivationFailed(status) }
        return key
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { throw Failure.noEntropy }
        return Data(bytes)
    }
}
