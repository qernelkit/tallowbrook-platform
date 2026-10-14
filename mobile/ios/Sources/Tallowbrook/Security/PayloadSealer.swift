import CryptoKit
import Foundation

/// Authenticated encryption for the app's own formats (locker commands, address-book
/// exports). Output is nonce ‖ ciphertext ‖ tag, the layout the locker firmware and the
/// web importer expect.
enum PayloadSealer {
    static func seal(_ plaintext: Data, using key: SymmetricKey, authenticating context: Data = Data()) throws -> Data {
        try AES.GCM.seal(plaintext, using: key, authenticating: context).combined!
    }

    static func open(_ sealed: Data, using key: SymmetricKey, authenticating context: Data = Data()) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key, authenticating: context)
    }
}
