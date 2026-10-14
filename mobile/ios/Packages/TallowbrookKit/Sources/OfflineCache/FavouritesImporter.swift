import CryptoSwift
import Foundation

/// A favourite address from the 2017 app, before addresses moved to SavedAddress.
public struct FavouriteAddress: Equatable, Sendable {
    public let label: String
    public let lines: [String]
    public let postcode: String
}

public enum FavouritesImportError: Error, Equatable {
    case unreadable
    case malformedLine(Int)
}

/// One-time import of `favourites.dat`, written by the 2017 app. Runs once after an
/// upgrade, then the file is deleted.
public struct FavouritesImporter: Sendable {
    public static let fileName = "favourites.dat"

    public init() {}

    /// `v1Key` is read by the caller from the keychain item the 2017 app created.
    public func importFavourites(from url: URL, v1Key: [UInt8]) throws -> [FavouriteAddress] {
        let data = try Data(contentsOf: url)
        let cipher = try Blowfish(key: v1Key, blockMode: ECB(), padding: .pkcs7)
        let plain = try cipher.decrypt(Array(data))
        guard let text = String(bytes: plain, encoding: .utf8) else {
            throw FavouritesImportError.unreadable
        }
        return try parse(text)
    }

    /// One favourite per line: `label|line 1|line 2|…|postcode`.
    func parse(_ text: String) throws -> [FavouriteAddress] {
        var result: [FavouriteAddress] = []
        for (number, line) in text.split(whereSeparator: \.isNewline).enumerated() {
            let fields = line.split(separator: "|", omittingEmptySubsequences: false).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            guard fields.count >= 3, !fields[0].isEmpty, let postcode = fields.last, !postcode.isEmpty else {
                throw FavouritesImportError.malformedLine(number + 1)
            }
            let lines = fields.dropFirst().dropLast().filter { !$0.isEmpty }
            result.append(FavouriteAddress(label: fields[0], lines: Array(lines), postcode: postcode))
        }
        return result
    }
}
