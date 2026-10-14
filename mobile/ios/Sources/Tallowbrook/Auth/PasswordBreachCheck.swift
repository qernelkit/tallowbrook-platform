import CryptoKit
import Foundation

/// Warns at sign-up when a password appears in known breach corpora. Only the first five
/// hex characters of the hash leave the device (k-anonymity range lookup); the match on
/// the remaining characters happens here.
struct PasswordBreachCheck {
    static let rangeEndpoint = URL(string: "https://breach-range.tallowbrook.example/range/")!

    let session: URLSession

    enum Result: Equatable {
        case notFound
        case found(times: Int)
    }

    func check(_ password: String) async throws -> Result {
        let digest = Insecure.SHA1.hash(data: Data(password.utf8))
        let hex = digest.map { String(format: "%02X", $0) }.joined()
        let prefix = String(hex.prefix(5))
        let suffix = hex.dropFirst(5)

        var request = URLRequest(url: Self.rangeEndpoint.appendingPathComponent(prefix))
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200, let body = String(data: data, encoding: .utf8) else {
            throw URLError(.badServerResponse)
        }

        for line in body.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            guard parts.count == 2, parts[0].caseInsensitiveCompare(suffix) == .orderedSame else { continue }
            let times = Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0
            return times > 0 ? .found(times: times) : .notFound
        }
        return .notFound
    }
}
