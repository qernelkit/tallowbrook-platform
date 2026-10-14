import Foundation

struct Address: Codable, Hashable, Identifiable {
    var id: UUID = UUID()
    var label: String
    var lines: [String]
    var postcode: String
    var countryCode: String
    var safePlaceNote: String?

    var singleLine: String {
        (lines + [postcode]).filter { !$0.isEmpty }.joined(separator: ", ")
    }

    /// UK-style postcodes are validated loosely; the delivery API has the final say.
    var hasPlausiblePostcode: Bool {
        let trimmed = postcode.trimmingCharacters(in: .whitespaces)
        guard countryCode == "GB" else { return !trimmed.isEmpty }
        let pattern = /^[A-Za-z]{1,2}[0-9][A-Za-z0-9]? ?[0-9][A-Za-z]{2}$/
        return trimmed.wholeMatch(of: pattern) != nil
    }

    var csvRow: String {
        [label, lines.joined(separator: " / "), postcode, countryCode, safePlaceNote ?? ""]
            .map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }
            .joined(separator: ",")
    }
}
