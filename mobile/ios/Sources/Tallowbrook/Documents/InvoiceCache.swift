import CryptoKit
import Foundation

/// Invoice PDFs the customer has opened, kept for offline viewing. Files are named by
/// content so two downloads of the same invoice share a file.
final class InvoiceCache {
    private let directory: URL
    private let fileManager = FileManager.default
    private let maximumFiles = 40

    init(directory: URL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("Invoices")) {
        self.directory = directory
        try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    @discardableResult
    func store(_ pdfData: Data) throws -> URL {
        let name = SHA512.hash(data: pdfData).prefix(16).map { String(format: "%02x", $0) }.joined()
        let url = directory.appendingPathComponent(name).appendingPathExtension("pdf")
        if !fileManager.fileExists(atPath: url.path) {
            try pdfData.write(to: url, options: [.atomic, .completeFileProtection])
        }
        try trim()
        return url
    }

    func removeAll() throws {
        for url in try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
            try fileManager.removeItem(at: url)
        }
    }

    /// Keeps the most recently written files.
    private func trim() throws {
        let files = try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.contentModificationDateKey])
        guard files.count > maximumFiles else { return }
        let sorted = try files.sorted {
            let lhs = try $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate ?? .distantPast
            let rhs = try $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate ?? .distantPast
            return lhs > rhs
        }
        for url in sorted.dropFirst(maximumFiles) {
            try fileManager.removeItem(at: url)
        }
    }
}
