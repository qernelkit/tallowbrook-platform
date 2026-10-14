import CryptoKit
import Foundation
import UniformTypeIdentifiers

/// Uploads scanned invoices and receipts the customs broker asks for. The broker's
/// upload endpoint rejects a body without a Content-MD5 header (RFC 1864).
struct CustomsAttachmentUploader {
    static let endpoint = URL(string: "https://customs.tallowbrook.example/v1/attachments")!
    static let maximumSize = 10 * 1024 * 1024

    enum Failure: Error, Equatable {
        case tooLarge
        case unsupportedType
        case rejected(status: Int)
    }

    let session: URLSession

    func upload(fileAt url: URL, declarationID: String, accessToken: String) async throws {
        let fileData = try Data(contentsOf: url)
        guard fileData.count <= Self.maximumSize else { throw Failure.tooLarge }
        guard let type = UTType(filenameExtension: url.pathExtension),
            type.conforms(to: .pdf) || type.conforms(to: .image)
        else { throw Failure.unsupportedType }

        let checksum = Insecure.MD5.hash(data: fileData)
        var request = URLRequest(url: Self.endpoint.appendingPathComponent(declarationID))
        request.httpMethod = "PUT"
        request.setValue(type.preferredMIMEType ?? "application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue(Data(checksum).base64EncodedString(), forHTTPHeaderField: "Content-MD5")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(url.lastPathComponent, forHTTPHeaderField: "X-File-Name")

        let (_, response) = try await session.upload(for: request, from: fileData)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else { throw Failure.rejected(status: status) }
    }
}
