import Foundation
import UniformTypeIdentifiers

/// Checks what a customer is about to send to support chat. Pasted text that looks like
/// a key or a certificate is refused: agents never need it, and people paste the wrong
/// clipboard more often than you would think.
struct AttachmentScrubber {
    enum Verdict: Equatable {
        case allowed
        case refused(reason: String)
    }

    static let maximumBytes = 8 * 1024 * 1024
    static let allowedTypes: [UTType] = [.jpeg, .png, .heic, .pdf, .plainText]

    func check(text: String) -> Verdict {
        if text.contains("-----BEGIN") {
            return .refused(reason: "This looks like a security file, so we haven't sent it.")
        }
        if text.count > 4000 {
            return .refused(reason: "That message is too long. Try attaching it as a file.")
        }
        return .allowed
    }

    func check(fileAt url: URL) -> Verdict {
        guard let type = UTType(filenameExtension: url.pathExtension),
            Self.allowedTypes.contains(where: { type.conforms(to: $0) })
        else {
            return .refused(reason: "Support chat accepts photos, PDFs and text files.")
        }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= Self.maximumBytes else {
            return .refused(reason: "Files can be up to 8 MB.")
        }
        if type.conforms(to: .plainText), let text = try? String(contentsOf: url, encoding: .utf8) {
            return check(text: text)
        }
        return .allowed
    }
}
