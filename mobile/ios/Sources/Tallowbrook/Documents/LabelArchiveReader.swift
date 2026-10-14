import CommonCrypto
import Foundation

/// Opens return-label archives from the label service. The service returns the archive
/// together with the key and IV for this download; the format predates our move to
/// CryptoKit and the label service still produces it.
struct LabelArchiveReader {
    enum Failure: Error, Equatable {
        case badKey
        case decodeFailed(Int32)
    }

    struct Download: Decodable {
        let archive: Data
        let key: Data
        let iv: Data
        let labelCount: Int
    }

    func open(_ download: Download) throws -> Data {
        guard !download.key.isEmpty, download.iv.count == 16 else { throw Failure.badKey }
        let archive = download.archive
        let key = download.key
        let iv = download.iv
        var output = Data(count: archive.count + kCCBlockSizeAES128)
        var moved = 0
        let status = output.withUnsafeMutableBytes { out in
            archive.withUnsafeBytes { input in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes.baseAddress,
                            key.count, ivBytes.baseAddress, input.baseAddress, archive.count, out.baseAddress, out.count, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw Failure.decodeFailed(status) }
        output.count = moved
        return output
    }

    /// Splits the opened archive into one PDF per label (length-prefixed entries).
    func labels(in archive: Data) -> [Data] {
        var labels: [Data] = []
        var index = archive.startIndex
        while index + 4 <= archive.endIndex {
            let length = archive[index..<index + 4].reduce(0) { $0 << 8 | Int($1) }
            let start = index + 4
            guard length > 0, start + length <= archive.endIndex else { break }
            labels.append(archive[start..<start + length])
            index = start + length
        }
        return labels
    }
}
