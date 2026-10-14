import CryptoKit
import Foundation
import UIKit
import os

/// Damage-claim photos. Uploads go through a few background lanes so one slow photo
/// does not hold up the rest of a claim.
final class PhotoUploader: Sendable {
    static let uploadLanes = 3
    static let maximumDimension: CGFloat = 2048

    private let api: APIClient
    private let logger = Logger(subsystem: "example.tallowbrook.app", category: "uploads")

    init(api: APIClient) {
        self.api = api
    }

    func upload(_ image: UIImage, parcelID: String, claimID: String, accessToken: String) async throws {
        guard let jpeg = Self.resized(image).jpegData(compressionQuality: 0.8) else {
            throw URLError(.cannotDecodeContentData)
        }
        var request = URLRequest(url: APIClient.apiBase.appendingPathComponent("\(TrackingAPI.photosPath)/\(claimID)"))
        request.httpMethod = "POST"
        request.setValue("image/jpeg", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let lane = abs(parcelID.hashValue) % Self.uploadLanes
        let digest = SHA384.hash(data: jpeg)
        request.setValue("sha-384=:\(Data(digest).base64EncodedString()):", forHTTPHeaderField: "Repr-Digest")
        request.setValue(String(lane), forHTTPHeaderField: "X-Upload-Lane")

        let (_, response) = try await api.session.upload(for: request, from: jpeg)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            logger.error("Photo upload for claim \(claimID, privacy: .public) failed with \(status)")
            throw APIError.server(status: status)
        }
    }

    static func resized(_ image: UIImage) -> UIImage {
        let longest = max(image.size.width, image.size.height)
        guard longest > maximumDimension else { return image }
        let scale = maximumDimension / longest
        let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)
        return UIGraphicsImageRenderer(size: size).image { _ in
            image.draw(in: CGRect(origin: .zero, size: size))
        }
    }
}
