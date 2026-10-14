import Foundation
import os

enum APIError: Error, Equatable {
    case unauthorized
    case notFound
    case server(status: Int)
    case decoding
}

struct SignedInSession: Decodable {
    let accessToken: String
    let refreshToken: String
    let customerName: String
    let expiresIn: Int
}

/// The customer API (api.tallowbrook.example) and the tracking host. Each request is a
/// small method here; views and view models never build URLs.
final class APIClient: Sendable {
    static let apiBase = URL(string: "https://api.tallowbrook.example")!
    static let trackBase = URL(string: "https://track.tallowbrook.example")!

    let session: URLSession
    private let decoder: JSONDecoder
    private let logger = Logger(subsystem: "example.tallowbrook.app", category: "api")

    init(delegate: PinnedSessionDelegate = PinnedSessionDelegate()) {
        let configuration = URLSessionConfiguration.default
        configuration.waitsForConnectivity = true
        configuration.timeoutIntervalForRequest = 20
        configuration.httpAdditionalHeaders = ["User-Agent": "Tallowbrook-iOS/\(BuildInfo.current.version)"]
        session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder
    }

    // MARK: Sign-in

    func authorize(email: String, password: String, codeChallenge: String) async throws -> String {
        var components = URLComponents(url: Self.apiBase.appendingPathComponent("/v2/auth/authorize"), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: "tallowbrook-ios"),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        var request = URLRequest(url: components.url!)
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(["email": email, "password": password])
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        struct Response: Decodable { let code: String }
        return try await send(request, as: Response.self).code
    }

    func exchange(code: String, codeVerifier: String, devicePublicKey: Data) async throws -> SignedInSession {
        var request = URLRequest(url: Self.apiBase.appendingPathComponent("/v2/auth/token"))
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode([
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": codeVerifier,
            "device_key": devicePublicKey.base64EncodedString(),
        ])
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try await send(request, as: SignedInSession.self)
    }

    // MARK: Parcels

    func parcels(accessToken: String) async throws -> [Parcel] {
        var request = URLRequest(url: Self.apiBase.appendingPathComponent(TrackingAPI.parcelsPath))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return try await send(request, as: [Parcel].self)
    }

    func events(for parcel: Parcel, accessToken: String) async throws -> [TrackingEvent] {
        let path = "\(TrackingAPI.parcelsPath)/\(parcel.trackingNumber)/events"
        var request = URLRequest(url: Self.trackBase.appendingPathComponent(path))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return try await send(request, as: [TrackingEvent].self)
    }

    func guestLookup(trackingNumber: String, postcode: String, signer: GuestTrackingSigner) async throws -> Parcel {
        var request = URLRequest(url: Self.trackBase.appendingPathComponent(TrackingAPI.guestLookupPath))
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(["tracking_number": trackingNumber, "postcode": postcode])
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        signer.sign(&request, trackingNumber: trackingNumber, postcode: postcode)
        return try await send(request, as: Parcel.self)
    }

    // MARK: Plumbing

    func send<T: Decodable>(_ request: URLRequest, as type: T.Type) async throws -> T {
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        switch status {
        case 200..<300:
            do {
                return try decoder.decode(T.self, from: data)
            } catch {
                logger.error("Could not decode \(T.self, privacy: .public): \(error.localizedDescription, privacy: .public)")
                throw APIError.decoding
            }
        case 401, 403:
            throw APIError.unauthorized
        case 404:
            throw APIError.notFound
        default:
            throw APIError.server(status: status)
        }
    }

    func sendWithoutBody(_ request: URLRequest) async throws {
        let (_, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw status == 401 ? APIError.unauthorized : APIError.server(status: status)
        }
    }
}
