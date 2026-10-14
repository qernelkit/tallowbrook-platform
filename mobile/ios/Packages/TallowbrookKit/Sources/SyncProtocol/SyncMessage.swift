import Foundation

/// A change one of the customer's devices publishes to the others.
public enum SyncMessage: Codable, Equatable, Sendable {
    case addressUpserted(SavedAddress)
    case addressRemoved(id: UUID)
    case preferencesChanged(DeliveryPreferences)
    case manifest(SyncManifest)
}

/// An address the customer saved in the app ("Home", "Office", a neighbour).
public struct SavedAddress: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public var label: String
    public var lines: [String]
    public var postcode: String
    public var countryCode: String
    public var safePlaceNote: String?
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        label: String,
        lines: [String],
        postcode: String,
        countryCode: String,
        safePlaceNote: String? = nil,
        updatedAt: Date = .now
    ) {
        self.id = id
        self.label = label
        self.lines = lines
        self.postcode = postcode
        self.countryCode = countryCode
        self.safePlaceNote = safePlaceNote
        self.updatedAt = updatedAt
    }
}

/// Delivery preferences that follow the customer between devices.
public struct DeliveryPreferences: Codable, Equatable, Sendable {
    public enum Fallback: String, Codable, Sendable {
        case neighbour
        case safePlace
        case depot
    }

    public var fallback: Fallback
    public var notifyOnOutForDelivery: Bool
    public var notifyOnDelay: Bool
    public var quietHoursStart: Int?
    public var quietHoursEnd: Int?

    public init(
        fallback: Fallback = .neighbour,
        notifyOnOutForDelivery: Bool = true,
        notifyOnDelay: Bool = true,
        quietHoursStart: Int? = nil,
        quietHoursEnd: Int? = nil
    ) {
        self.fallback = fallback
        self.notifyOnOutForDelivery = notifyOnOutForDelivery
        self.notifyOnDelay = notifyOnDelay
        self.quietHoursStart = quietHoursStart
        self.quietHoursEnd = quietHoursEnd
    }
}

/// What a device has applied so far. The sync server uses it to work out which
/// messages a device still needs.
public struct SyncManifest: Codable, Equatable, Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public let deviceID: String
        public let sequence: UInt64

        public init(deviceID: String, sequence: UInt64) {
            self.deviceID = deviceID
            self.sequence = sequence
        }
    }

    public let deviceID: String
    public let generatedAt: Date
    public var entries: [Entry]

    public init(deviceID: String, generatedAt: Date = .now, entries: [Entry]) {
        self.deviceID = deviceID
        self.generatedAt = generatedAt
        self.entries = entries
    }

    /// The bytes a device signs: entries sorted so every platform agrees on them.
    public func canonicalBytes() throws -> Data {
        var copy = self
        copy.entries.sort { ($0.deviceID, $0.sequence) < ($1.deviceID, $1.sequence) }
        return try JSONEncoder.sync.encode(copy)
    }
}

extension JSONEncoder {
    /// Stable output: sorted keys and ISO 8601 dates, the same on iOS and on the server.
    public static var sync: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}

extension JSONDecoder {
    public static var sync: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
