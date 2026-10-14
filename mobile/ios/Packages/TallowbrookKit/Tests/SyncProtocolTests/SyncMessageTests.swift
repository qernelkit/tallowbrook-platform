import Foundation
import SyncProtocol
import XCTest

final class SyncMessageTests: XCTestCase {
    func testAddressRoundTrips() throws {
        let address = SavedAddress(
            label: "Office",
            lines: ["4 Wharf Lane", "Unit 2"],
            postcode: "TB1 4QX",
            countryCode: "GB",
            safePlaceNote: "Reception desk",
            updatedAt: Date(timeIntervalSince1970: 1_760_000_000)
        )
        let message = SyncMessage.addressUpserted(address)

        let data = try JSONEncoder.sync.encode(message)
        let decoded = try JSONDecoder.sync.decode(SyncMessage.self, from: data)

        XCTAssertEqual(decoded, message)
    }

    func testManifestBytesIgnoreEntryOrder() throws {
        let date = Date(timeIntervalSince1970: 1_760_000_000)
        let first = SyncManifest(
            deviceID: "phone",
            generatedAt: date,
            entries: [.init(deviceID: "tablet", sequence: 4), .init(deviceID: "phone", sequence: 9)]
        )
        let second = SyncManifest(
            deviceID: "phone",
            generatedAt: date,
            entries: [.init(deviceID: "phone", sequence: 9), .init(deviceID: "tablet", sequence: 4)]
        )

        XCTAssertEqual(try first.canonicalBytes(), try second.canonicalBytes())
    }

    func testPreferencesDefaults() {
        let preferences = DeliveryPreferences()
        XCTAssertEqual(preferences.fallback, .neighbour)
        XCTAssertTrue(preferences.notifyOnOutForDelivery)
        XCTAssertNil(preferences.quietHoursStart)
    }
}
