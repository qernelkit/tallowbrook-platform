import Foundation

struct TrackingEvent: Identifiable, Codable, Hashable {
    enum Kind: String, Codable {
        case scanned
        case departed
        case arrived
        case outForDelivery = "out_for_delivery"
        case deliveryAttempted = "delivery_attempted"
        case delivered
        case exception
    }

    let id: String
    let kind: Kind
    let occurredAt: Date
    let location: String?
    let detail: String?
    let proofOfDeliveryPhotoID: String?

    var symbolName: String {
        switch kind {
        case .scanned: "barcode.viewfinder"
        case .departed: "arrow.up.right"
        case .arrived: "building.2"
        case .outForDelivery: "truck.box"
        case .deliveryAttempted: "door.left.hand.closed"
        case .delivered: "checkmark.circle.fill"
        case .exception: "exclamationmark.triangle"
        }
    }
}
