import Foundation

struct Parcel: Identifiable, Codable, Hashable {
    enum Status: String, Codable, CaseIterable {
        case labelCreated = "label_created"
        case inTransit = "in_transit"
        case outForDelivery = "out_for_delivery"
        case awaitingCollection = "awaiting_collection"
        case delivered
        case returned
        case held

        var title: String {
            switch self {
            case .labelCreated: "Label created"
            case .inTransit: "On its way"
            case .outForDelivery: "Out for delivery"
            case .awaitingCollection: "Ready to collect"
            case .delivered: "Delivered"
            case .returned: "Returned to sender"
            case .held: "Held at the depot"
            }
        }
    }

    var id: String { trackingNumber }
    let trackingNumber: String
    var nickname: String?
    var sender: String
    var status: Status
    var estimatedDelivery: Date?
    var deliveryAddress: Address?
    var dutiesDue: Decimal?
    var isHighValue: Bool
    var lockerID: String?

    var displayName: String { nickname ?? sender }

    var needsAction: Bool {
        dutiesDue != nil || status == .awaitingCollection || status == .held
    }

    // Two fetches of the same parcel are the same row, whatever their status.
    static func == (lhs: Parcel, rhs: Parcel) -> Bool {
        lhs.trackingNumber == rhs.trackingNumber
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(trackingNumber)
    }
}
