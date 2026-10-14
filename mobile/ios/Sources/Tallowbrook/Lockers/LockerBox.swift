import Foundation

/// A parcel locker bank, as listed for a parcel waiting in one.
struct Locker: Identifiable, Equatable {
    let id: String
    let name: String
    let address: String
    let box: LockerBox
}

/// One compartment of a locker bank, reached over Bluetooth through the bank's controller.
struct LockerBox: Equatable {
    let compartment: Int
    let peripheralID: UUID
    let transport: LockerTransportReference

    /// Closes the compartment and latches it after the customer has taken the parcel.
    /// Latching needs no proof: anyone may close a door.
    func seal() async throws {
        try await transport.value.send(command: .latch(compartment: compartment), to: peripheralID)
    }
}

/// What a locker bank advertises before an unlock.
struct LockerAdvertisement: Equatable {
    /// The bank's key-agreement key in X9.63 form.
    let keyData: Data
    /// Fresh per advertisement; ties the unlock to this moment.
    let challenge: Data
}

enum LockerCommand: Equatable {
    case open(compartment: Int, payload: Data, ephemeralKey: Data)
    case latch(compartment: Int)

    var frame: Data {
        switch self {
        case let .open(compartment, payload, ephemeralKey):
            var frame = Data([0x01, UInt8(compartment)])
            frame.append(UInt8(ephemeralKey.count))
            frame.append(ephemeralKey)
            frame.append(payload)
            return frame
        case let .latch(compartment):
            return Data([0x02, UInt8(compartment)])
        }
    }
}

protocol LockerTransport: Sendable {
    func advertisement(from peripheralID: UUID) async throws -> LockerAdvertisement
    func send(command: LockerCommand, to peripheralID: UUID) async throws
    func waitForDoorClosed(on peripheralID: UUID, compartment: Int) async throws
}

/// Lets `LockerBox` stay Equatable while holding a transport.
struct LockerTransportReference: Equatable {
    let value: any LockerTransport

    static func == (lhs: Self, rhs: Self) -> Bool { true }
}
