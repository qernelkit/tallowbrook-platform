import CoreBluetooth
import Foundation
import os

/// Locker banks over Bluetooth LE. One GATT service; the advertisement characteristic is
/// read, commands are written with response, door state arrives as notifications.
final class BluetoothLockerTransport: NSObject, LockerTransport, @unchecked Sendable {
    static let serviceUUID = CBUUID(string: "6F1C0001-8A5D-4E2B-9C1A-3B7D2E40A001")
    static let advertisementUUID = CBUUID(string: "6F1C0002-8A5D-4E2B-9C1A-3B7D2E40A001")
    static let commandUUID = CBUUID(string: "6F1C0003-8A5D-4E2B-9C1A-3B7D2E40A001")
    static let doorStateUUID = CBUUID(string: "6F1C0004-8A5D-4E2B-9C1A-3B7D2E40A001")

    enum Failure: Error {
        case bluetoothOff
        case notConnected
        case badAdvertisement
        case timedOut
    }

    private let central: CBCentralManager
    private let queue = DispatchQueue(label: "example.tallowbrook.lockers")
    private let logger = Logger(subsystem: "example.tallowbrook.app", category: "lockers")
    private var peripherals: [UUID: CBPeripheral] = [:]
    private var pendingReads: [UUID: CheckedContinuation<Data, Error>] = [:]
    private var pendingWrites: [UUID: CheckedContinuation<Void, Error>] = [:]
    private var doorWaiters: [UUID: CheckedContinuation<Void, Error>] = [:]

    override init() {
        central = CBCentralManager(delegate: nil, queue: queue)
        super.init()
        central.delegate = self
    }

    func advertisement(from peripheralID: UUID) async throws -> LockerAdvertisement {
        let data = try await read(Self.advertisementUUID, from: peripheralID)
        // Layout: key length (1 byte) ‖ key ‖ 16-byte challenge.
        guard let length = data.first.map(Int.init), data.count == 1 + length + 16 else {
            throw Failure.badAdvertisement
        }
        let key = data.subdata(in: 1..<(1 + length))
        let challenge = data.subdata(in: (1 + length)..<data.count)
        return LockerAdvertisement(keyData: key, challenge: challenge)
    }

    func send(command: LockerCommand, to peripheralID: UUID) async throws {
        let (peripheral, characteristic) = try characteristic(Self.commandUUID, on: peripheralID)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async {
                self.pendingWrites[peripheralID] = continuation
                peripheral.writeValue(command.frame, for: characteristic, type: .withResponse)
            }
        }
    }

    func waitForDoorClosed(on peripheralID: UUID, compartment: Int) async throws {
        let (peripheral, characteristic) = try characteristic(Self.doorStateUUID, on: peripheralID)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async {
                self.doorWaiters[peripheralID] = continuation
                peripheral.setNotifyValue(true, for: characteristic)
            }
        }
        logger.debug("Door closed on compartment \(compartment)")
    }

    private func read(_ uuid: CBUUID, from peripheralID: UUID) async throws -> Data {
        let (peripheral, characteristic) = try characteristic(uuid, on: peripheralID)
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.pendingReads[peripheralID] = continuation
                peripheral.readValue(for: characteristic)
            }
        }
    }

    private func characteristic(_ uuid: CBUUID, on peripheralID: UUID) throws -> (CBPeripheral, CBCharacteristic) {
        guard central.state == .poweredOn else { throw Failure.bluetoothOff }
        guard let peripheral = peripherals[peripheralID] ?? central.retrievePeripherals(withIdentifiers: [peripheralID]).first,
            let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }),
            let characteristic = service.characteristics?.first(where: { $0.uuid == uuid })
        else { throw Failure.notConnected }
        return (peripheral, characteristic)
    }
}

extension BluetoothLockerTransport: CBCentralManagerDelegate, CBPeripheralDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        logger.info("Bluetooth state \(central.state.rawValue)")
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripherals[peripheral.identifier] = peripheral
        peripheral.delegate = self
        peripheral.discoverServices([Self.serviceUUID])
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        for service in peripheral.services ?? [] where service.uuid == Self.serviceUUID {
            peripheral.discoverCharacteristics(nil, for: service)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        let id = peripheral.identifier
        if characteristic.uuid == Self.doorStateUUID {
            if characteristic.value == Data([0x00]), let waiter = doorWaiters.removeValue(forKey: id) {
                waiter.resume()
            }
            return
        }
        guard let continuation = pendingReads.removeValue(forKey: id) else { return }
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume(returning: characteristic.value ?? Data())
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let continuation = pendingWrites.removeValue(forKey: peripheral.identifier) else { return }
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }
}
