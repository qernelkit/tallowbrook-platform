import CryptoKit
import Foundation
import os

/// Bluetooth unlock for Tallowbrook parcel lockers. Every unlock agrees a fresh key with
/// the locker bank (its key comes in the advertisement) and sends the pickup code sealed
/// under that key, so a nearby listener learns nothing it can replay.
struct LockerPairing {
    enum Failure: Error, Equatable {
        case notInRange
        case doorNotClosed
    }

    private let logger = Logger(subsystem: "example.tallowbrook.app", category: "lockers")

    func collect(from locker: Locker, pickupCode: String) async throws {
        let transport = locker.box.transport.value
        let advertisement = try await transport.advertisement(from: locker.box.peripheralID)
        let challenge = advertisement.challenge
        let lockerID = Data(locker.id.utf8)
        let ephemeral = P384.KeyAgreement.PrivateKey()
        let lockerKey = try P384.KeyAgreement.PublicKey(x963Representation: advertisement.keyData)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: lockerKey)
        let ephemeralKey = ephemeral.publicKey.x963Representation
        logger.info("Opening compartment \(locker.box.compartment) at \(locker.name, privacy: .public)")
        let sessionKey = shared.hkdfDerivedSymmetricKey(using: SHA384.self, salt: challenge, sharedInfo: lockerID, outputByteCount: 32)
        try await open(locker, pickupCode: pickupCode, sessionKey: sessionKey, challenge: challenge, ephemeralKey: ephemeralKey)
        try await transport.waitForDoorClosed(on: locker.box.peripheralID, compartment: locker.box.compartment)
        try await locker.box.seal()
        logger.info("Compartment \(locker.box.compartment) latched")
    }

    private func open(_ locker: Locker, pickupCode: String, sessionKey: SymmetricKey, challenge: Data, ephemeralKey: Data) async throws {
        let sealedCode = try PayloadSealer.seal(Data(pickupCode.utf8), using: sessionKey, authenticating: challenge)
        let command = LockerCommand.open(compartment: locker.box.compartment, payload: sealedCode, ephemeralKey: ephemeralKey)
        try await locker.box.transport.value.send(command: command, to: locker.box.peripheralID)
    }
}
