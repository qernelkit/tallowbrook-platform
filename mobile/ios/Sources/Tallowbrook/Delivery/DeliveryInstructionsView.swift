import SwiftUI

struct DeliveryInstructions: Codable, Equatable {
    var safePlace: String = ""
    var leaveWithNeighbour = true
    var neighbourHouse: String = ""
    var gateCode: String = ""
    var notes: String = ""
}

struct DeliveryInstructionsView: View {
    @Environment(AppServices.self) private var services
    @Environment(\.dismiss) private var dismiss
    let parcel: Parcel

    @State private var instructions = DeliveryInstructions()
    @State private var saving = false
    @State private var message: String?

    var body: some View {
        Form {
            Section("If you're out") {
                TextField("Safe place (e.g. behind the side gate)", text: $instructions.safePlace)
                Toggle("Neighbours can take it in", isOn: $instructions.leaveWithNeighbour)
                if instructions.leaveWithNeighbour {
                    TextField("Preferred neighbour (house number)", text: $instructions.neighbourHouse)
                }
            }

            Section {
                SecureField("Gate or door code", text: $instructions.gateCode)
                    .keyboardType(.numbersAndPunctuation)
            } header: {
                Text("Access")
            } footer: {
                Text("Only your courier on the day can read this code.")
            }

            Section("Anything else") {
                TextField("Notes for the courier", text: $instructions.notes, axis: .vertical)
                    .lineLimit(3...6)
            }

            Section {
                Button(saving ? "Saving…" : "Save instructions") {
                    Task { await save() }
                }
                .disabled(saving)
            }

            if let message {
                Section { Text(message).foregroundStyle(.secondary) }
            }
        }
        .navigationTitle("Delivery instructions")
    }

    private func save() async {
        guard let token = services.accessToken else { return }
        saving = true
        defer { saving = false }
        do {
            var plain = instructions
            var sealedCode: SealedGateCode?
            if !instructions.gateCode.isEmpty {
                let courier = try await services.api.assignedCourier(for: parcel, accessToken: token)
                if #available(iOS 26.0, *) {
                    sealedCode = try GateCodeSealer().seal(gateCode: instructions.gateCode, for: courier)
                    plain.gateCode = ""
                }
                // On earlier systems the code goes to the delivery API over TLS, which seals it.
            }
            try await services.api.saveInstructions(plain, sealedGateCode: sealedCode, for: parcel, accessToken: token)
            dismiss()
        } catch {
            message = "We couldn't save your instructions. Try again."
        }
    }
}

extension APIClient {
    func assignedCourier(for parcel: Parcel, accessToken: String) async throws -> AssignedCourier {
        var request = URLRequest(url: Self.apiBase.appendingPathComponent("\(TrackingAPI.parcelsPath)/\(parcel.trackingNumber)/courier"))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return try await send(request, as: AssignedCourier.self)
    }

    func saveInstructions(_ instructions: DeliveryInstructions, sealedGateCode: SealedGateCode?, for parcel: Parcel, accessToken: String)
        async throws
    {
        struct Body: Encodable {
            let instructions: DeliveryInstructions
            let sealedGateCode: SealedGateCode?
        }
        var request = URLRequest(
            url: Self.apiBase.appendingPathComponent("\(TrackingAPI.parcelsPath)/\(parcel.trackingNumber)/instructions"))
        request.httpMethod = "PUT"
        request.httpBody = try JSONEncoder().encode(Body(instructions: instructions, sealedGateCode: sealedGateCode))
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        try await sendWithoutBody(request)
    }
}
