import SwiftUI

struct RedeliveryCheckoutView: View {
    enum Reason: String {
        case redelivery
        case customsDuty = "customs_duty"

        var title: String {
            switch self {
            case .redelivery: "Redelivery"
            case .customsDuty: "Customs duty"
            }
        }
    }

    @Environment(AppServices.self) private var services
    @Environment(\.dismiss) private var dismiss

    let parcel: Parcel
    let amount: Decimal
    let reason: Reason

    @State private var cardNumber = ""
    @State private var cardIsValid = false
    @State private var expiry = ""
    @State private var securityCode = ""
    @State private var holderName = ""
    @State private var redeliveryDate = Calendar.current.date(byAdding: .day, value: 1, to: .now) ?? .now
    @State private var paying = false
    @State private var message: String?

    private var canPay: Bool {
        cardIsValid && expiryParts != nil && (3...4).contains(securityCode.count) && !holderName.isEmpty && !paying
    }

    private var expiryParts: (month: Int, year: Int)? {
        let parts = expiry.split(separator: "/").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        guard parts.count == 2, (1...12).contains(parts[0]) else { return nil }
        return (parts[0], parts[1] < 100 ? 2000 + parts[1] : parts[1])
    }

    var body: some View {
        Form {
            Section(reason.title) {
                LabeledContent("Parcel", value: parcel.displayName)
                LabeledContent("Amount", value: amount.formatted(.currency(code: "GBP")))
                if reason == .redelivery {
                    DatePicker("Deliver on", selection: $redeliveryDate, in: Date.now..., displayedComponents: .date)
                }
            }
            Section("Card") {
                CardNumberField(number: $cardNumber, isValid: $cardIsValid)
                TextField("MM/YY", text: $expiry)
                    .keyboardType(.numbersAndPunctuation)
                SecureField("Security code", text: $securityCode)
                    .keyboardType(.numberPad)
                TextField("Name on card", text: $holderName)
                    .textContentType(.name)
            }
            Section {
                Button(paying ? "Paying…" : "Pay \(amount.formatted(.currency(code: "GBP")))") {
                    Task { await pay() }
                }
                .disabled(!canPay)
            }
            if let message {
                Section { Text(message) }
            }
        }
        .navigationTitle(reason.title)
    }

    private func pay() async {
        guard let token = services.accessToken, let expiryParts else { return }
        paying = true
        defer { paying = false }
        let card = CardDetails(
            number: CardNumberField.digits(of: cardNumber).map(String.init).joined(),
            expiryMonth: expiryParts.month,
            expiryYear: expiryParts.year,
            securityCode: securityCode,
            holderName: holderName
        )
        do {
            let processor = try await services.api.processorKey(accessToken: token)
            let sealedCard = try CardEnvelope(processorKeyID: processor.keyID, processorKeyData: processor.publicKey).seal(card)
            try await services.api.pay(
                PaymentRequest(
                    trackingNumber: parcel.trackingNumber,
                    reason: reason.rawValue,
                    amountMinor: NSDecimalNumber(decimal: amount * 100).intValue,
                    redeliveryDate: reason == .redelivery ? redeliveryDate : nil,
                    card: sealedCard
                ),
                accessToken: token
            )
            securityCode = ""
            dismiss()
        } catch {
            message = "The payment didn't go through. You haven't been charged."
        }
    }
}

struct ProcessorKey: Decodable {
    let keyID: String
    let publicKey: Data
}

struct PaymentRequest: Encodable {
    let trackingNumber: String
    let reason: String
    let amountMinor: Int
    let redeliveryDate: Date?
    let card: String
}

extension APIClient {
    func processorKey(accessToken: String) async throws -> ProcessorKey {
        var request = URLRequest(url: Self.apiBase.appendingPathComponent("/v2/payments/processor-key"))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return try await send(request, as: ProcessorKey.self)
    }

    func pay(_ payment: PaymentRequest, accessToken: String) async throws {
        var request = URLRequest(url: Self.apiBase.appendingPathComponent("/v2/payments"))
        request.httpMethod = "POST"
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        request.httpBody = try encoder.encode(payment)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        try await sendWithoutBody(request)
    }
}
