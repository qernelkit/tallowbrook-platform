import SwiftUI

struct ParcelDetailView: View {
    @Environment(AppServices.self) private var services
    let parcel: Parcel

    @State private var events: [TrackingEvent] = []
    @State private var loading = true
    @State private var shareURL: URL?
    @State private var actionMessage: String?

    var body: some View {
        List {
            Section {
                LabeledContent("Tracking number", value: parcel.trackingNumber)
                LabeledContent("From", value: parcel.sender)
                LabeledContent("Status", value: parcel.status.title)
                if let address = parcel.deliveryAddress {
                    LabeledContent("Delivering to", value: address.singleLine)
                }
            }

            Section("What you can do") {
                if let duties = parcel.dutiesDue {
                    NavigationLink("Pay \(duties.formatted(.currency(code: "GBP"))) customs duty") {
                        RedeliveryCheckoutView(parcel: parcel, amount: duties, reason: .customsDuty)
                    }
                }
                if parcel.status == .held || parcel.status == .awaitingCollection {
                    NavigationLink("Book a redelivery") {
                        RedeliveryCheckoutView(parcel: parcel, amount: 3.50, reason: .redelivery)
                    }
                }
                NavigationLink("Delivery instructions") {
                    DeliveryInstructionsView(parcel: parcel)
                }
                if let shareURL {
                    ShareLink("Share tracking", item: shareURL)
                } else {
                    Button("Share tracking") { makeShareLink() }
                }
            }

            Section("Journey") {
                if loading {
                    ProgressView()
                }
                ForEach(events) { event in
                    HStack(alignment: .top) {
                        Image(systemName: event.symbolName).frame(width: 24)
                        VStack(alignment: .leading) {
                            Text(event.detail ?? event.kind.rawValue.capitalized)
                            Text(event.occurredAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if let location = event.location {
                                Text(location).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }

            if let actionMessage {
                Section { Text(actionMessage).font(.footnote) }
            }
        }
        .navigationTitle(parcel.displayName)
        .task { await loadEvents() }
    }

    private func loadEvents() async {
        defer { loading = false }
        guard let token = services.accessToken else { return }
        events = (try? await services.api.events(for: parcel, accessToken: token)) ?? []
    }

    private func makeShareLink() {
        do {
            shareURL = try ShareLinkSigner().link(for: parcel.trackingNumber, validFor: 7 * 24 * 3600)
        } catch {
            actionMessage = "Couldn't create a share link."
        }
    }
}
