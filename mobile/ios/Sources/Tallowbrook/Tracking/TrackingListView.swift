import SwiftUI

struct TrackingListView: View {
    @Environment(AppServices.self) private var services
    @State private var showingGuestLookup = false
    @State private var filter: Filter = .active

    enum Filter: String, CaseIterable, Identifiable {
        case active = "On the way"
        case needsAction = "Needs action"
        case delivered = "Delivered"

        var id: String { rawValue }
    }

    private var visibleParcels: [Parcel] {
        services.parcels.filter { parcel in
            switch filter {
            case .active: parcel.status != .delivered && parcel.status != .returned
            case .needsAction: parcel.needsAction
            case .delivered: parcel.status == .delivered
            }
        }
        .sorted { ($0.estimatedDelivery ?? .distantFuture) < ($1.estimatedDelivery ?? .distantFuture) }
    }

    var body: some View {
        List {
            Picker("Show", selection: $filter) {
                ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .listRowSeparator(.hidden)

            if let message = services.refreshError {
                Label(message, systemImage: "wifi.slash")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            ForEach(visibleParcels) { parcel in
                NavigationLink(value: parcel) {
                    ParcelRow(parcel: parcel)
                }
            }

            if visibleParcels.isEmpty {
                ContentUnavailableView(
                    "Nothing here", systemImage: "shippingbox",
                    description: Text("Parcels sent to your email address appear here automatically."))
            }
        }
        .navigationTitle("Parcels")
        .navigationDestination(for: Parcel.self) { ParcelDetailView(parcel: $0) }
        .refreshable { await services.refreshParcels() }
        .toolbar {
            Button("Track a parcel", systemImage: "magnifyingglass") { showingGuestLookup = true }
        }
        .sheet(isPresented: $showingGuestLookup) {
            GuestLookupSheet()
        }
    }
}

private struct ParcelRow: View {
    let parcel: Parcel

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(parcel.displayName).font(.headline)
                Spacer()
                if parcel.needsAction {
                    Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
                }
            }
            Text(parcel.status.title).font(.subheadline)
            if let date = parcel.estimatedDelivery {
                Text("Expected \(date.formatted(.dateTime.weekday(.wide).day().month()))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}

private struct GuestLookupSheet: View {
    @Environment(AppServices.self) private var services
    @Environment(\.dismiss) private var dismiss
    @State private var trackingNumber = ""
    @State private var postcode = ""
    @State private var result: Parcel?
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                TextField("Tracking number", text: $trackingNumber)
                    .textInputAutocapitalization(.characters)
                TextField("Delivery postcode", text: $postcode)
                    .textInputAutocapitalization(.characters)
                Button("Look up") { Task { await lookUp() } }
                    .disabled(trackingNumber.count < 10 || postcode.isEmpty)
                if let result {
                    LabeledContent("Status", value: result.status.title)
                }
                if let message {
                    Text(message).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Track a parcel")
            .toolbar { Button("Done") { dismiss() } }
        }
    }

    private func lookUp() async {
        do {
            guard let signer = try GuestTrackingSigner.current() else {
                message = "Guest tracking isn't ready yet. Try again in a moment."
                return
            }
            result = try await services.api.guestLookup(trackingNumber: trackingNumber, postcode: postcode, signer: signer)
            message = nil
        } catch APIError.notFound {
            message = "We couldn't find a parcel with that number and postcode."
        } catch {
            message = "Something went wrong. Try again."
        }
    }
}
