import SwiftUI
import SyncProtocol

struct SettingsView: View {
    @Environment(AppServices.self) private var services
    @AppStorage("notify.outForDelivery") private var notifyOutForDelivery = true
    @AppStorage("notify.delays") private var notifyDelays = true
    @State private var topics: [String] = ["Out for delivery", "Delayed"]
    @State private var showingExport = false
    @State private var exportPassword = ""
    @State private var exportedFile: URL?
    @State private var message: String?

    var body: some View {
        Form {
            Section("Notifications") {
                Toggle("Out for delivery", isOn: $notifyOutForDelivery)
                Toggle("Delays", isOn: $notifyDelays)
                TopicTokenField(
                    topics: $topics, suggestions: ["Out for delivery", "Delayed", "Delivered", "Customs", "Collection reminders"])
            }

            Section("Addresses") {
                Button("Export saved addresses") { showingExport = true }
                if let exportedFile {
                    ShareLink("Share export", item: exportedFile)
                }
            }

            Section("Support") {
                LabeledContent("Version", value: BuildInfo.current.summary)
                Link("Help centre", destination: URL(string: "https://help.tallowbrook.example")!)
            }

            Section {
                Button("Sign out", role: .destructive) { services.signOut() }
            }

            if let message {
                Section { Text(message).font(.footnote) }
            }
        }
        .navigationTitle("Settings")
        .alert("Export addresses", isPresented: $showingExport) {
            SecureField("Password for the file", text: $exportPassword)
            Button("Export") { export() }
            Button("Cancel", role: .cancel) { exportPassword = "" }
        } message: {
            Text("You'll need this password to open the file on tallowbrook.example.")
        }
    }

    private func export() {
        defer { exportPassword = "" }
        let exporter = AddressBookExport()
        do {
            let data = try exporter.export(SavedAddresses.load(), password: exportPassword)
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(exporter.suggestedFileName())
            try data.write(to: url, options: .completeFileProtection)
            exportedFile = url
        } catch AddressBookExport.Failure.passwordTooShort {
            message = "Use at least 8 characters."
        } catch {
            message = "The export didn't work. Try again."
        }
    }
}

/// Addresses saved on this device (synced to the customer's other devices).
enum SavedAddresses {
    private static let fileName = "saved-addresses.json"

    private static var fileURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent(fileName)
    }

    static func load() -> [Address] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        return (try? JSONDecoder().decode([Address].self, from: data)) ?? []
    }

    static func save(_ addresses: [Address]) throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(addresses).write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    static func apply(_ saved: SavedAddress) throws {
        var all = load().filter { $0.id != saved.id }
        all.append(
            Address(
                id: saved.id, label: saved.label, lines: saved.lines, postcode: saved.postcode, countryCode: saved.countryCode,
                safePlaceNote: saved.safePlaceNote))
        try save(all)
    }
}
