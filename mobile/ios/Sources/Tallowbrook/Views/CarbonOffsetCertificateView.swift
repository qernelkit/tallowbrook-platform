import SwiftUI

/// The customer's yearly carbon-offset certificate: how much CO2e their deliveries
/// produced and how much Tallowbrook offset on their behalf. Shown as a card they can
/// save or share.
struct CarbonOffsetCertificateView: View {
    let year: Int
    @State private var summary: OffsetSummary?

    struct OffsetSummary: Decodable {
        let deliveries: Int
        let kilogramsCO2e: Double
        let projectName: String
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Your \(String(year)) carbon offsets")
                    .font(.title2.bold())
                if let summary {
                    LabeledContent("Deliveries", value: summary.deliveries.formatted())
                    LabeledContent(
                        "Emissions offset", value: "\(summary.kilogramsCO2e.formatted(.number.precision(.fractionLength(1)))) kg CO2e")
                    LabeledContent("Project", value: summary.projectName)
                    Text("Thank you for choosing consolidated delivery days.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ContentUnavailableView(
                        "Not ready yet", systemImage: "leaf", description: Text("Your \(String(year)) summary appears in January."))
                }
            }
            .padding()
            .background(.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
            .padding()
        }
        .navigationTitle("Carbon offset")
    }
}
