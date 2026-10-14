import SwiftUI

/// Chip-style input for the notification topics a customer follows. Tapping a chip
/// removes it; suggestions not yet chosen are offered below.
struct TopicTokenField: View {
    @Binding var topics: [String]
    let suggestions: [String]

    private var remaining: [String] {
        suggestions.filter { !topics.contains($0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(topics, id: \.self) { topic in
                        Button {
                            topics.removeAll { $0 == topic }
                        } label: {
                            Label(topic, systemImage: "xmark.circle.fill")
                                .labelStyle(.titleAndIcon)
                                .font(.subheadline)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(.tint.opacity(0.15), in: Capsule())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !remaining.isEmpty {
                Menu("Add a topic") {
                    ForEach(remaining, id: \.self) { topic in
                        Button(topic) { topics.append(topic) }
                    }
                }
                .font(.subheadline)
            }
        }
    }
}
