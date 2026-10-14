import SwiftUI

@main
struct TallowbrookApp: App {
    @State private var services = AppServices.live()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(services)
                .task { await services.start() }
        }
    }
}

struct RootView: View {
    @Environment(AppServices.self) private var services

    var body: some View {
        if services.isSignedIn {
            TabView {
                Tab("Parcels", systemImage: "shippingbox") {
                    NavigationStack { TrackingListView() }
                }
                Tab("Certificate", systemImage: "leaf") {
                    NavigationStack { CarbonOffsetCertificateView(year: Calendar.current.component(.year, from: .now) - 1) }
                }
                Tab("Settings", systemImage: "gearshape") {
                    NavigationStack { SettingsView() }
                }
            }
        } else {
            NavigationStack { LoginView() }
        }
    }
}
