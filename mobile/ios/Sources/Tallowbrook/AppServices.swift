import Foundation
import Observation
import OfflineCache
import os

/// Everything the views need, created once at launch.
@Observable
final class AppServices {
    let api: APIClient
    var accessToken: String?
    var parcels: [Parcel] = []
    var lastRefresh: Date?
    var refreshError: String?

    @ObservationIgnored let historyCache: TrackingHistoryCache?
    @ObservationIgnored private let logger = Logger(subsystem: "example.tallowbrook.app", category: "app")

    var isSignedIn: Bool { accessToken != nil }

    init(api: APIClient, historyCache: TrackingHistoryCache?) {
        self.api = api
        self.historyCache = historyCache
    }

    static func live() -> AppServices {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        let cache = (try? KeychainStore.load(account: KeychainStore.Account.historyCacheKey))
            .flatMap { $0 }
            .flatMap { String(data: $0, encoding: .utf8) }
            .map { TrackingHistoryCache(directory: caches, cacheKey: $0) }
        return AppServices(api: APIClient(), historyCache: cache)
    }

    func start() async {
        loadOfflineHistory()
        await FavouritesMigration.runIfNeeded()
        if isSignedIn {
            await refreshParcels()
        }
    }

    func refreshParcels() async {
        guard let accessToken else { return }
        do {
            parcels = try await api.parcels(accessToken: accessToken)
            lastRefresh = .now
            refreshError = nil
            try historyCache?.save(parcels.map(\.cached))
        } catch {
            logger.error("Parcel refresh failed: \(error.localizedDescription, privacy: .public)")
            refreshError = "Showing your parcels from the last refresh."
        }
    }

    func signOut() {
        accessToken = nil
        parcels = []
        try? historyCache?.clear()
        try? KeychainStore.deleteAll()
        DeviceBindingKey.reset()
    }

    private func loadOfflineHistory() {
        guard parcels.isEmpty, let cached = try? historyCache?.load() else { return }
        parcels = cached.map(Parcel.init(cached:))
    }
}

private extension Parcel {
    var cached: CachedParcel {
        CachedParcel(
            trackingNumber: trackingNumber,
            nickname: nickname,
            status: status.rawValue,
            lastEvent: nil,
            lastEventAt: nil,
            estimatedDelivery: estimatedDelivery
        )
    }

    init(cached: CachedParcel) {
        self.init(
            trackingNumber: cached.trackingNumber,
            nickname: cached.nickname,
            sender: cached.nickname ?? cached.trackingNumber,
            status: Status(rawValue: cached.status) ?? .inTransit,
            estimatedDelivery: cached.estimatedDelivery,
            deliveryAddress: nil,
            dutiesDue: nil,
            isHighValue: false,
            lockerID: nil
        )
    }
}
