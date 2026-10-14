import Foundation
import OfflineCache
import os

/// Moves favourites from the 2017 app's file into saved addresses, once.
enum FavouritesMigration {
    private static let doneKey = "migration.favourites.done"
    private static let logger = Logger(subsystem: "example.tallowbrook.app", category: "migration")

    static func runIfNeeded(defaults: UserDefaults = .standard) async {
        guard !defaults.bool(forKey: doneKey) else { return }
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let file = documents.appendingPathComponent(FavouritesImporter.fileName)
        guard FileManager.default.fileExists(atPath: file.path) else {
            defaults.set(true, forKey: doneKey)
            return
        }
        do {
            guard let v1Key = try KeychainStore.load(account: KeychainStore.Account.favouritesV1Key) else {
                logger.error("Favourites file without its key; leaving it in place")
                return
            }
            let favourites = try FavouritesImporter().importFavourites(from: file, v1Key: Array(v1Key))
            var addresses = SavedAddresses.load()
            for favourite in favourites where !addresses.contains(where: { $0.label == favourite.label }) {
                addresses.append(Address(label: favourite.label, lines: favourite.lines, postcode: favourite.postcode, countryCode: "GB"))
            }
            try SavedAddresses.save(addresses)
            try FileManager.default.removeItem(at: file)
            try KeychainStore.delete(account: KeychainStore.Account.favouritesV1Key)
            defaults.set(true, forKey: doneKey)
            logger.info("Imported \(favourites.count) favourites")
        } catch {
            logger.error("Favourites import failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
