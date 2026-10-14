import Foundation
import os

/// Partner loyalty cards (supermarket and fuel schemes) customers link to earn points on
/// deliveries. The partner's card feed is decoded by the Objective-C codec we have had
/// since 2016.
struct LoyaltyCardService {
    struct FeedRecord: Decodable {
        let record: Data
        let checksum: Data
    }

    private let codec = TBLoyaltyCardCodec()
    private let logger = Logger(subsystem: "example.tallowbrook.app", category: "loyalty")

    func memberNumbers(in feed: [FeedRecord]) throws -> [String] {
        guard let feedKey = try KeychainStore.load(account: KeychainStore.Account.loyaltyFeedKey) else {
            logger.notice("No loyalty feed key yet")
            return []
        }
        return feed.compactMap { item in
            let number = codec.memberNumber(fromRecord: item.record, checksum: item.checksum, key: feedKey)
            if number == nil {
                logger.debug("Skipped a loyalty record that did not decode")
            }
            return number
        }
    }
}

/// Opt-in audience matching for the ad partner: only the hashed email leaves the app.
struct MarketingAudience {
    func matchIdentifier(forEmail email: String) -> String {
        TBAudienceMatching.hashedEmail(email)
    }
}
