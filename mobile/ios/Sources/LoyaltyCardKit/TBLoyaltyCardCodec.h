//
//  TBLoyaltyCardCodec.h
//  LoyaltyCardKit
//
//  Decodes member numbers from the loyalty partner's card feed.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TBLoyaltyCardCodec : NSObject

/// Returns the member number in a feed record, or nil when the record does not decode
/// or its checksum does not match. Results are cached in memory.
- (nullable NSString *)memberNumberFromRecord:(NSData *)record checksum:(NSData *)checksum key:(NSData *)key;

- (void)clearCache;

@end

NS_ASSUME_NONNULL_END
