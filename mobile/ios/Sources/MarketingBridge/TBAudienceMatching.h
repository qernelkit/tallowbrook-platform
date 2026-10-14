//
//  TBAudienceMatching.h
//  MarketingBridge
//
//  Audience matching for the ad partner (customers who opted in only).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TBAudienceMatching : NSObject

/// Trimmed, lower-cased email, hashed as the ad partner's matching API requires. Hex.
+ (NSString *)hashedEmail:(NSString *)email;

@end

NS_ASSUME_NONNULL_END
