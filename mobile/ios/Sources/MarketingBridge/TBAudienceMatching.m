//
//  TBAudienceMatching.m
//  MarketingBridge
//

#import "TBAudienceMatching.h"

#import <CommonCrypto/CommonCrypto.h>

@implementation TBAudienceMatching

+ (NSString *)hashedEmail:(NSString *)email {
    NSString *trimmed = [email stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSData *normalized = [[trimmed lowercaseString] dataUsingEncoding:NSUTF8StringEncoding];

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(normalized.bytes, (CC_LONG)normalized.length, digest);

    NSMutableString *hex = [NSMutableString stringWithCapacity:sizeof(digest) * 2];
    for (size_t i = 0; i < sizeof(digest); i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return [hex copy];
}

@end
