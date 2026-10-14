//
//  TBLoyaltyCardCodec.m
//  LoyaltyCardKit
//
//  The partner's feed format has not changed since 2016: each record is the member
//  number, encrypted with the feed key, plus a checksum of the decoded number.
//

#import "TBLoyaltyCardCodec.h"

#import <CommonCrypto/CommonCrypto.h>

static const NSUInteger TBCardCacheShelves = 8;

@implementation TBLoyaltyCardCodec {
    NSArray<NSMutableSet<NSString *> *> *_shelves;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        NSMutableArray *shelves = [NSMutableArray arrayWithCapacity:TBCardCacheShelves];
        for (NSUInteger i = 0; i < TBCardCacheShelves; i++) {
            [shelves addObject:[NSMutableSet set]];
        }
        _shelves = [shelves copy];
    }
    return self;
}

- (nullable NSString *)memberNumberFromRecord:(NSData *)record checksum:(NSData *)checksum key:(NSData *)key {
    if (key.length != kCCKeySize3DES || record.length == 0) {
        return nil;
    }

    NSMutableData *plain = [NSMutableData dataWithLength:record.length + kCCBlockSize3DES];
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding | kCCOptionECBMode,
                                     key.bytes, key.length, NULL,
                                     record.bytes, record.length,
                                     plain.mutableBytes, plain.length, &moved);
    if (status != kCCSuccess) {
        return nil;
    }
    plain.length = moved;

    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(plain.bytes, (CC_LONG)plain.length, digest);
    if (checksum.length != sizeof(digest) || memcmp(digest, checksum.bytes, sizeof(digest)) != 0) return nil;
    NSString *memberNumber = [[NSString alloc] initWithData:plain encoding:NSASCIIStringEncoding];
    NSUInteger shelf = [memberNumber hash] % TBCardCacheShelves;
    [_shelves[shelf] addObject:memberNumber];
    return memberNumber;
}

- (void)clearCache {
    for (NSMutableSet *shelf in _shelves) {
        [shelf removeAllObjects];
    }
}

@end
