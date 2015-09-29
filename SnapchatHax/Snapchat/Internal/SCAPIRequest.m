//
//  SCAPIRequest.m
//  SnapchatHax
//
//  Created by Alex Nichol on 12/17/13.
//  Copyright (c) 2013 Alex Nichol. All rights reserved.
//

#import "SCAPIRequest.h"
#import "ANAppDelegate.h"

@implementation SCAPIRequest

+ (NSString *)timestampString {
    NSTimeInterval time = [NSDate date].timeIntervalSince1970;
    return [NSString stringWithFormat:@"%llu", (unsigned long long)round(time * 1000.0)];
}

+ (NSString *)encodeQueryParam:(NSString *)param {
    NSMutableString * str = [NSMutableString string];
    for (NSInteger i = 0; i < param.length; i++) {
        unichar aChar = [param characterAtIndex:i];
        if (isalnum(aChar)) {
            [str appendFormat:@"%C", aChar];
        } else {
            [str appendFormat:@"%%%02X", (unsigned char)aChar];
        }
    }
    return str;
}

+ (NSString *)encodeQuery:(NSDictionary *)dict {
    NSMutableString * str = [NSMutableString string];
    
    for (NSString * key in dict) {
        if (str.length) [str appendString:@"&"];
        [str appendFormat:@"%@=%@", [self encodeQueryParam:key],
         [self encodeQueryParam:[dict[key] description]]];
    }
    
    return str;
}

- (id)initWithConfiguration:(SCAPIConfiguration *)enc
                       path:(NSString *)path
                      token:(NSString *)token
                 dictionary:(NSDictionary *)dict {
    if ((self = [super init])) {
        [self setURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@%@", enc.baseURL, path]]];
        [self setHTTPMethod:@"POST"];
        NSString * timestamp = self.class.timestampString;
        
        //[self setValue:@"v1:497A8F6530B882880BB5F6B8A05A6DD0:821D90768F0D6C30BB3BAC0EE4E6E3E16C76B41B51D0700D8323C0E931C87A54C4D9E70C0A5F5D893BC433650FDC65A3" forHTTPHeaderField:@"X-Snapchat-Client-Auth-Token"];
        //[self setValue:@"v1:8E2326C9A6AFA96653AC268B4C451C3C:F3E8B4671B97341CE9EDBA8A2411A060A72FCCE4A9D440D427A080A3F6CF782A4C03D4AC117C60733A3F55CB50566F99" forHTTPHeaderField:@"X-Snapchat-Client-Token"];
        
        NSString *req_token = [enc dualHash:[token dataUsingEncoding:NSUTF8StringEncoding]
                                       andHash:[timestamp dataUsingEncoding:NSUTF8StringEncoding]];
        
        NSString *hashedAuthToken = [NSString stringWithFormat:@"%@|%@|%@", req_token, timestamp, path];
        NSData *hashedAuthTokenData = [hashedAuthToken dataUsingEncoding: NSUTF8StringEncoding];

        NSString *hashedClientToken = [NSString stringWithFormat:@"%@|%@|%@|%@", [dict objectForKey: @"username"], [dict objectForKey: @"password"], timestamp, path];
        NSData *hashedClientTokenData = [hashedClientToken dataUsingEncoding: NSUTF8StringEncoding];
        
        ANAppDelegate *appDelegate = [[UIApplication sharedApplication] delegate];
        
        [self setValue: [appDelegate.signer getEncryptedHashForData: hashedAuthTokenData] forHTTPHeaderField:@"X-Snapchat-Client-Auth-Token"];
        [self setValue: [appDelegate.signer getEncryptedHashForData: hashedClientTokenData] forHTTPHeaderField:@"X-Snapchat-Client-Token"];
        
        [self setValue:timestamp forHTTPHeaderField:@"X-Timestamp"];
        [self setValue:@"en_PL" forHTTPHeaderField:@"Accept-Locale"];
        
        NSMutableDictionary * jsonBody = [dict mutableCopy];

        NSString *dsig = [appDelegate.signer getDSIGWithUsername: [dict objectForKey: @"username"] withEMail: @"" withPassword: [dict objectForKey: @"password"]
                                                   withTimestamp: timestamp withReqToken: req_token];
        
        jsonBody[@"dsig"] = dsig;
        jsonBody[@"dtoken1i"] = [appDelegate.signer getDeviceTokenKey];
        
        jsonBody[@"req_token"] = [enc dualHash:[token dataUsingEncoding:NSUTF8StringEncoding]
                                       andHash:[timestamp dataUsingEncoding:NSUTF8StringEncoding]];
        jsonBody[@"timestamp"] = @([timestamp longLongValue]);
       
        NSData * encoded = [[self.class encodeQuery:jsonBody] dataUsingEncoding:NSASCIIStringEncoding];
        [self setHTTPBody:encoded];
        [self setValue:[NSString stringWithFormat:@"%d", (int)encoded.length]
    forHTTPHeaderField:@"Content-Length"];
        [self setValue:enc.userAgent forHTTPHeaderField:@"User-Agent"];
        [self setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    }
    return self;
}

@end
