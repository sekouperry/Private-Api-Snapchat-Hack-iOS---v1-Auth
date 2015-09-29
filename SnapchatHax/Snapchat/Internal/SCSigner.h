//
//  SCSigner.h
//  SnapchatHax
//
//  Copyright (c) 2015 Alex Nichol. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SCSigner : NSObject
{
    
    
}

@property (strong, nonatomic) NSFileHandle *cryptFileHandle;
@property (strong, nonatomic) NSData *cryptData;

-(NSString*) getEncryptedHashForData: (NSData*) data;

-(NSString*) getDeviceTokenKey;
-(NSString*) getDeviceTokenValue;

-(NSString*) getDSIGWithArray: (NSArray*) components;
-(NSString*) getDSIGWithUsername: (NSString*) username withEMail: (NSString*) email withPassword: (NSString*) password withTimestamp: (NSString*) timestamp withReqToken: (NSString*) reqToken;


@end
