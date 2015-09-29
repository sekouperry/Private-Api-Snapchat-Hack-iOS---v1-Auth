//
//  SCSnapManager.h
//  SnapchatHax
//
//  Copyright (c) 2013 Alex Nichol. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SCAPISession.h"

@protocol SCSnapManagerDelegate <NSObject>

- (void)scSnapManager:(id)sender insertedAtIndex:(NSInteger)index;
- (void)scSnapManager:(id)sender deletedAtIndex:(NSInteger)index;
- (void)scSnapManagerFinishedLoading:(id)sender;
- (void)scSnapManager:(id)sender failedWithError:(NSError *)e;

@end

@interface SCSnapManager : NSObject {
    NSMutableArray * fetchers;
    NSCache * blobs;
    NSMutableArray * snaps;
}

@property (readonly) NSMutableArray * snaps;
@property (readonly) NSCache * blobs;
@property (nonatomic, weak) id<SCSnapManagerDelegate> delegate;

- (void)cancelAll;
- (void)startFetchingBlobs:(SCAPISession *)session;

@end
