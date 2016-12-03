//
//  GJHHTTPTool.h
//  TestLocation
//
//  Created by apple on 16/5/23.
//  Copyright © 2016年 gjh.李智聪 All rights reserved.
//

#import <Foundation/Foundation.h>

#import "GJHLoginViewController.h"

#import <UIKit/UIKit.h>
#import "GJHTabBarController.h"
#import "GJHLoginViewController.h"

typedef void (^GJHRequestSuccess)(id json);
typedef void (^GJHRequestFailure)(NSError *error);





@interface GJHHTTPTool : NSObject

@property (nonatomic,strong)GJHTabBarController *TabBarView;


+(AFHTTPSessionManager *)shareManagerWith:(NSString *)jwtStr Bool:(BOOL)Bool;
+ (void)GET:(NSString *)url params:(NSDictionary *)params view:(UIViewController *)controller success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure;

+ (void)POST:(NSString *)url params:(NSDictionary *)params  view:(UIViewController *)controller success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure;

+ (void)POST:(NSString *)url params:(NSDictionary *)params  view:(UIViewController *)controller jwt:(NSString *)jwt Bool:(BOOL)Bool success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure;

+ (void)PUT:(NSString *)url parameters:(NSDictionary *)params success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure;

+ (id)POST:(NSString *)path parameters:(NSDictionary *)params file:(NSString *)file fileName:(NSString *)fileName imageDataArray:(NSArray *)dataArrs  completionHandle:(void (^)(id success, NSError *error))completionHandle;

@end
