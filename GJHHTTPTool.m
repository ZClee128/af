//
//  GJHHTTPTool.m
//  TestLocation
//
//  Created by apple on 16/5/23.
//  Copyright © 2016年 gjh.李智聪 All rights reserved.
//

#import "GJHHTTPTool.h"
#import "GJHLoginViewController.h"
#import "sys/utsname.h"
#import "GJHJwtId.h"
@implementation GJHHTTPTool
+(AFHTTPSessionManager *)shareManagerWith:(NSString *)jwtStr Bool:(BOOL)Bool{
    static dispatch_once_t once;
    static AFHTTPSessionManager *manager;
    dispatch_once(&once, ^{
        AFSecurityPolicy *securityPolicy = [[AFSecurityPolicy alloc] init];
        [securityPolicy setAllowInvalidCertificates:YES];
        manager = [AFHTTPSessionManager manager];

        NSLog(@"token====%@",[[NSUserDefaults standardUserDefaults] objectForKey:kToken]);
        [manager setSecurityPolicy:securityPolicy];
        //manager.responseSerializer = [AFHTTPResponseSerializer serializer];
        manager.responseSerializer.acceptableContentTypes = [NSSet setWithObjects:@"text/x-json",@"text/html",@"image/jpeg",@"application/json", nil];
    });
    NSString *message = [[NSUserDefaults standardUserDefaults] objectForKey:kToken];
    NSString *secret = [[NSUserDefaults standardUserDefaults] objectForKey:@"jwtKey"];
    NSString *algorithmName = @"HS256";
    
    JWTBuilder *builder = [JWTBuilder decodeMessage:message].secret(secret).algorithmName(algorithmName);
    
    NSDictionary *payload = builder.decode;
    
    if (!builder.jwtError) {
        // do your work here
        NSLog(@"payload == %@ ",payload);
        long long iphone;
        if ([[self deviceString] isEqualToString:@"iPhone 4S"]) {
            NSTimeInterval timeStamp= [[NSDate date] timeIntervalSince1970];
//            CGFloat iphone3 = timeStamp*1000;
            NSString *str = [NSString stringWithFormat:@"%.f",timeStamp];
            iphone = [str longLongValue];
        }else
        {
            iphone = [[NSDate date] timeIntervalSince1970];
            
        }
        
        if (Bool == NO) {
            jwtStr = [NSString stringWithFormat:@"%@.%zd.%f.%ld",[[NSUserDefaults standardUserDefaults] objectForKey:@"UserID"],arc4random()%10000000000,[[NSDate date] timeIntervalSince1970],[GJHJwtId getJwtId]];
        }
            NSDictionary *pay = @{@"jti":jwtStr,@"iss":payload[@"payload"][@"iss"],@"jwt_login_user":payload[@"payload"][@"jwt_login_user"],@"sub":payload[@"payload"][@"sub"],@"iat":[NSString stringWithFormat:@"%lld",iphone + [[[NSUserDefaults standardUserDefaults] objectForKey:@"sub"] longLongValue]],@"exp":[NSString stringWithFormat:@"%lld",iphone + [[[NSUserDefaults standardUserDefaults] objectForKey:@"sub"] longLongValue]+60]};
            NSString *secret = [[NSUserDefaults standardUserDefaults] objectForKey:@"jwtKey"];
            id<JWTAlgorithm> algorithm = [JWTAlgorithmFactory algorithmByName:@"HS256"];
            NSString *token = [JWTBuilder encodePayload:pay].secret(secret).algorithm(algorithm).encode;
            
            [manager.requestSerializer setValue:token forHTTPHeaderField:@"x-tn-token"];
            NSLog(@"token====%@----->%@--->%@",pay,token,secret);
        
        
    }
    else {
        // handle error
        NSLog(@"error ---> %@",builder.jwtError);
    }

    
//    manager.requestSerializer.timeoutInterval =10.f;
    [manager.requestSerializer willChangeValueForKey:@"timeoutInterval"];
    manager.requestSerializer.timeoutInterval = 30.0f;
    [manager.requestSerializer didChangeValueForKey:@"timeoutInterval"];
    return manager;
}
+ (NSString*)deviceString
{
    // 需要#import "sys/utsname.h"
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *deviceString = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
    
    if ([deviceString isEqualToString:@"iPhone1,1"])    return @"iPhone 1G";
    if ([deviceString isEqualToString:@"iPhone1,2"])    return @"iPhone 3G";
    if ([deviceString isEqualToString:@"iPhone2,1"])    return @"iPhone 3GS";
    if ([deviceString isEqualToString:@"iPhone3,1"])    return @"iPhone 4";
    if ([deviceString isEqualToString:@"iPhone4,1"])    return @"iPhone 4S";
    if ([deviceString isEqualToString:@"iPhone5,2"])    return @"iPhone 5";
    if ([deviceString isEqualToString:@"iPhone3,2"])    return @"Verizon iPhone 4";
    if ([deviceString isEqualToString:@"iPod1,1"])      return @"iPod Touch 1G";
    if ([deviceString isEqualToString:@"iPod2,1"])      return @"iPod Touch 2G";
    if ([deviceString isEqualToString:@"iPod3,1"])      return @"iPod Touch 3G";
    if ([deviceString isEqualToString:@"iPod4,1"])      return @"iPod Touch 4G";
    if ([deviceString isEqualToString:@"iPad1,1"])      return @"iPad";
    if ([deviceString isEqualToString:@"iPad2,1"])      return @"iPad 2 (WiFi)";
    if ([deviceString isEqualToString:@"iPad2,2"])      return @"iPad 2 (GSM)";
    if ([deviceString isEqualToString:@"iPad2,3"])      return @"iPad 2 (CDMA)";
    if ([deviceString isEqualToString:@"i386"])         return @"Simulator";
    if ([deviceString isEqualToString:@"x86_64"])       return @"Simulator";
    NSLog(@"NOTE: Unknown device type: %@", deviceString);
    return deviceString;
}


-(NSDate*)dateFromLongLong:(long long)msSince1970{
    
    return [NSDate dateWithTimeIntervalSince1970:msSince1970 / 1000];
}
+ (AFSecurityPolicy *)customSecurityPolicy
{
    //先导入证书，找到证书的路径
    NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"passport.tnomg.com" ofType:@"cer"];
    NSData *certData = [NSData dataWithContentsOfFile:cerPath];
    
    //AFSSLPinningModeCertificate 使用证书验证模式
    AFSecurityPolicy *securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    //allowInvalidCertificates 是否允许无效证书（也就是自建的证书），默认为NO
    //如果是需要验证自建证书，需要设置为YES
    securityPolicy.allowInvalidCertificates = YES;
    
    //validatesDomainName 是否需要验证域名，默认为YES；
    //假如证书的域名与你请求的域名不一致，需把该项设置为NO；如设成NO的话，即服务器使用其他可信任机构颁发的证书，也可以建立连接，这个非常危险，建议打开。
    //置为NO，主要用于这种情况：客户端请求的是子域名，而证书上的是另外一个域名。因为SSL证书上的域名是独立的，假如证书上注册的域名是www.google.com，那么mail.google.com是无法验证通过的；当然，有钱可以注册通配符的域名*.google.com，但这个还是比较贵的。
    //如置为NO，建议自己添加对应域名的校验逻辑。
    securityPolicy.validatesDomainName = NO;
    NSSet *set = [[NSSet alloc] initWithObjects:certData, nil];
    securityPolicy.pinnedCertificates = set;
    
    return securityPolicy;
}

+ (void)GET:(NSString *)url params:(NSDictionary *)params view:(UIViewController *)controller success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure
{
    NSLog(@"----params---%@",params);
    AFHTTPSessionManager *manager = [self shareManagerWith:nil Bool:NO];
//    [manager setSecurityPolicy:[self customSecurityPolicy]];
    [manager GET:url parameters:params progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        !success ? : success(responseObject);
        if ([responseObject[@"errcode"] intValue] == 400003 || [responseObject[@"errcode"] intValue] == 400000 || [responseObject[@"errcode"] intValue] == 400006 || [responseObject[@"errcode"] intValue] == 400130 || [responseObject[@"errcode"] intValue] == 400129 || [responseObject[@"errcode"] intValue] == 400128 ||
            [responseObject[@"errcode"] intValue] == 400127 ||
            [responseObject[@"errcode"] intValue] == 400126) {
            NSLog(@"错误信息====");
            if ([responseObject[@"errcode"] intValue] == 400003 ) {
                [ESToast showDelayToastWithText:@"你的账户已在其他设备登录"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400130 ) {
                [ESToast showDelayToastWithText:@"你的手机时间异常,请设置手机时间"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400129 ) {
                [ESToast showDelayToastWithText:@"非法访问，jwt格式不正确"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400128 ) {
                [ESToast showDelayToastWithText:@"jwt请求过期"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400127 ) {
                [ESToast showDelayToastWithText:@"jwt已失效"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400126 ) {
                [ESToast showDelayToastWithText:@"jwt签名认证失败"];
            }
            
            
            controller.navigationController.navigationBar.hidden = YES;
            controller.tabBarController.tabBar.hidden = YES;
            controller.navigationController.interactivePopGestureRecognizer.enabled = NO ;
            NSFileManager *defaultManager = [NSFileManager defaultManager];
            NSString *docPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)lastObject];
            NSString *dataFilepath = [docPath stringByAppendingPathComponent:@"person.yangyang"];
            if ([defaultManager isDeletableFileAtPath:dataFilepath]) {
                [defaultManager removeItemAtPath:dataFilepath error:nil];
            }
            NSUserDefaults *defualts = [NSUserDefaults standardUserDefaults];
            [defualts removeObjectForKey:@"phone"];
            [defualts removeObjectForKey:@"UserID"];
            [defualts removeObjectForKey:kToken];
            [defualts removeObjectForKey:@"merchanrID"];
            [[GJHHTTPTool shareManagerWith:nil Bool:NO].requestSerializer setValue:@"" forHTTPHeaderField:@"x-tn-token"];
            GJHLoginViewController *login = [GJHLoginViewController new];
            login.type = 1;
            [controller.navigationController pushViewController:login animated:YES];
            [[NSNotificationCenter defaultCenter] postNotificationName:@"eixt" object:[UIImage imageNamed:@"ic_logHui"]];
        }

    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        !failure ? : failure(error);
        if (error.code == -1001) {
//            [controller hideHUDWithView:nil];
            [ESToast showDelayToastWithText:@"连接超时,请检查网络"];
        }else if (error.code == -1009)
        {
            [ESToast showDelayToastWithText:@"您的网络好像不太给力,请检查网络"];
        }
    }];
}

+ (void)PUT:(NSString *)url parameters:(NSDictionary *)params success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure
{
    AFHTTPSessionManager *manager = [self shareManagerWith:nil Bool:NO];
    [manager PUT:url parameters:params success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        !success ? : success(responseObject);
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        !failure ? : failure(error);
        if (error.code == -1001) {
            //            [controller hideHUDWithView:nil];
            [ESToast showDelayToastWithText:@"连接超时,请检查网络"];
        }else if (error.code == -1009)
        {
            [ESToast showDelayToastWithText:@"您的网络好像不太给力,请检查网络"];
        }
    }];
}

+ (void)POST:(NSString *)url params:(NSDictionary *)params  view:(UIViewController *)controller jwt:(NSString *)jwt Bool:(BOOL)Bool success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure
{
    NSLog(@"----params---%@",params);
    AFHTTPSessionManager *manager = [self shareManagerWith:jwt Bool:YES];
    [manager setSecurityPolicy:[self customSecurityPolicy]];
    [manager POST:url parameters:params progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        !success ? : success(responseObject);
        
        if ([responseObject[@"errcode"] intValue] == 400003 || [responseObject[@"errcode"] intValue] == 400000 ||[responseObject[@"errcode"] intValue] == 400006 ||[responseObject[@"errcode"] intValue] == 400130 || [responseObject[@"errcode"] intValue] == 400129 || [responseObject[@"errcode"] intValue] == 400128 ||
            [responseObject[@"errcode"] intValue] == 400127 ||
            [responseObject[@"errcode"] intValue] == 400126) {
            NSLog(@"错误信息====");
            if ([responseObject[@"errcode"] intValue] == 400003 ) {
                [ESToast showDelayToastWithText:@"你的账户已在其他设备登录"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400130 ) {
                [ESToast showDelayToastWithText:@"你的手机时间异常,请设置手机时间"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400129 ) {
                [ESToast showDelayToastWithText:@"非法访问，jwt格式不正确"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400128 ) {
                [ESToast showDelayToastWithText:@"jwt请求过期"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400127 ) {
                [ESToast showDelayToastWithText:@"jwt已失效"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400126 ) {
                [ESToast showDelayToastWithText:@"jwt签名认证失败"];
            }
            
            
            controller.tabBarController.tabBar.hidden = YES;
            controller.navigationController.navigationBar.hidden = YES;
            controller.navigationController.interactivePopGestureRecognizer.enabled = NO ;
            NSFileManager *defaultManager = [NSFileManager defaultManager];
            NSString *docPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)lastObject];
            NSString *dataFilepath = [docPath stringByAppendingPathComponent:@"person.yangyang"];
            if ([defaultManager isDeletableFileAtPath:dataFilepath]) {
                [defaultManager removeItemAtPath:dataFilepath error:nil];
            }
            NSUserDefaults *defualts = [NSUserDefaults standardUserDefaults];
            [defualts removeObjectForKey:@"phone"];
            [defualts removeObjectForKey:@"UserID"];
            [defualts removeObjectForKey:kToken];
            [defualts removeObjectForKey:@"merchanrID"];
            [[GJHHTTPTool shareManagerWith:nil Bool:NO].requestSerializer setValue:@"" forHTTPHeaderField:@"x-tn-token"];
            GJHLoginViewController *login = [GJHLoginViewController new];
            login.type = 1;
            [controller.navigationController pushViewController:login animated:YES];
            [[NSNotificationCenter defaultCenter] postNotificationName:@"eixt" object:[UIImage imageNamed:@"ic_logHui"]];
            
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        !failure ? : failure(error);
        if (error.code == -1001) {
            //            [controller hideHUDWithView:nil];
            [ESToast showDelayToastWithText:@"连接超时,请检查网络"];
        }else if (error.code == -1009)
        {
            [ESToast showDelayToastWithText:@"您的网络好像不太给力,请检查网络"];
        }
    }];

}



+(void)POST:(NSString *)url params:(NSDictionary *)params view:(UIViewController *)controller success:(GJHRequestSuccess)success failure:(GJHRequestFailure)failure
{
    NSLog(@"----params---%@",params);
    AFHTTPSessionManager *manager = [self shareManagerWith:nil Bool:NO];
    [manager setSecurityPolicy:[self customSecurityPolicy]];
    [manager POST:url parameters:params progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        !success ? : success(responseObject);
        
        if ([responseObject[@"errcode"] intValue] == 400003 || [responseObject[@"errcode"] intValue] == 400000 ||[responseObject[@"errcode"] intValue] == 400006 ||[responseObject[@"errcode"] intValue] == 400130 || [responseObject[@"errcode"] intValue] == 400129 || [responseObject[@"errcode"] intValue] == 400128 ||
            [responseObject[@"errcode"] intValue] == 400127 ||
            [responseObject[@"errcode"] intValue] == 400126) {
            NSLog(@"错误信息====");
            if ([responseObject[@"errcode"] intValue] == 400003 ) {
                [ESToast showDelayToastWithText:@"你的账户已在其他设备登录"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400130 ) {
                [ESToast showDelayToastWithText:@"你的手机时间异常,请设置手机时间"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400129 ) {
                [ESToast showDelayToastWithText:@"非法访问，jwt格式不正确"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400128 ) {
                [ESToast showDelayToastWithText:@"jwt请求过期"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400127 ) {
                [ESToast showDelayToastWithText:@"jwt已失效"];
            }
            else if ([responseObject[@"errcode"] intValue] == 400126 ) {
                [ESToast showDelayToastWithText:@"jwt签名认证失败"];
            }
            
            
            controller.tabBarController.tabBar.hidden = YES;
            controller.navigationController.navigationBar.hidden = YES;
            controller.navigationController.interactivePopGestureRecognizer.enabled = NO ;
            NSFileManager *defaultManager = [NSFileManager defaultManager];
            NSString *docPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)lastObject];
            NSString *dataFilepath = [docPath stringByAppendingPathComponent:@"person.yangyang"];
            if ([defaultManager isDeletableFileAtPath:dataFilepath]) {
                [defaultManager removeItemAtPath:dataFilepath error:nil];
            }
            NSUserDefaults *defualts = [NSUserDefaults standardUserDefaults];
            [defualts removeObjectForKey:@"phone"];
            [defualts removeObjectForKey:@"UserID"];
            [defualts removeObjectForKey:kToken];
            [defualts removeObjectForKey:@"merchanrID"];
            [[GJHHTTPTool shareManagerWith:nil Bool:NO].requestSerializer setValue:@"" forHTTPHeaderField:@"x-tn-token"];
            GJHLoginViewController *login = [GJHLoginViewController new];
            login.type = 1;
            [controller.navigationController pushViewController:login animated:YES];
            [[NSNotificationCenter defaultCenter] postNotificationName:@"eixt" object:[UIImage imageNamed:@"ic_logHui"]];
            
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        !failure ? : failure(error);
        if (error.code == -1001) {
            //            [controller hideHUDWithView:nil];
            [ESToast showDelayToastWithText:@"连接超时,请检查网络"];
        }else if (error.code == -1009)
        {
            [ESToast showDelayToastWithText:@"您的网络好像不太给力,请检查网络"];
        }
    }];
}

+ (id)POST:(NSString *)path parameters:(NSDictionary *)params file:(NSString *)file fileName:(NSString *)fileName imageDataArray:(NSArray *)dataArrs completionHandle:(void (^)(id, NSError *))completionHandle{
//    [self showBusy];
    AFHTTPSessionManager *manager =[AFHTTPSessionManager manager];
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager.requestSerializer setValue:[[NSUserDefaults standardUserDefaults] objectForKey:kToken] forHTTPHeaderField:@"x-tn-token"];
    return [manager POST:path parameters:params constructingBodyWithBlock:^(id<AFMultipartFormData>  _Nonnull formData) {
        for(NSInteger i = 0; i < dataArrs.count; i++)
        {
            UIImage *image = [dataArrs objectAtIndex: i];
            
            NSData  *imageData  =UIImageJPEGRepresentation(image, 0.2);
            
//            NSString *Name = [NSString stringWithFormat:@"%@%ld",fileName, i+1];
//            NSString *fileName = [NSString stringWithFormat:@"%@.jpg", Name];
            //参数名
            NSString *stringName = nil;
            
            stringName =[NSString stringWithFormat:@"%@%ld.jpg",file,i+1];
            
            [formData appendPartWithFileData:imageData name:fileName fileName:stringName mimeType:@"image/jpeg"];
        }
        
    } progress:^(NSProgress * _Nonnull uploadProgress) {
        
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
//        [self hideProgress];
        completionHandle(responseObject, nil);
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        
//        [self hideProgress];
        
        completionHandle(nil, error);
    }];
}




-(NSString *)dataFilepath
{
    //1.获取文件路径
    NSString *docPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)lastObject];
    return [docPath stringByAppendingPathComponent:@"person.yangyang"];
}

@end
