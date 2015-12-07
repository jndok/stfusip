//
//  glue.m
//  ropnroll_final
//
//  Created by jndok on 14/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#import <Foundation/Foundation.h>

extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);

UInt64 KextUnslidBaseAddress(const char *KextBundleName)
{
    return (UInt64)[((NSNumber*)(((__bridge NSDictionary*)OSKextCopyLoadedKextInfo(NULL, NULL))[[NSString stringWithUTF8String:KextBundleName]][@"OSBundleLoadAddress"])) unsignedLongLongValue];
}