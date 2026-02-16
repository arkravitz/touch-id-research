// Execute only Apple's base-class initializer and memory-only command packer.
// No manager singleton, proxy factory, connection, pairing, or IOKit method.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

static NSData *fromHex(NSString *hex) {
    if (![hex isKindOfClass:NSString.class] || hex.length % 2) return nil;
    NSMutableData *data = [NSMutableData data];
    NSCharacterSet *bad = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
    if ([hex rangeOfCharacterFromSet:bad].location != NSNotFound) return nil;
    for (NSUInteger i=0; i<hex.length; i+=2) {
        unsigned value=0; [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i,2)]] scanHexInt:&value];
        uint8_t byte=value; [data appendBytes:&byte length:1];
    }
    return data;
}
int main(void) {
    @autoreleasepool {
        if (!dlopen("/System/Library/PrivateFrameworks/TrustedAccessory.framework/TrustedAccessory",RTLD_LAZY)) return 2;
        Class cls=objc_getClass("TAManagerProxy");
        SEL selector=sel_registerName("prepareCommand:version:inValue:inData:inSize:command:");
        if (!cls || !class_getInstanceMethod(cls,selector)) return 3;
        NSData *input=[[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
        NSError *error=nil;
        id cases=[NSJSONSerialization JSONObjectWithData:input options:0 error:&error];
        if (![cases isKindOfClass:NSArray.class]) return 4;
        NSMutableArray *results=[NSMutableArray array];
        for (id row in cases) {
            if (![row isKindOfClass:NSDictionary.class]) return 5;
            for (NSString *key in @[@"command",@"version",@"in_value"]) {
                id n=row[key];
                if (![n isKindOfClass:NSNumber.class] || [n longLongValue]<0 || [n unsignedLongLongValue]>65535) return 6;
            }
            NSData *payload=fromHex(row[@"payload_hex"]);
            if (!payload || payload.length>1024*1024) return 7;
            id proxy=[[cls alloc] init];
            if (!proxy || object_getClass(proxy)!=cls) return 8;
            id __autoreleasing output=nil;
            typedef int (*Pack)(id,SEL,uint16_t,uint16_t,uint16_t,const void *,NSUInteger,id __autoreleasing *);
            int status=((Pack)objc_msgSend)(proxy,selector,[row[@"command"] unsignedShortValue],
                [row[@"version"] unsignedShortValue],[row[@"in_value"] unsignedShortValue],
                payload.length ? payload.bytes : NULL,payload.length,&output);
            if (status || ![output isKindOfClass:NSData.class] || [output length]<8+payload.length) return 9;
            const uint8_t *bytes=[output bytes];
            NSMutableString *hex=[NSMutableString string];
            for (NSUInteger i=0;i<[output length];i++) [hex appendFormat:@"%02x",bytes[i]];
            [results addObject:@{@"status":@(status),@"buffer_length":@([output length]),@"buffer_hex":hex}];
        }
        NSData *json=[NSJSONSerialization dataWithJSONObject:results options:NSJSONWritingPrettyPrinted error:&error];
        if (!json) return 10;
        [[NSFileHandle fileHandleWithStandardOutput] writeData:json];
    }
    return 0;
}
