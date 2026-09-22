#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/utsname.h>
#import <string.h>

// Resolve the jailbreak's hook provider at runtime, without SDK-specific headers.
typedef void (*HookMessage)(Class, SEL, IMP, IMP *);
static HookMessage hookMessage;
static NSString *const targetVersion = @"8.29";
static NSString *const targetBuild = @"1866";
static NSString *const targetOS = @"16.3";
static const NSTimeInterval futureTimestamp = 4070908800.0; // 2099-01-01 UTC
static id (*originalObject)(id, SEL, NSString *);
static NSDictionary *(*originalInfo)(id, SEL);

static BOOL signalBundle(NSBundle *bundle) {
    // Avoid bundleIdentifier here: it can read infoDictionary and recurse.
    NSString *path = bundle.bundlePath;
    return [path.lastPathComponent isEqualToString:@"Signal.app"] ||
        [path.lastPathComponent isEqualToString:@"SignalNSE.appex"] ||
        [path.lastPathComponent isEqualToString:@"SignalShareExtension.appex"];
}

static id replacementValue(NSString *key, id value) {
    if ([key isEqualToString:@"CFBundleShortVersionString"]) return targetVersion;
    if ([key isEqualToString:@"CFBundleVersion"]) return targetBuild;
    if ([key isEqualToString:@"BuildDetails"] && [value isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *details = [value mutableCopy];
        details[@"Timestamp"] = @(futureTimestamp);
        details[@"DateTime"] = @"Thu Jan 01 00:00:00 UTC 2099";
        return details;
    }
    return value;
}

static id bundleObject(id self, SEL sel, NSString *key) {
    id value = originalObject(self, sel, key);
    return signalBundle(self) ? replacementValue(key, value) : value;
}

static NSDictionary *bundleInfo(id self, SEL sel) {
    NSDictionary *value = originalInfo(self, sel);
    if (!signalBundle(self) || !value) return value;
    NSMutableDictionary *result = [value mutableCopy];
    for (NSString *key in @[@"CFBundleShortVersionString", @"CFBundleVersion", @"BuildDetails"]) {
        id replacement = replacementValue(key, value[key]);
        if (replacement) result[key] = replacement;
    }
    return result;
}

static NSString *deviceVersion(id self, SEL sel) { return targetOS; }

// Objective-C callers only. Pure Swift calls are addressed by the build date
// and version inputs above, not assumed to pass through this selector.
static BOOL notExpired(id self, SEL sel) { return NO; }

// Reproduce the two hooks verified in the supplied FuckSignalExpiry 0.9.0.
static NSUInteger expiryStatusCode(id self, SEL sel) { return 0; }
static NSOperatingSystemVersion (*originalOSVersion)(id, SEL);
static NSOperatingSystemVersion legacyOSVersion(id self, SEL sel) {
    NSOperatingSystemVersion value = originalOSVersion(self, sel);
    value.majorVersion = 10000;
    return value;
}

static void install(Class cls, NSString *name, IMP replacement, IMP *original) {
    SEL selector = NSSelectorFromString(name);
    if (cls && class_getInstanceMethod(cls, selector)) {
        hookMessage(cls, selector, replacement, original);
    }
}

static NSInteger (*originalStatus)(id, SEL);
static NSInteger responseStatus(id self, SEL sel) {
    NSInteger code = originalStatus(self, sel);
    // Host + status only. Never log paths, credentials, phone numbers or bodies.
    NSString *host = [(NSHTTPURLResponse *)self URL].host.lowercaseString;
    if (code >= 400 && ([host isEqualToString:@"signal.org"] ||
                       [host hasSuffix:@".signal.org"] ||
                       [host hasSuffix:@".whispersystems.org"])) {
        @synchronized (NSHTTPURLResponse.class) {
            static NSUInteger count;
            if (count++ < 32) NSLog(@"[SignalBypass14] HTTP %ld from %@", (long)code, host);
        }
    }
    return code;
}

__attribute__((constructor)) static void start(void) {
    @autoreleasepool {
        NSBundle *main = NSBundle.mainBundle;
        NSString *identifier = main.bundleIdentifier;
        if (![@[@"org.whispersystems.signal", @"org.whispersystems.signal.SignalNSE",
                @"org.whispersystems.signal.shareextension"] containsObject:identifier]) return;
        // Capture genuine values before installing any hook.
        struct utsname kernel;
        BOOL isIOS14 = uname(&kernel) == 0 && strncmp(kernel.release, "20.", 3) == 0;
        NSString *installedVersion = [main objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        NSString *installedBuild = [main objectForInfoDictionaryKey:@"CFBundleVersion"];
        if (!isIOS14 || ![installedVersion isEqualToString:@"7.19.1"] ||
            ![installedBuild isEqualToString:@"208"]) {
            NSLog(@"[SignalBypass14] Inactive: requires iOS 14, Signal 7.19.1 (208)");
            return;
        }
        void *provider = dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        hookMessage = (HookMessage)dlsym(provider ?: RTLD_DEFAULT, "MSHookMessageEx");
        if (!hookMessage) {
            NSLog(@"[SignalBypass14] No compatible hook provider");
            return;
        }
        install(NSProcessInfo.class, @"operatingSystemVersion", (IMP)legacyOSVersion, (IMP *)&originalOSVersion);
        Class expiryClass = NSClassFromString(@"SignalServiceKit.AppExpiryImpl");
        if (!expiryClass) expiryClass = objc_getClass("_TtC16SignalServiceKit13AppExpiryImpl");
        install(object_getClass(expiryClass), @"appExpiredStatusCode", (IMP)expiryStatusCode, NULL);
        install(NSBundle.class, @"objectForInfoDictionaryKey:", (IMP)bundleObject, (IMP *)&originalObject);
        install(NSBundle.class, @"infoDictionary", (IMP)bundleInfo, (IMP *)&originalInfo);
        install(UIDevice.class, @"systemVersion", (IMP)deviceVersion, NULL);
        install(NSClassFromString(@"AppExpiry"), @"isExpired", (IMP)notExpired, NULL);
        install(NSClassFromString(@"SignalServiceKit.AppExpiryImpl"), @"isExpired", (IMP)notExpired, NULL);
        install(NSHTTPURLResponse.class, @"statusCode", (IMP)responseStatus, (IMP *)&originalStatus);
        NSLog(@"[SignalBypass14] v0.2.0 active; app 8.29.0.1866; legacy expiry hooks; build date 2099-01-01");
    }
}
