#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/utsname.h>
#import <string.h>
// v0.9 injection canary compile-fix marker
// v0.9 compile trigger 2


// Resolve the jailbreak's hook provider at runtime, without SDK-specific headers.
typedef void (*HookMessage)(Class, SEL, IMP, IMP *);
typedef void (*HookFunction)(void *, void *, void **);
static HookMessage hookMessage;
static HookFunction hookFunction;
static NSUInteger swiftHookCount;
static void install(Class cls, NSString *name, IMP replacement, IMP *original);

#import "StartupDiagnostics.h"
static NSString *const targetVersion = @"8.29";
static NSString *const targetBuild = @"1866"; // exact build from the supplied working Signal 8.29 IPA
static NSString *const targetOS = @"16.3";
static NSString *const networkUserAgent = @"Signal-iOS/8.29.0.1866 iOS/16.3";
static const NSTimeInterval futureTimestamp = 1789506082.0; // exact Signal 8.29 build timestamp
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
        details[@"DateTime"] = @"Tue Sep 15 21:01:22 UTC 2026";
        details[@"SignalCommit"] = @"3188f61b17c4b4caa837ab52a0babab5b9fd6423 Feature flags for .production.";
        details[@"XCodeVersion"] = @"2600.2660";
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

static void install(Class cls, NSString *name, IMP replacement, IMP *original) {
    SEL selector = NSSelectorFromString(name);
    if (cls && class_getInstanceMethod(cls, selector)) {
        hookMessage(cls, selector, replacement, original);
    }
}


static BOOL swiftReturnFalse(void) { return NO; }
static NSUInteger swiftReturnZero(void) { return 0; }
static void swiftNoop(void) {}

static BOOL installSwiftHook(const char *symbol, void *replacement) {
    if (!hookFunction) return NO;
    void *target = dlsym(RTLD_DEFAULT, symbol);
    if (!target) {
        trace("swift symbol missing: %s", symbol);
        return NO;
    }
    hookFunction(target, replacement, NULL);
    swiftHookCount++;
    trace("swift hook installed: %s", symbol);
    return YES;
}

static void installSwiftRegistrationHooks(void) {
    // These symbols are exported by the exact SignalServiceKit binary in
    // Signal 7.19.1 (208). They cover the pure-Swift paths that Objective-C
    // method swizzling cannot reliably reach.
    installSwiftHook("$s16SignalServiceKit13AppExpiryImplC9isExpiredSbvg",
                     (void *)&swiftReturnFalse);
    installSwiftHook("$s16SignalServiceKit13AppExpiryImplC9isExpiredSbvgTq",
                     (void *)&swiftReturnFalse);
    installSwiftHook("$s16SignalServiceKit13AppExpiryImplC06setHasD23ExpiredAtCurrentVersion2dbyAA2DB_p_tF",
                     (void *)&swiftNoop);
    installSwiftHook("$s16SignalServiceKit13AppExpiryImplC06setHasD23ExpiredAtCurrentVersion2dbyAA2DB_p_tFTq",
                     (void *)&swiftNoop);
    installSwiftHook("$s16SignalServiceKit13AppExpiryImplC20appExpiredStatusCodeSuvgZ",
                     (void *)&swiftReturnZero);
    installSwiftHook("$s16SignalServiceKit19RegistrationSessionV37hasUnknownChallengeRequiringAppUpdateSbvg",
                     (void *)&swiftReturnFalse);
}

static BOOL signalServiceHost(NSString *host) {
    NSString *lower = host.lowercaseString;
    return [lower isEqualToString:@"signal.org"] ||
        [lower hasSuffix:@".signal.org"] ||
        [lower hasSuffix:@".whispersystems.org"];
}

static NSString *lastRequestHost;
static NSString *lastRequestMethod;
static NSString *lastRequestUA;
static NSInteger lastHTTPStatus = -1;
static BOOL sawSignalRequest;
static BOOL sawRemoteExpiry499;

static void rememberRequest(NSURLRequest *request) {
    if (!request || !signalServiceHost(request.URL.host)) return;
    @synchronized (NSURLSession.class) {
        sawSignalRequest = YES;
        lastRequestHost = [request.URL.host.lowercaseString copy];
        lastRequestMethod = [(request.HTTPMethod ?: @"REQUEST") copy];
        lastRequestUA = [([request valueForHTTPHeaderField:@"User-Agent"] ?: @"<none>") copy];
    }
}

static void rememberResponse(NSURLResponse *response) {
    if (![response isKindOfClass:NSHTTPURLResponse.class]) return;
    NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
    NSString *host = http.URL.host.lowercaseString;
    if (!signalServiceHost(host)) return;
    NSInteger status = http.statusCode;
    @synchronized (NSURLSession.class) {
        lastRequestHost = [host copy];
        if (!(sawRemoteExpiry499 && status == 400)) {
            lastHTTPStatus = status;
        }
    }
}

static NSString *diagnosticSummary(void) {
    @synchronized (NSURLSession.class) {
        NSString *status = lastHTTPStatus >= 0 ? [NSString stringWithFormat:@"%ld", (long)lastHTTPStatus] : @"none";
        return [NSString stringWithFormat:@"SB14 v0.8 • swift=%lu • req=%@ • %@ %@ • HTTP %@ • UA=%@",
                (unsigned long)swiftHookCount,
                sawSignalRequest ? @"yes" : @"no",
                lastRequestMethod ?: @"none",
                lastRequestHost ?: @"none",
                status,
                lastRequestUA ?: @"none"];
    }
}


static UIViewController *topVisibleController(void) {
    UIWindow *window = nil;
    for (UIWindow *candidate in UIApplication.sharedApplication.windows) {
        if (!candidate.hidden && candidate.alpha > 0.0) {
            window = candidate;
            break;
        }
    }
    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController) controller = controller.presentedViewController;
    if ([controller isKindOfClass:UINavigationController.class]) {
        UIViewController *visible = ((UINavigationController *)controller).visibleViewController;
        if (visible) controller = visible;
    }
    if ([controller isKindOfClass:UITabBarController.class]) {
        UIViewController *selected = ((UITabBarController *)controller).selectedViewController;
        if (selected) controller = selected;
    }
    return controller;
}

static void showInjectionCanary(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"org.whispersystems.signal"]) return;
        UIViewController *controller = topVisibleController();
        if (!controller) return;
        NSString *message = [NSString stringWithFormat:
            @"Tweak injection confirmed.\nMSHookMessageEx: %@\nMSHookFunction: %@\nSwift hooks: %lu",
            hookMessage ? @"yes" : @"no",
            hookFunction ? @"yes" : @"no",
            (unsigned long)swiftHookCount];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"SB14 v1.0 loaded"
                                                                        message:message
                                                                 preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Continue" style:UIAlertActionStyleDefault handler:nil]];
        [controller presentViewController:alert animated:YES completion:nil];
    });
}

static void (*originalSetHeaderValue)(id, SEL, NSString *, NSString *);
static void setHeaderValue(id self, SEL sel, NSString *value, NSString *field) {
    if ([field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        [value hasPrefix:@"Signal-iOS/"]) {
        value = networkUserAgent;
    }
    originalSetHeaderValue(self, sel, value, field);
}

static void (*originalAddHeaderValue)(id, SEL, NSString *, NSString *);
static void addHeaderValue(id self, SEL sel, NSString *value, NSString *field) {
    if ([field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        [value hasPrefix:@"Signal-iOS/"]) {
        value = networkUserAgent;
    }
    originalAddHeaderValue(self, sel, value, field);
}

static NSURLRequest *latestIdentityRequest(NSURLRequest *request) {
    if (!request || !signalServiceHost(request.URL.host)) return request;
    NSMutableURLRequest *copy = [request mutableCopy];
    NSString *before = [copy valueForHTTPHeaderField:@"User-Agent"] ?: @"<none>";
    [copy setValue:networkUserAgent forHTTPHeaderField:@"User-Agent"];
    NSString *after = [copy valueForHTTPHeaderField:@"User-Agent"] ?: @"<none>";
    rememberRequest(copy);
    @synchronized (NSURLSession.class) {
        static NSUInteger count;
        if (count++ < 32) {
            trace("request method=%s host=%s ua_before=%s ua_after=%s",
                  (copy.HTTPMethod ?: @"REQUEST").UTF8String,
                  (copy.URL.host.lowercaseString ?: @"<none>").UTF8String,
                  before.UTF8String, after.UTF8String);
            NSLog(@"[SignalBypass14] forcing latest Signal identity for %@ %@",
                  copy.HTTPMethod ?: @"REQUEST", copy.URL.host.lowercaseString);
        }
    }
    return copy;
}

typedef NSURLSessionDataTask *(*DataTaskRequestFn)(id, SEL, NSURLRequest *);
typedef NSURLSessionDataTask *(*DataTaskRequestCompletionFn)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionUploadTask *(*UploadTaskDataFn)(id, SEL, NSURLRequest *, NSData *);
typedef NSURLSessionUploadTask *(*UploadTaskDataCompletionFn)(id, SEL, NSURLRequest *, NSData *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionDownloadTask *(*DownloadTaskRequestFn)(id, SEL, NSURLRequest *);
typedef NSURLSessionDownloadTask *(*DownloadTaskRequestCompletionFn)(id, SEL, NSURLRequest *, void (^)(NSURL *, NSURLResponse *, NSError *));

static DataTaskRequestFn originalDataTaskRequest;
static DataTaskRequestCompletionFn originalDataTaskRequestCompletion;
static UploadTaskDataFn originalUploadTaskData;
static UploadTaskDataCompletionFn originalUploadTaskDataCompletion;
static DownloadTaskRequestFn originalDownloadTaskRequest;
static DownloadTaskRequestCompletionFn originalDownloadTaskRequestCompletion;

static NSURLSessionDataTask *dataTaskRequest(id self, SEL sel, NSURLRequest *request) {
    return originalDataTaskRequest(self, sel, latestIdentityRequest(request));
}

static NSURLSessionDataTask *dataTaskRequestCompletion(id self, SEL sel, NSURLRequest *request,
                                                        void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    NSURLRequest *updated = latestIdentityRequest(request);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        rememberResponse(response);
        if (completion) completion(data, response, error);
    };
    return originalDataTaskRequestCompletion(self, sel, updated, wrapped);
}

static NSURLSessionUploadTask *uploadTaskData(id self, SEL sel, NSURLRequest *request, NSData *data) {
    return originalUploadTaskData(self, sel, latestIdentityRequest(request), data);
}

static NSURLSessionUploadTask *uploadTaskDataCompletion(id self, SEL sel, NSURLRequest *request, NSData *data,
                                                        void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    NSURLRequest *updated = latestIdentityRequest(request);
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *responseData, NSURLResponse *response, NSError *error) {
        rememberResponse(response);
        if (completion) completion(responseData, response, error);
    };
    return originalUploadTaskDataCompletion(self, sel, updated, data, wrapped);
}

static NSURLSessionDownloadTask *downloadTaskRequest(id self, SEL sel, NSURLRequest *request) {
    return originalDownloadTaskRequest(self, sel, latestIdentityRequest(request));
}

static NSURLSessionDownloadTask *downloadTaskRequestCompletion(id self, SEL sel, NSURLRequest *request,
                                                                void (^completion)(NSURL *, NSURLResponse *, NSError *)) {
    return originalDownloadTaskRequestCompletion(self, sel, latestIdentityRequest(request), completion);
}

static void installNetworkIdentityHooks(void) {
    // Foundation uses class clusters. Hook their concrete iOS 14 implementations,
    // not only the public abstract classes.
    NSMutableURLRequest *probeRequest = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://chat.signal.org/"]];
    Class requestClass = object_getClass(probeRequest);
    install(requestClass, @"setValue:forHTTPHeaderField:", (IMP)setHeaderValue, (IMP *)&originalSetHeaderValue);
    install(requestClass, @"addValue:forHTTPHeaderField:", (IMP)addHeaderValue, (IMP *)&originalAddHeaderValue);

    NSURLSession *probeSession = NSURLSession.sharedSession;
    Class sessionClass = object_getClass(probeSession);
    install(sessionClass, @"dataTaskWithRequest:", (IMP)dataTaskRequest, (IMP *)&originalDataTaskRequest);
    install(sessionClass, @"dataTaskWithRequest:completionHandler:", (IMP)dataTaskRequestCompletion,
            (IMP *)&originalDataTaskRequestCompletion);
    install(sessionClass, @"uploadTaskWithRequest:fromData:", (IMP)uploadTaskData, (IMP *)&originalUploadTaskData);
    install(sessionClass, @"uploadTaskWithRequest:fromData:completionHandler:", (IMP)uploadTaskDataCompletion,
            (IMP *)&originalUploadTaskDataCompletion);
    install(sessionClass, @"downloadTaskWithRequest:", (IMP)downloadTaskRequest, (IMP *)&originalDownloadTaskRequest);
    install(sessionClass, @"downloadTaskWithRequest:completionHandler:", (IMP)downloadTaskRequestCompletion,
            (IMP *)&originalDownloadTaskRequestCompletion);

    trace("network hooks requestClass=%s sessionClass=%s",
          class_getName(requestClass), class_getName(sessionClass));
}

static NSInteger (*originalStatus)(id, SEL);
static NSInteger responseStatus(id self, SEL sel) {
    NSInteger code = originalStatus(self, sel);
    // Host + status only. Never log paths, credentials, phone numbers or bodies.
    NSString *host = [(NSHTTPURLResponse *)self URL].host.lowercaseString;
    if (code >= 400 && signalServiceHost(host)) {
        @synchronized (NSHTTPURLResponse.class) {
            static NSUInteger count;
            if (count++ < 48) {
                trace("response host=%s status=%ld", (host ?: @"<none>").UTF8String, (long)code);
                NSLog(@"[SignalBypass14] HTTP %ld from %@", (long)code, host);
            }
            lastRequestHost = [host copy];
            lastHTTPStatus = code;
            if (code == 499) sawRemoteExpiry499 = YES;
        }
        if (code == 499) {
            // Signal 7.19 treats 499 as an instruction to permanently expire this local app version.
            // Do not fake a success: preserve an error response, but prevent the secondary update lockout.
            trace("remote-expiry 499 masked as 400 so registration remains retryable");
            return 400;
        }
    }
    return code;
}

typedef id (*AlertFactoryFn)(id, SEL, NSString *, NSString *, UIAlertControllerStyle);
static AlertFactoryFn originalAlertFactory;
static id diagnosticAlertFactory(id self, SEL sel, NSString *title, NSString *message, UIAlertControllerStyle style) {
    BOOL relevant = [title containsString:@"Update Required"] ||
        [message containsString:@"Something went wrong"];
    if (relevant) {
        NSString *summary = diagnosticSummary();
        message = message.length ? [message stringByAppendingFormat:@"\n\n%@", summary] : summary;
    }
    return originalAlertFactory(self, sel, title, message, style);
}

static void installDiagnosticAlertHook(void) {
    Class meta = object_getClass(UIAlertController.class);
    SEL selector = @selector(alertControllerWithTitle:message:preferredStyle:);
    if (meta && class_getInstanceMethod(meta, selector)) {
        hookMessage(meta, selector, (IMP)diagnosticAlertFactory, (IMP *)&originalAlertFactory);
    }
}


static void (*originalAlertViewDidAppear)(id, SEL, BOOL);
static void alertViewDidAppear(id self, SEL sel, BOOL animated) {
    originalAlertViewDidAppear(self, sel, animated);
    UIAlertController *alert = (UIAlertController *)self;
    if (![alert isKindOfClass:UIAlertController.class]) return;
    if (![alert.title containsString:@"Update Required"]) return;
    if ([alert.message containsString:@"SB14 v0.8"]) return;
    NSString *summary = diagnosticSummary();
    alert.message = alert.message.length
        ? [alert.message stringByAppendingFormat:@"\n\n%@", summary]
        : summary;
}

static void installVisibleDiagnosticHook(void) {
    install(UIAlertController.class, @"viewDidAppear:", (IMP)alertViewDidAppear,
            (IMP *)&originalAlertViewDidAppear);
}

static void installConcreteHTTPResponseHook(void) {
    NSHTTPURLResponse *probe = [[NSHTTPURLResponse alloc]
        initWithURL:[NSURL URLWithString:@"https://chat.signal.org/"]
        statusCode:499
        HTTPVersion:@"HTTP/1.1"
        headerFields:@{}];
    Class responseClass = object_getClass(probe);
    install(responseClass, @"statusCode", (IMP)responseStatus, (IMP *)&originalStatus);
    trace("response hook class=%s", class_getName(responseClass));
}

__attribute__((constructor)) static void start(void) {
    startTrace();
    @autoreleasepool {
        trace("reading app metadata");
        NSBundle *main = NSBundle.mainBundle;
        NSString *identifier = main.bundleIdentifier;
        if (![@[@"org.whispersystems.signal", @"org.whispersystems.signal.SignalNSE",
                @"org.whispersystems.signal.shareextension"] containsObject:identifier]) return;
        showInjectionCanary();
        // Capture genuine values before installing any hook.
        struct utsname kernel;
        BOOL isIOS14 = uname(&kernel) == 0 && strncmp(kernel.release, "20.", 3) == 0;
        NSString *installedVersion = [main objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        NSString *installedBuild = [main objectForInfoDictionaryKey:@"CFBundleVersion"];
        trace("kernel iOS14=%d; installed version=%s build=%s", isIOS14, installedVersion.UTF8String, installedBuild.UTF8String);
        BOOL originalMetadata = [installedVersion isEqualToString:@"7.19.1"] && [installedBuild isEqualToString:@"208"];
        BOOL spoofedMetadata = [installedVersion isEqualToString:@"8.29"] && [installedBuild isEqualToString:@"1866"];
        if (!isIOS14 || (!originalMetadata && !spoofedMetadata)) {
            trace("inactive: unsupported OS/app version");
            NSLog(@"[SignalBypass14] Inactive: requires iOS 14 with Signal 7.19.1 (208) or its spoofed 8.29 (1866) metadata");
            return;
        }
        void *provider = dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        hookMessage = (HookMessage)dlsym(provider ?: RTLD_DEFAULT, "MSHookMessageEx");
        hookFunction = (HookFunction)dlsym(provider ?: RTLD_DEFAULT, "MSHookFunction");
        if (!hookMessage || !hookFunction) {
            trace("missing Substrate hook provider: message=%p function=%p", hookMessage, hookFunction);
            NSLog(@"[SignalBypass14] No compatible MSHookMessageEx/MSHookFunction provider");
            return;
        }
        installStartupDiagnostics();
        installSwiftRegistrationHooks();
        installNetworkIdentityHooks();
        installDiagnosticAlertHook();
        installVisibleDiagnosticHook();
        trace("NSProcessInfo OS availability retained; forcing current network identity; installing compatibility hooks");
        Class expiryClass = NSClassFromString(@"SignalServiceKit.AppExpiryImpl");
        if (!expiryClass) expiryClass = objc_getClass("_TtC16SignalServiceKit13AppExpiryImpl");
        install(object_getClass(expiryClass), @"appExpiredStatusCode", (IMP)expiryStatusCode, NULL);
        install(NSBundle.class, @"objectForInfoDictionaryKey:", (IMP)bundleObject, (IMP *)&originalObject);
        install(NSBundle.class, @"infoDictionary", (IMP)bundleInfo, (IMP *)&originalInfo);
        install(UIDevice.class, @"systemVersion", (IMP)deviceVersion, NULL);
        install(NSClassFromString(@"AppExpiry"), @"isExpired", (IMP)notExpired, NULL);
        install(expiryClass, @"isExpired", (IMP)notExpired, NULL);
        installConcreteHTTPResponseHook();
        trace("compatibility hooks installed; constructor returning");
        NSLog(@"[SignalBypass14] v1.0.0 active; %lu pure-Swift registration hooks installed; exact 8.29.0.1866 metadata retained", (unsigned long)swiftHookCount);
    }
}
