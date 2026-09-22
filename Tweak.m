#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// v1.4.0: minimal registration User-Agent fix.
//
// The successful iOS 16 trace showed:
//   POST https://chat.signal.org/v1/verification/session
//   User-Agent: Signal-iOS/8.29.0.1866 iOS/16.2
//   HTTP 200
//
// The failing iOS 14 capture showed the same endpoint receiving the genuine
// 7.19.1/iOS 14 identity and returning HTTP 499.
//
// This build therefore avoids the crash-prone pure-Swift expiry hooks from
// v1.3.0 and changes only the final NSURLSession request immediately before
// Signal sends registration traffic.

typedef void (*HookMessage)(Class, SEL, IMP, IMP *);
static HookMessage hookMessage;

static NSString *const workingUserAgent = @"Signal-iOS/8.29.0.1866 iOS/16.2";

static BOOL isSignalHost(NSString *host) {
    NSString *h = host.lowercaseString ?: @"";
    return [h isEqualToString:@"signal.org"] ||
           [h hasSuffix:@".signal.org"] ||
           [h hasSuffix:@".whispersystems.org"];
}

static BOOL isRegistrationRequest(NSURLRequest *request) {
    if (!request || !isSignalHost(request.URL.host)) return NO;
    NSString *path = request.URL.path.lowercaseString ?: @"";
    return [path containsString:@"/v1/verification/session"];
}

static NSURLRequest *rewriteRegistrationIdentity(NSURLRequest *request) {
    if (!isRegistrationRequest(request)) return request;

    NSMutableURLRequest *copy = [request mutableCopy];
    [copy setValue:workingUserAgent forHTTPHeaderField:@"User-Agent"];

    // Keep every other header, method, URL and body byte-for-byte as Signal
    // created them. The working iOS 16 trace showed X-Signal-Agent is absent
    // on the initial verification-session request, so this tweak does not add it.
    return copy;
}

typedef NSURLSessionUploadTask *(*UploadDataFn)(id, SEL, NSURLRequest *, NSData *);
typedef NSURLSessionUploadTask *(*UploadDataCompletionFn)(id, SEL, NSURLRequest *, NSData *,
                                                           void (^)(NSData *, NSURLResponse *, NSError *));
typedef NSURLSessionDataTask *(*DataRequestFn)(id, SEL, NSURLRequest *);
typedef NSURLSessionDataTask *(*DataRequestCompletionFn)(id, SEL, NSURLRequest *,
                                                         void (^)(NSData *, NSURLResponse *, NSError *));

static UploadDataFn originalUploadData;
static UploadDataCompletionFn originalUploadDataCompletion;
static DataRequestFn originalDataRequest;
static DataRequestCompletionFn originalDataRequestCompletion;

static NSURLSessionUploadTask *uploadData(id self, SEL sel, NSURLRequest *request, NSData *data) {
    return originalUploadData(self, sel, rewriteRegistrationIdentity(request), data);
}

static NSURLSessionUploadTask *uploadDataCompletion(id self, SEL sel, NSURLRequest *request, NSData *data,
                                                     void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    return originalUploadDataCompletion(self, sel, rewriteRegistrationIdentity(request), data, completion);
}

static NSURLSessionDataTask *dataRequest(id self, SEL sel, NSURLRequest *request) {
    return originalDataRequest(self, sel, rewriteRegistrationIdentity(request));
}

static NSURLSessionDataTask *dataRequestCompletion(id self, SEL sel, NSURLRequest *request,
                                                    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    return originalDataRequestCompletion(self, sel, rewriteRegistrationIdentity(request), completion);
}

static void install(Class cls, SEL selector, IMP replacement, IMP *original) {
    if (!hookMessage || !cls) return;
    if (!class_getInstanceMethod(cls, selector)) return;
    hookMessage(cls, selector, replacement, original);
}

__attribute__((constructor)) static void start(void) {
    @autoreleasepool {
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"org.whispersystems.signal"]) return;

        void *provider = dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        hookMessage = (HookMessage)dlsym(provider ?: RTLD_DEFAULT, "MSHookMessageEx");
        if (!hookMessage) return;

        // Signal 7.19.1's OWSURLSession uses NSURLSession uploadTaskWithRequest:
        // fromData: for registration. Hook the concrete Foundation session class
        // so the User-Agent is replaced after Signal has finished preparing the
        // request, not earlier where AppVersion can overwrite it again.
        Class sessionClass = [NSURLSession.sharedSession class];

        install(sessionClass,
                @selector(uploadTaskWithRequest:fromData:),
                (IMP)uploadData,
                (IMP *)&originalUploadData);

        install(sessionClass,
                @selector(uploadTaskWithRequest:fromData:completionHandler:),
                (IMP)uploadDataCompletion,
                (IMP *)&originalUploadDataCompletion);

        install(sessionClass,
                @selector(dataTaskWithRequest:),
                (IMP)dataRequest,
                (IMP *)&originalDataRequest);

        install(sessionClass,
                @selector(dataTaskWithRequest:completionHandler:),
                (IMP)dataRequestCompletion,
                (IMP *)&originalDataRequestCompletion);
    }
}
