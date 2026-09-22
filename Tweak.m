#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// v1.4.3: keep the verified v1.4.x verification-session User-Agent rewrite,
// extend the exact same final rewrite to POST /v1/registration after the
// SMS code has been accepted, and preserve sanitized logs across launches.

typedef void (*HookMessage)(Class, SEL, IMP, IMP *);
static HookMessage hookMessage;

static NSString *const workingUserAgent = @"Signal-iOS/8.29.0.1866 iOS/16.2";
static NSUInteger gTraceSequence = 0;

static NSUInteger nextTraceSequence(void) {
    @synchronized (NSFileHandle.class) {
        return ++gTraceSequence;
    }
}

static NSString *tracePath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/SignalBypass14-Registration.log"];
}

static void appendTrace(NSString *text) {
    if (!text.length) return;
    @synchronized (NSFileHandle.class) {
        NSString *path = tracePath();
        NSFileManager *fm = NSFileManager.defaultManager;
        [fm createDirectoryAtPath:path.stringByDeletingLastPathComponent
      withIntermediateDirectories:YES attributes:nil error:nil];
        if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
        NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!h) return;
        @try {
            [h seekToEndOfFile];
            [h writeData:[[text stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
            [h synchronizeFile];
        } @catch (__unused NSException *e) {}
        [h closeFile];
    }
}

static NSString *timestamp(void) {
    static NSDateFormatter *f;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        f = [NSDateFormatter new];
        f.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        f.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
        f.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    });
    return [f stringFromDate:[NSDate date]];
}

static BOOL isSignalHost(NSString *host) {
    NSString *h = host.lowercaseString ?: @"";
    return [h isEqualToString:@"signal.org"] ||
           [h hasSuffix:@".signal.org"] ||
           [h hasSuffix:@".whispersystems.org"];
}

static BOOL isRegistrationRequest(NSURLRequest *request) {
    if (!request || !isSignalHost(request.URL.host)) return NO;

    NSString *path = request.URL.path.lowercaseString ?: @"";

    // Stage 1: phone verification session.
    if ([path containsString:@"/v1/verification/session"]) return YES;

    // Stage 2: after the verification session returns verified=true,
    // Signal creates/re-registers the account here.
    if ([path isEqualToString:@"/v1/registration"]) return YES;

    return NO;
}

static NSString *safePath(NSURL *url) {
    NSArray<NSString *> *parts = [url.path componentsSeparatedByString:@"/"];
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithCapacity:parts.count];
    BOOL redactNext = NO;
    for (NSString *part in parts) {
        if (!part.length) { [out addObject:part]; continue; }
        if (redactNext) {
            [out addObject:@"<session>"];
            redactNext = NO;
            continue;
        }
        [out addObject:part];
        if ([part isEqualToString:@"session"]) redactNext = YES;
    }
    return [out componentsJoinedByString:@"/"];
}

static BOOL sensitiveKey(NSString *key) {
    NSString *k = key.lowercaseString;
    if ([k isEqualToString:@"id"] || [k isEqualToString:@"number"] ||
        [k isEqualToString:@"e164"] || [k isEqualToString:@"code"] ||
        [k isEqualToString:@"aci"] || [k isEqualToString:@"pni"] ||
        [k isEqualToString:@"uuid"] || [k isEqualToString:@"username"]) return YES;

    NSArray<NSString *> *needles = @[
        @"token", @"password", @"credential", @"authorization", @"auth",
        @"sessionid", @"session_id", @"verificationcode", @"captcha",
        @"pushchallenge", @"secret", @"identity", @"prekey", @"publickey",
        @"signature", @"kyber", @"recoverypassword", @"registrationid"
    ];
    for (NSString *n in needles) if ([k containsString:n]) return YES;
    return NO;
}

static id sanitizeJSON(id obj) {
    if ([obj isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *d = [NSMutableDictionary dictionary];
        [(NSDictionary *)obj enumerateKeysAndObjectsUsingBlock:^(id keyObj, id value, BOOL *stop) {
            NSString *key = [keyObj description];
            d[key] = sensitiveKey(key) ? @"<redacted>" : (sanitizeJSON(value) ?: [NSNull null]);
        }];
        return d;
    }
    if ([obj isKindOfClass:NSArray.class]) {
        NSMutableArray *a = [NSMutableArray array];
        for (id value in (NSArray *)obj) [a addObject:sanitizeJSON(value) ?: [NSNull null]];
        return a;
    }
    if ([obj isKindOfClass:NSString.class]) {
        NSString *s = obj;
        if (s.length > 160) return [NSString stringWithFormat:@"<string %lu chars>", (unsigned long)s.length];
        return s;
    }
    return obj ?: [NSNull null];
}

static NSString *safeBody(NSData *data) {
    if (!data.length) return @"<none>";
    if (data.length > 131072) return [NSString stringWithFormat:@"<%lu bytes omitted>", (unsigned long)data.length];

    NSError *error = nil;
    id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (!json || error) return [NSString stringWithFormat:@"<non-JSON %lu bytes>", (unsigned long)data.length];

    id clean = sanitizeJSON(json);
    NSData *pretty = [NSJSONSerialization dataWithJSONObject:clean options:NSJSONWritingPrettyPrinted error:nil];
    return pretty ? [[NSString alloc] initWithData:pretty encoding:NSUTF8StringEncoding] : @"<JSON unavailable>";
}

static NSString *headerValue(NSURLRequest *request, NSString *wanted) {
    for (NSString *key in request.allHTTPHeaderFields) {
        if ([key caseInsensitiveCompare:wanted] == NSOrderedSame) {
            return request.allHTTPHeaderFields[key];
        }
    }
    return nil;
}

static NSString *responseHeaders(NSURLResponse *response) {
    if (![response isKindOfClass:NSHTTPURLResponse.class]) return @"<not HTTP>";

    NSDictionary *headers = ((NSHTTPURLResponse *)response).allHeaderFields ?: @{};
    NSMutableDictionary *selected = [NSMutableDictionary dictionary];

    for (NSString *wanted in @[@"Content-Type", @"X-Signal-Timestamp", @"Retry-After", @"Cache-Control"]) {
        for (id keyObj in headers) {
            NSString *key = [keyObj description];
            if ([key caseInsensitiveCompare:wanted] == NSOrderedSame) {
                selected[wanted] = [headers[keyObj] description];
                break;
            }
        }
    }
    return selected.description;
}

static NSURLRequest *rewriteRegistrationIdentity(NSURLRequest *request) {
    if (!isRegistrationRequest(request)) return request;

    NSMutableURLRequest *copy = [request mutableCopy];
    [copy setValue:workingUserAgent forHTTPHeaderField:@"User-Agent"];
    return copy;
}

static void logRequest(NSUInteger sequence,
                       NSURLRequest *original,
                       NSURLRequest *finalRequest,
                       NSData *body) {
    if (!isRegistrationRequest(finalRequest)) return;

    appendTrace([NSString stringWithFormat:
        @"[%@] [R%03lu] REQUEST %@ https://%@%@\n"
         "Original-User-Agent: %@\n"
         "Final-User-Agent: %@\n"
         "X-Signal-Agent: %@\n"
         "Content-Type: %@\n"
         "Accept-Language: %@\n"
         "Body: %@",
        timestamp(),
        (unsigned long)sequence,
        finalRequest.HTTPMethod ?: @"?",
        finalRequest.URL.host ?: @"?",
        safePath(finalRequest.URL),
        headerValue(original, @"User-Agent") ?: @"<missing>",
        headerValue(finalRequest, @"User-Agent") ?: @"<missing>",
        headerValue(finalRequest, @"X-Signal-Agent") ?: @"<missing>",
        headerValue(finalRequest, @"Content-Type") ?: @"<missing>",
        headerValue(finalRequest, @"Accept-Language") ?: @"<missing>",
        safeBody(body ?: finalRequest.HTTPBody)
    ]);
}

static void logResponse(NSUInteger sequence,
                        NSURLRequest *request,
                        NSURLResponse *response,
                        NSData *data,
                        NSError *error) {
    if (!isRegistrationRequest(request)) return;

    NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class]
        ? ((NSHTTPURLResponse *)response).statusCode : -1;

    NSString *err = error
        ? [NSString stringWithFormat:@"%@/%ld", error.domain, (long)error.code]
        : @"none";

    appendTrace([NSString stringWithFormat:
        @"[%@] [R%03lu] RESPONSE HTTP %ld https://%@%@ error=%@\n"
         "Headers: %@\n"
         "Body: %@\n",
        timestamp(),
        (unsigned long)sequence,
        (long)status,
        request.URL.host ?: @"?",
        safePath(request.URL),
        err,
        responseHeaders(response),
        safeBody(data)
    ]);
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
    NSURLRequest *rewritten = rewriteRegistrationIdentity(request);
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, data);
    return originalUploadData(self, sel, rewritten, data);
}

static NSURLSessionUploadTask *uploadDataCompletion(id self, SEL sel, NSURLRequest *request, NSData *data,
                                                     void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    NSURLRequest *rewritten = rewriteRegistrationIdentity(request);
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, data);

    void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
    ^(NSData *responseData, NSURLResponse *response, NSError *error) {
        logResponse(sequence, rewritten, response, responseData, error);
        if (completion) completion(responseData, response, error);
    };

    return originalUploadDataCompletion(self, sel, rewritten, data, wrapped);
}

static NSURLSessionDataTask *dataRequest(id self, SEL sel, NSURLRequest *request) {
    NSURLRequest *rewritten = rewriteRegistrationIdentity(request);
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, rewritten.HTTPBody);
    return originalDataRequest(self, sel, rewritten);
}

static NSURLSessionDataTask *dataRequestCompletion(id self, SEL sel, NSURLRequest *request,
                                                    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    NSURLRequest *rewritten = rewriteRegistrationIdentity(request);
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, rewritten.HTTPBody);

    void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
    ^(NSData *responseData, NSURLResponse *response, NSError *error) {
        logResponse(sequence, rewritten, response, responseData, error);
        if (completion) completion(responseData, response, error);
    };

    return originalDataRequestCompletion(self, sel, rewritten, wrapped);
}

static void install(Class cls, SEL selector, IMP replacement, IMP *original) {
    if (!hookMessage || !cls) return;
    if (!class_getInstanceMethod(cls, selector)) return;
    hookMessage(cls, selector, replacement, original);
}

__attribute__((constructor)) static void start(void) {
    @autoreleasepool {
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"org.whispersystems.signal"]) return;

        appendTrace(@"\n============================================================");
        appendTrace([NSString stringWithFormat:
            @"NEW SIGNAL LAUNCH %@\nSignalBypass14 v1.4.3 registration trace\nApp: %@ (%@)\niOS: %@\nExpected flow: POST session -> PATCH session -> POST /code -> PUT /code -> POST /v1/registration.\nSensitive values are redacted.\n",
            timestamp(),
            [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?",
            [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"?",
            NSProcessInfo.processInfo.operatingSystemVersionString ?: @"?"
        ]);

        void *provider = dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        hookMessage = (HookMessage)dlsym(provider ?: RTLD_DEFAULT, "MSHookMessageEx");
        if (!hookMessage) {
            appendTrace(@"MSHookMessageEx unavailable.");
            return;
        }

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

        appendTrace([NSString stringWithFormat:@"Hooks installed on %@.", NSStringFromClass(sessionClass)]);
    }
}
