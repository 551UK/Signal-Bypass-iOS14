#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static IMP oldUpload = NULL;
static IMP oldUploadCompletion = NULL;
static IMP oldData = NULL;
static IMP oldDataCompletion = NULL;
static IMP oldWebSocketRequest = NULL;
static IMP oldWebSocketURL = NULL;
static IMP oldStatus = NULL;
static NSUInteger seqNo = 0;

static NSString *logPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/SignalMessageTrace16.log"];
}

static NSString *now(void) {
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

static void logLine(NSString *line) {
    if (!line.length) return;
    @synchronized (NSFileHandle.class) {
        NSString *path = logPath();
        NSFileManager *fm = NSFileManager.defaultManager;
        [fm createDirectoryAtPath:path.stringByDeletingLastPathComponent
      withIntermediateDirectories:YES attributes:nil error:nil];
        if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
        NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!h) return;
        @try {
            [h seekToEndOfFile];
            [h writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
            [h synchronizeFile];
        } @catch (__unused NSException *e) {}
        [h closeFile];
    }
}

static NSUInteger nextSeq(void) {
    @synchronized (NSFileHandle.class) { return ++seqNo; }
}

static BOOL signalHost(NSString *host) {
    NSString *h = host.lowercaseString ?: @"";
    return [h isEqualToString:@"signal.org"] ||
           [h hasSuffix:@".signal.org"] ||
           [h hasSuffix:@".whispersystems.org"];
}

static BOOL interesting(NSURL *url) {
    if (!url || !signalHost(url.host)) return NO;
    NSString *p = url.path.lowercaseString ?: @"";
    return [p containsString:@"/v1/messages"] ||
           [p containsString:@"/v2/keys"] ||
           [p containsString:@"/v1/profile"] ||
           [p containsString:@"/v1/certificate/delivery"] ||
           [p containsString:@"/v1/websocket"] ||
           [p containsString:@"/v2/directory/auth"];
}

static NSString *header(NSURLRequest *r, NSString *name) {
    for (NSString *key in r.allHTTPHeaderFields) {
        if ([key caseInsensitiveCompare:name] == NSOrderedSame) return r.allHTTPHeaderFields[key];
    }
    return nil;
}

static NSString *safeURL(NSURL *url) {
    if (!url) return @"<nil>";
    NSURLComponents *c = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSMutableArray<NSURLQueryItem *> *items = [NSMutableArray array];
    for (NSURLQueryItem *i in c.queryItems ?: @[]) {
        [items addObject:[NSURLQueryItem queryItemWithName:i.name value:@"<redacted>"]];
    }
    c.queryItems = items.count ? items : nil;
    return c.string ?: [NSString stringWithFormat:@"%@://%@%@", url.scheme ?: @"?", url.host ?: @"?", url.path ?: @"/"];
}

static void logRequest(NSUInteger seq, NSURLRequest *r, NSString *kind) {
    if (!interesting(r.URL)) return;
    logLine([NSString stringWithFormat:
        @"[%@] [R%03lu] %@ %@ %@\n"
         "URL: %@\n"
         "User-Agent: %@\n"
         "Authorization: %@\n"
         "Unidentified-Access-Key: %@\n"
         "Group-Send-Token: %@\n"
         "Content-Type: %@\n"
         "Accept-Language: %@\n"
         "Body-Bytes: %lu",
        now(), (unsigned long)seq, kind ?: @"REQUEST",
        r.HTTPMethod ?: @"?", r.URL.host ?: @"?",
        safeURL(r.URL),
        header(r, @"User-Agent") ?: @"<missing>",
        header(r, @"Authorization") ? @"present" : @"absent",
        header(r, @"Unidentified-Access-Key") ? @"present" : @"absent",
        header(r, @"Group-Send-Token") ? @"present" : @"absent",
        header(r, @"Content-Type") ?: @"<missing>",
        header(r, @"Accept-Language") ?: @"<missing>",
        (unsigned long)r.HTTPBody.length
    ]);
}

static void logResponse(NSUInteger seq, NSURLRequest *r, NSURLResponse *resp, NSData *data, NSError *err) {
    if (!interesting(r.URL)) return;
    NSInteger status = [resp isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse *)resp).statusCode : -1;
    NSString *ct = @"<missing>";
    NSString *sigts = @"<missing>";
    if ([resp isKindOfClass:NSHTTPURLResponse.class]) {
        NSDictionary *h = ((NSHTTPURLResponse *)resp).allHeaderFields ?: @{};
        for (id k in h) {
            NSString *ks = [k description];
            if ([ks caseInsensitiveCompare:@"Content-Type"] == NSOrderedSame) ct = [h[k] description];
            if ([ks caseInsensitiveCompare:@"X-Signal-Timestamp"] == NSOrderedSame) sigts = [h[k] description];
        }
    }
    logLine([NSString stringWithFormat:
        @"[%@] [R%03lu] RESPONSE HTTP %ld %@\n"
         "URL: %@\n"
         "Error: %@\n"
         "Content-Type: %@\n"
         "X-Signal-Timestamp: %@\n"
         "Response-Bytes: %lu",
        now(), (unsigned long)seq, (long)status, r.URL.host ?: @"?",
        safeURL(r.URL),
        err ? [NSString stringWithFormat:@"%@/%ld", err.domain, (long)err.code] : @"none",
        ct, sigts, (unsigned long)data.length
    ]);
}

typedef NSURLSessionUploadTask *(*UploadFn)(id,SEL,NSURLRequest*,NSData*);
typedef NSURLSessionUploadTask *(*UploadCompletionFn)(id,SEL,NSURLRequest*,NSData*,void (^)(NSData*,NSURLResponse*,NSError*));
typedef NSURLSessionDataTask *(*DataFn)(id,SEL,NSURLRequest*);
typedef NSURLSessionDataTask *(*DataCompletionFn)(id,SEL,NSURLRequest*,void (^)(NSData*,NSURLResponse*,NSError*));
typedef NSURLSessionWebSocketTask *(*WebSocketRequestFn)(id,SEL,NSURLRequest*);
typedef NSURLSessionWebSocketTask *(*WebSocketURLFn)(id,SEL,NSURL*);

static id tracedUpload(id self, SEL _cmd, NSURLRequest *r, NSData *body) {
    NSUInteger s = nextSeq();
    logRequest(s, r, @"UPLOAD");
    UploadFn orig = (void *)oldUpload;
    return orig(self,_cmd,r,body);
}

static id tracedUploadCompletion(id self, SEL _cmd, NSURLRequest *r, NSData *body,
                                 void (^completion)(NSData*,NSURLResponse*,NSError*)) {
    NSUInteger s = nextSeq();
    logRequest(s, r, @"UPLOAD");
    UploadCompletionFn orig = (void *)oldUploadCompletion;
    void (^wrapped)(NSData*,NSURLResponse*,NSError*) = ^(NSData *d, NSURLResponse *resp, NSError *e) {
        logResponse(s, r, resp, d, e);
        if (completion) completion(d,resp,e);
    };
    return orig(self,_cmd,r,body,wrapped);
}

static id tracedData(id self, SEL _cmd, NSURLRequest *r) {
    NSUInteger s = nextSeq();
    logRequest(s, r, @"DATA");
    DataFn orig = (void *)oldData;
    return orig(self,_cmd,r);
}

static id tracedDataCompletion(id self, SEL _cmd, NSURLRequest *r,
                               void (^completion)(NSData*,NSURLResponse*,NSError*)) {
    NSUInteger s = nextSeq();
    logRequest(s, r, @"DATA");
    DataCompletionFn orig = (void *)oldDataCompletion;
    void (^wrapped)(NSData*,NSURLResponse*,NSError*) = ^(NSData *d, NSURLResponse *resp, NSError *e) {
        logResponse(s, r, resp, d, e);
        if (completion) completion(d,resp,e);
    };
    return orig(self,_cmd,r,wrapped);
}

static id tracedWebSocketRequest(id self, SEL _cmd, NSURLRequest *r) {
    NSUInteger s = nextSeq();
    logRequest(s, r, @"WEBSOCKET");
    WebSocketRequestFn orig = (void *)oldWebSocketRequest;
    return orig(self,_cmd,r);
}

static id tracedWebSocketURL(id self, SEL _cmd, NSURL *url) {
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:url];
    r.HTTPMethod = @"GET";
    NSUInteger s = nextSeq();
    logRequest(s, r, @"WEBSOCKET-URL");
    WebSocketURLFn orig = (void *)oldWebSocketURL;
    return orig(self,_cmd,url);
}

static NSInteger tracedStatus(id self, SEL _cmd) {
    NSInteger (*orig)(id,SEL) = (void *)oldStatus;
    NSInteger status = orig(self,_cmd);
    NSURL *url = [self respondsToSelector:@selector(URL)] ? [self URL] : nil;
    if (interesting(url)) {
        logLine([NSString stringWithFormat:@"[%@] RESPONSE-STATUS HTTP %ld URL: %@",
                 now(), (long)status, safeURL(url)]);
    }
    return status;
}

static void hookMethod(Class cls, SEL sel, IMP replacement, IMP *old) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        logLine([NSString stringWithFormat:@"Missing selector %@ on %@", NSStringFromSelector(sel), NSStringFromClass(cls)]);
        return;
    }
    *old = method_setImplementation(m, replacement);
}

__attribute__((constructor)) static void startTracer(void) {
    @autoreleasepool {
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"org.whispersystems.signal"]) return;

        logLine(@"\n============================================================");
        logLine([NSString stringWithFormat:
            @"NEW SIGNAL LAUNCH %@\nSignal Message Tracer iOS16 0.1.0\nApp: %@ (%@)\niOS: %@\n"
             "Read-only tracer. No requests/responses are modified. Credential values and query values are not logged.",
            now(),
            [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?",
            [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"?",
            NSProcessInfo.processInfo.operatingSystemVersionString ?: @"?"
        ]);

        Class sessionClass = [NSURLSession.sharedSession class];
        hookMethod(sessionClass, @selector(uploadTaskWithRequest:fromData:), (IMP)tracedUpload, &oldUpload);
        hookMethod(sessionClass, @selector(uploadTaskWithRequest:fromData:completionHandler:), (IMP)tracedUploadCompletion, &oldUploadCompletion);
        hookMethod(sessionClass, @selector(dataTaskWithRequest:), (IMP)tracedData, &oldData);
        hookMethod(sessionClass, @selector(dataTaskWithRequest:completionHandler:), (IMP)tracedDataCompletion, &oldDataCompletion);
        hookMethod(sessionClass, @selector(webSocketTaskWithRequest:), (IMP)tracedWebSocketRequest, &oldWebSocketRequest);
        hookMethod(sessionClass, @selector(webSocketTaskWithURL:), (IMP)tracedWebSocketURL, &oldWebSocketURL);

        NSHTTPURLResponse *probe = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"https://chat.signal.org/"]
                                                               statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
        hookMethod([probe class], @selector(statusCode), (IMP)tracedStatus, &oldStatus);

        logLine([NSString stringWithFormat:@"Hooks installed: session=%@ response=%@",
                 NSStringFromClass(sessionClass), NSStringFromClass([probe class])]);
    }
}
