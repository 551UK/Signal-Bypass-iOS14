#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static IMP oldUpload = NULL;
static IMP oldData = NULL;
static IMP oldStatus = NULL;

static NSString *logPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/SignalRegistrationTrace.log"];
}

static void logLine(NSString *line) {
    if (!line.length) return;
    @synchronized (NSFileHandle.class) {
        NSString *path = logPath();
        NSFileManager *fm = NSFileManager.defaultManager;
        [fm createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
        if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
        NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!h) return;
        [h seekToEndOfFile];
        [h writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
        [h closeFile];
    }
}

static BOOL wantedURL(NSURL *url) {
    NSString *host = url.host.lowercaseString ?: @"";
    NSString *path = url.path.lowercaseString ?: @"";
    BOOL signal = [host isEqualToString:@"signal.org"] || [host hasSuffix:@".signal.org"] || [host hasSuffix:@".whispersystems.org"];
    return signal && ([path containsString:@"/verification/"] || [path containsString:@"/accounts"]);
}

static NSString *header(NSURLRequest *r, NSString *name) {
    for (NSString *key in r.allHTTPHeaderFields) {
        if ([key caseInsensitiveCompare:name] == NSOrderedSame) return r.allHTTPHeaderFields[key];
    }
    return nil;
}

static void logRequest(NSURLRequest *r) {
    if (!wantedURL(r.URL)) return;
    NSString *ua = header(r, @"User-Agent") ?: @"<missing>";
    NSString *agent = header(r, @"X-Signal-Agent") ?: @"<missing>";
    NSString *type = header(r, @"Content-Type") ?: @"<missing>";
    NSString *lang = header(r, @"Accept-Language") ?: @"<missing>";
    logLine([NSString stringWithFormat:@"REQUEST %@ https://%@%@\nUser-Agent: %@\nX-Signal-Agent: %@\nContent-Type: %@\nAccept-Language: %@\n",
             r.HTTPMethod ?: @"?", r.URL.host ?: @"?", r.URL.path ?: @"/", ua, agent, type, lang]);
}

static id tracedUpload(id self, SEL _cmd, NSURLRequest *request, NSData *data) {
    id (*orig)(id,SEL,NSURLRequest*,NSData*) = (void *)oldUpload;
    id task = orig(self,_cmd,request,data);
    logRequest(request);
    return task;
}

static id tracedData(id self, SEL _cmd, NSURLRequest *request) {
    id (*orig)(id,SEL,NSURLRequest*) = (void *)oldData;
    id task = orig(self,_cmd,request);
    logRequest(request);
    return task;
}

static NSInteger tracedStatus(id self, SEL _cmd) {
    NSInteger (*orig)(id,SEL) = (void *)oldStatus;
    NSInteger status = orig(self,_cmd);
    NSURL *url = [self URL];
    if (wantedURL(url)) {
        logLine([NSString stringWithFormat:@"RESPONSE HTTP %ld https://%@%@\n",
                 (long)status, url.host ?: @"?", url.path ?: @"/"]);
    }
    return status;
}

static void hookMethod(Class cls, SEL sel, IMP replacement, IMP *old) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *old = method_setImplementation(m, replacement);
}

__attribute__((constructor)) static void startTracer(void) {
    @autoreleasepool {
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"org.whispersystems.signal"]) return;
        [@"" writeToFile:logPath() atomically:YES encoding:NSUTF8StringEncoding error:nil];
        logLine([NSString stringWithFormat:@"Signal Registration Tracer 0.1.0\nApp: %@ (%@)\niOS: %@\n",
                 [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?",
                 [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"?",
                 UIDevice.currentDevice.systemVersion ?: @"?"]);

        NSURLSession *session = NSURLSession.sharedSession;
        Class sessionClass = [session class];
        hookMethod(sessionClass, @selector(uploadTaskWithRequest:fromData:), (IMP)tracedUpload, &oldUpload);
        hookMethod(sessionClass, @selector(dataTaskWithRequest:), (IMP)tracedData, &oldData);

        NSHTTPURLResponse *probe = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:@"https://chat.signal.org/"]
                                                               statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
        hookMethod([probe class], @selector(statusCode), (IMP)tracedStatus, &oldStatus);
        logLine([NSString stringWithFormat:@"Hooks installed: session=%@ response=%@", NSStringFromClass(sessionClass), NSStringFromClass([probe class])]);
    }
}
