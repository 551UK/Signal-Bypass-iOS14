#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// v1.4.8: exact v1.4.6 known-good login/banner baseline plus chat websocket only.
// Registration, SPQR, /v1/registration, /v2/keys, REST UA handling, and the
// ExpirationNagView fix are unchanged. This build only modernizes the legacy
// /v1/websocket/ transport used for normal Signal messaging. No CDSI/contact-
// discovery experiment is included.

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

static BOOL isChatServiceRequest(NSURLRequest *request) {
    if (!request) return NO;
    NSString *host = request.URL.host.lowercaseString ?: @"";
    return [host isEqualToString:@"chat.signal.org"];
}

static BOOL isRegistrationRequest(NSURLRequest *request) {
    if (!request || !isSignalHost(request.URL.host)) return NO;

    NSString *path = request.URL.path.lowercaseString ?: @"";

    // Stage 1: phone verification session.
    if ([path containsString:@"/v1/verification/session"]) return YES;

    // Stage 2: after the verification session returns verified=true,
    // Signal creates/re-registers the account here.
    if ([path isEqualToString:@"/v1/registration"]) return YES;

    // Stage 3: authenticated pre-key upload immediately after account creation.
    if ([path isEqualToString:@"/v2/keys"]) return YES;

    return NO;
}

static BOOL isAccountRegistrationRequest(NSURLRequest *request) {
    if (!request || !isSignalHost(request.URL.host)) return NO;
    NSString *path = request.URL.path.lowercaseString ?: @"";
    return [path isEqualToString:@"/v1/registration"];
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
        @"signature", @"kyber", @"recoverypassword", @"registrationid",
        @"accesskey", @"profilekey"
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

static NSData *rewriteAccountRegistrationBody(NSURLRequest *request, NSData *body) {
    if (!isAccountRegistrationRequest(request) || !body.length) return body;

    NSError *error = nil;
    id root = [NSJSONSerialization JSONObjectWithData:body
                                              options:NSJSONReadingMutableContainers
                                                error:&error];
    if (error || ![root isKindOfClass:NSMutableDictionary.class]) return body;

    NSMutableDictionary *json = (NSMutableDictionary *)root;
    id attrsObject = json[@"accountAttributes"];
    if (![attrsObject isKindOfClass:NSMutableDictionary.class]) return body;

    NSMutableDictionary *attrs = (NSMutableDictionary *)attrsObject;
    id capsObject = attrs[@"capabilities"];
    NSMutableDictionary *caps = nil;

    if ([capsObject isKindOfClass:NSMutableDictionary.class]) {
        caps = (NSMutableDictionary *)capsObject;
    } else if ([capsObject isKindOfClass:NSDictionary.class]) {
        caps = [capsObject mutableCopy];
        attrs[@"capabilities"] = caps;
    } else {
        caps = [NSMutableDictionary dictionary];
        attrs[@"capabilities"] = caps;
    }

    // Signal-Server currently requires this capability for new device creation.
    // Change only this one field so we can test the next server-side gate without
    // altering the verified session, account keys, auth, or any response.
    caps[@"spqr"] = @YES;

    NSData *rewritten = [NSJSONSerialization dataWithJSONObject:json options:0 error:&error];
    return (!error && rewritten.length) ? rewritten : body;
}

static NSURLRequest *rewriteRegistrationIdentity(NSURLRequest *request) {
    // Current Signal-Server applies remote client deprecation beyond the
    // registration endpoints. Once the account is created, the old client
    // immediately hits PUT /v2/keys with its old identity and receives 499.
    // Use the same proven identity for every request to the authenticated
    // Signal chat service so we do not have to chase the same version gate
    // endpoint-by-endpoint.
    if (!isChatServiceRequest(request)) return request;

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
    NSData *finalData = rewriteAccountRegistrationBody(rewritten, data);
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, finalData);
    if (isAccountRegistrationRequest(rewritten) && finalData != data) {
        appendTrace([NSString stringWithFormat:@"[%@] [R%03lu] Injected-Capability: spqr=true",
                     timestamp(), (unsigned long)sequence]);
    }
    return originalUploadData(self, sel, rewritten, finalData);
}

static NSURLSessionUploadTask *uploadDataCompletion(id self, SEL sel, NSURLRequest *request, NSData *data,
                                                     void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    NSURLRequest *rewritten = rewriteRegistrationIdentity(request);
    NSData *finalData = rewriteAccountRegistrationBody(rewritten, data);
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, finalData);
    if (isAccountRegistrationRequest(rewritten) && finalData != data) {
        appendTrace([NSString stringWithFormat:@"[%@] [R%03lu] Injected-Capability: spqr=true",
                     timestamp(), (unsigned long)sequence]);
    }

    void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
    ^(NSData *responseData, NSURLResponse *response, NSError *error) {
        logResponse(sequence, rewritten, response, responseData, error);
        if (completion) completion(responseData, response, error);
    };

    return originalUploadDataCompletion(self, sel, rewritten, finalData, wrapped);
}

static NSURLSessionDataTask *dataRequest(id self, SEL sel, NSURLRequest *request) {
    NSURLRequest *rewritten = rewriteRegistrationIdentity(request);
    if (isAccountRegistrationRequest(rewritten) && rewritten.HTTPBody.length) {
        NSData *body = rewriteAccountRegistrationBody(rewritten, rewritten.HTTPBody);
        if (body != rewritten.HTTPBody) {
            NSMutableURLRequest *copy = [rewritten mutableCopy];
            copy.HTTPBody = body;
            rewritten = copy;
        }
    }
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, rewritten.HTTPBody);
    return originalDataRequest(self, sel, rewritten);
}

static NSURLSessionDataTask *dataRequestCompletion(id self, SEL sel, NSURLRequest *request,
                                                    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    NSURLRequest *rewritten = rewriteRegistrationIdentity(request);
    if (isAccountRegistrationRequest(rewritten) && rewritten.HTTPBody.length) {
        NSData *body = rewriteAccountRegistrationBody(rewritten, rewritten.HTTPBody);
        if (body != rewritten.HTTPBody) {
            NSMutableURLRequest *copy = [rewritten mutableCopy];
            copy.HTTPBody = body;
            rewritten = copy;
        }
    }
    NSUInteger sequence = nextTraceSequence();
    logRequest(sequence, request, rewritten, rewritten.HTTPBody);

    void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
    ^(NSData *responseData, NSURLResponse *response, NSError *error) {
        logResponse(sequence, rewritten, response, responseData, error);
        if (completion) completion(responseData, response, error);
    };

    return originalDataRequestCompletion(self, sel, rewritten, wrapped);
}


typedef NSURLSessionWebSocketTask *(*WebSocketURLFn)(id, SEL, NSURL *);
typedef NSURLSessionWebSocketTask *(*WebSocketRequestFn)(id, SEL, NSURLRequest *);

static WebSocketURLFn originalWebSocketURL;
static WebSocketRequestFn originalWebSocketRequest;

static BOOL isLegacyChatWebSocketURL(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString ?: @"";
    NSString *path = url.path.lowercaseString ?: @"";
    BOOL chatHost = [host isEqualToString:@"chat.signal.org"] ||
                    [host isEqualToString:@"ud-chat.signal.org"];
    BOOL chatPath = [path isEqualToString:@"/v1/websocket"] ||
                    [path isEqualToString:@"/v1/websocket/"];
    return chatHost && chatPath;
}

static void copySessionHeaders(id sessionObject, NSMutableURLRequest *request) {
    if (![sessionObject isKindOfClass:NSURLSession.class]) return;

    NSDictionary *headers = ((NSURLSession *)sessionObject).configuration.HTTPAdditionalHeaders;
    if (![headers isKindOfClass:NSDictionary.class]) return;

    [headers enumerateKeysAndObjectsUsingBlock:^(id keyObject, id valueObject, BOOL *stop) {
        NSString *key = [keyObject description];
        NSString *value = [valueObject description];
        if (key.length && value.length) {
            [request setValue:value forHTTPHeaderField:key];
        }
    }];
}

static NSMutableURLRequest *modernizeChatWebSocket(id sessionObject,
                                                    NSURLRequest *sourceRequest,
                                                    NSURL *sourceURL) {
    NSURL *url = sourceRequest.URL ?: sourceURL;
    if (!isLegacyChatWebSocketURL(url)) return nil;

    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!components) return nil;

    NSString *originalHost = components.host.lowercaseString ?: @"";
    BOOL movedUdHost = NO;

    // Signal 7.19.1 has a separate anonymous socket at ud-chat.signal.org.
    // That hostname is retired; current Signal uses the unified chat service.
    if ([originalHost isEqualToString:@"ud-chat.signal.org"]) {
        components.host = @"chat.signal.org";
        movedUdHost = YES;
    }

    NSString *login = nil;
    NSString *password = nil;
    NSMutableArray<NSURLQueryItem *> *remaining = [NSMutableArray array];

    for (NSURLQueryItem *item in components.queryItems ?: @[]) {
        NSString *name = item.name.lowercaseString;
        if ([name isEqualToString:@"login"]) {
            login = item.value;
            continue;
        }
        if ([name isEqualToString:@"password"]) {
            password = item.value;
            continue;
        }
        [remaining addObject:item];
    }

    BOOL hadLegacyQueryAuth = login.length || password.length;
    components.queryItems = remaining.count ? remaining : nil;

    NSURL *finalURL = components.URL ?: url;
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:finalURL];
    request.HTTPMethod = sourceRequest.HTTPMethod ?: @"GET";

    // Old Signal moves websocket headers to URLSessionConfiguration because it
    // normally creates the task from URL only. Preserve those headers first.
    copySessionHeaders(sessionObject, request);

    for (NSString *key in sourceRequest.allHTTPHeaderFields ?: @{}) {
        NSString *value = sourceRequest.allHTTPHeaderFields[key];
        if (key.length && value.length) {
            [request setValue:value forHTTPHeaderField:key];
        }
    }

    // Use the same server-facing identity that is already proven for the REST
    // registration/key-upload path.
    [request setValue:workingUserAgent forHTTPHeaderField:@"User-Agent"];

    // Current Signal-Server authenticates the identified websocket with HTTP
    // Basic Authorization rather than login/password URL query parameters.
    if (login.length && password.length) {
        NSString *credentials = [NSString stringWithFormat:@"%@:%@", login, password];
        NSData *credentialData = [credentials dataUsingEncoding:NSUTF8StringEncoding];
        NSString *encoded = [credentialData base64EncodedStringWithOptions:0];
        if (encoded.length) {
            [request setValue:[@"Basic " stringByAppendingString:encoded]
           forHTTPHeaderField:@"Authorization"];
        }
    }

    appendTrace([NSString stringWithFormat:
        @"[%@] CHAT-WEBSOCKET host=%@->%@ path=%@ auth=%@ ua=8.29",
        timestamp(),
        originalHost.length ? originalHost : @"?",
        finalURL.host ?: @"?",
        finalURL.path ?: @"/",
        (login.length && password.length) ? @"query->basic" :
            (hadLegacyQueryAuth ? @"incomplete-query" : @"anonymous")
    ]);

    return request;
}

static NSURLSessionWebSocketTask *webSocketRequestTask(id self, SEL sel, NSURLRequest *request) {
    NSMutableURLRequest *rewritten = modernizeChatWebSocket(self, request, nil);
    return originalWebSocketRequest(self, sel, rewritten ?: request);
}

static NSURLSessionWebSocketTask *webSocketURLTask(id self, SEL sel, NSURL *url) {
    if (isLegacyChatWebSocketURL(url) && originalWebSocketRequest) {
        NSMutableURLRequest *rewritten = modernizeChatWebSocket(self, nil, url);
        if (rewritten) {
            // Build this websocket from a request so the Authorization and
            // corrected User-Agent headers reach the upgrade request.
            return originalWebSocketRequest(self, @selector(webSocketTaskWithRequest:), rewritten);
        }
    }
    return originalWebSocketURL(self, sel, url);
}

typedef void (*SetHiddenFn)(id, SEL, BOOL);
static SetHiddenFn originalExpirationNagSetHidden;

static void expirationNagSetHidden(id self, SEL sel, BOOL hidden) {
    // ExpirationNagView is the local reminder used for both app/OS expiry.
    // v1.4.8 only prevents this reminder view from becoming visible; it does
    // not spoof UIDevice/iOS globally and does not touch any login/network state.
    if (originalExpirationNagSetHidden) {
        originalExpirationNagSetHidden(self, sel, YES);
    }
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
            @"NEW SIGNAL LAUNCH %@\nSignalBypass14 v1.4.8 registration trace\nApp: %@ (%@)\niOS: %@\nBaseline: v1.4.6 registration/banner behavior preserved. Added chat /v1/websocket/ compatibility only.\nSensitive values are redacted.\n",
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

        install(sessionClass,
                @selector(webSocketTaskWithRequest:),
                (IMP)webSocketRequestTask,
                (IMP *)&originalWebSocketRequest);

        install(sessionClass,
                @selector(webSocketTaskWithURL:),
                (IMP)webSocketURLTask,
                (IMP *)&originalWebSocketURL);

        appendTrace([NSString stringWithFormat:
            @"Chat websocket hooks: URL=%@ request=%@.",
            originalWebSocketURL ? @"yes" : @"no",
            originalWebSocketRequest ? @"yes" : @"no"
        ]);

        // Signal 7.19.1 runtime name confirmed from the actual IPA:
        // _TtC6Signal17ExpirationNagView / Signal.ExpirationNagView.
        Class expirationNagClass = NSClassFromString(@"Signal.ExpirationNagView");
        if (!expirationNagClass) expirationNagClass = NSClassFromString(@"ExpirationNagView");

        if (expirationNagClass && class_getInstanceMethod(expirationNagClass, @selector(setHidden:))) {
            install(expirationNagClass,
                    @selector(setHidden:),
                    (IMP)expirationNagSetHidden,
                    (IMP *)&originalExpirationNagSetHidden);
            appendTrace([NSString stringWithFormat:@"OS expiry banner hidden via %@.", NSStringFromClass(expirationNagClass)]);
        } else {
            appendTrace(@"ExpirationNagView class not found; banner hook not installed.");
        }

        appendTrace([NSString stringWithFormat:@"Hooks installed on %@.", NSStringFromClass(sessionClass)]);
    }
}
