#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <unistd.h>
#import <string.h>

// v1.5.7: v1.5.6 proves /v2/config itself is reachable (HTTP 200), but the
// old app still retries config/directory auth and never creates a CDSI websocket.
// The v2->legacy response adapter was not reached on-device. Force the exact
// RemoteConfig.cdsiLookupWithLibsignal getter to false at runtime (Swift symbol
// hook plus Objective-C fallback), and make v2 config response translation key
// only off the final request path so nested NSURLSession rewriting cannot miss it.

typedef void (*HookMessage)(Class, SEL, IMP, IMP *);
typedef void (*HookFunction)(void *, void *, void **);
static HookMessage hookMessage;
static HookFunction hookFunction;

static NSString *const workingUserAgent = @"Signal-iOS/8.29.0.1866 iOS/16.2";

// Signal 7.19.1's stale CDSI enclave measurement and the value bundled by
// Signal 8.29. This patch previously matched one occurrence in SignalServiceKit.
static const char *oldCdsiMrEnclave = "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57";
static const char *newCdsiMrEnclave = "15637fa1e54fe655176d3df1a9f94b87c01ed377acaa570682dc5d72c95ef07b";

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

static NSString *safeNetworkPath(NSURL *url) {
    if (!url) return @"?";

    NSArray<NSString *> *parts = [url.path componentsSeparatedByString:@"/"];
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithCapacity:parts.count];

    NSSet<NSString *> *alwaysKeep = [NSSet setWithArray:@[
        @"", @"v1", @"v2", @"v3", @"v4", @"api", @"queue", @"empty",
        @"messages", @"keys", @"profile", @"devices", @"accounts", @"certificate",
        @"delivery", @"attachments", @"form", @"upload", @"verification",
        @"session", @"code", @"registration", @"usernames", @"discovery",
        @"multi_recipient", @"spam", @"challenge", @"config"
    ]];

    BOOL redactNext = NO;
    NSString *previous = nil;

    for (NSString *part in parts) {
        if (!part.length) {
            [out addObject:part];
            previous = part;
            continue;
        }

        NSString *lower = part.lowercaseString;
        BOOL looksSensitive = NO;

        if (redactNext) {
            looksSensitive = YES;
            redactNext = NO;
        } else if ([part hasPrefix:@"+"] ||
                   part.length >= 24 ||
                   [lower containsString:@"="]) {
            looksSensitive = YES;
        }

        if (looksSensitive && ![alwaysKeep containsObject:lower]) {
            [out addObject:@"<id>"];
        } else {
            [out addObject:part];
        }

        if ([lower isEqualToString:@"messages"] ||
            [lower isEqualToString:@"profile"] ||
            [lower isEqualToString:@"usernames"]) {
            redactNext = YES;
        }

        previous = part;
        (void)previous;
    }

    return [out componentsJoinedByString:@"/"];
}

static void logHttpRequestMetadata(NSURLRequest *request, NSData *body) {
    if (!request || !isSignalHost(request.URL.host)) return;
    appendTrace([NSString stringWithFormat:
        @"[%@] HTTP-REQUEST %@ host=%@ path=%@ bodyBytes=%lu",
        timestamp(),
        request.HTTPMethod ?: @"?",
        request.URL.host ?: @"?",
        safeNetworkPath(request.URL),
        (unsigned long)(body ?: request.HTTPBody).length]);
}

static void logHttpResponseMetadata(NSURLRequest *request,
                                    NSURLResponse *response,
                                    NSError *error) {
    if (!request || !isSignalHost(request.URL.host)) return;

    NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class]
        ? ((NSHTTPURLResponse *)response).statusCode : -1;

    appendTrace([NSString stringWithFormat:
        @"[%@] HTTP-RESPONSE %@ host=%@ path=%@ status=%ld error=%@",
        timestamp(),
        request.HTTPMethod ?: @"?",
        request.URL.host ?: @"?",
        safeNetworkPath(request.URL),
        (long)status,
        error ? [NSString stringWithFormat:@"%@/%ld", error.domain, (long)error.code] : @"none"]);
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


static BOOL isLegacyRemoteConfigRequest(NSURLRequest *request) {
    if (!request || !isChatServiceRequest(request)) return NO;
    NSString *path = request.URL.path.lowercaseString ?: @"";
    return [path isEqualToString:@"/v1/config"] || [path isEqualToString:@"/v1/config/"];
}

static BOOL isModernRemoteConfigRequest(NSURLRequest *request) {
    if (!request || !isChatServiceRequest(request)) return NO;
    NSString *path = request.URL.path.lowercaseString ?: @"";
    return [path isEqualToString:@"/v2/config"] || [path isEqualToString:@"/v2/config/"];
}

static NSData *legacyRemoteConfigResponseData(void) {
    // Signal 7.19.1 expects the old array-based remote-config schema. We only
    // provide flags needed to keep its supported network stacks on compatible
    // code paths. In particular, native CDSI uses the patched MrEnclave below.
    NSArray *config = @[
        @{@"name": @"ios.cdsiLookup.libsignal", @"enabled": @NO},
        @{@"name": @"ios.experimentalTransportEnabled.libsignal", @"enabled": @NO},
        @{@"name": @"ios.experimentalTransportEnabled.libsignalAuth", @"enabled": @NO},
        @{@"name": @"ios.experimentalTransportEnabled.shadowing", @"enabled": @NO}
    ];
    NSDictionary *root = @{
        @"config": config,
        @"serverEpochTime": @((unsigned long long)[NSDate date].timeIntervalSince1970)
    };
    return [NSJSONSerialization dataWithJSONObject:root options:0 error:nil];
}

static NSData *rewriteRemoteConfigResponseData(NSURLRequest *originalRequest,
                                               NSURLRequest *finalRequest,
                                               NSData *responseData,
                                               NSURLResponse *response,
                                               NSError *error) {
    if (!isModernRemoteConfigRequest(finalRequest) ||
        error ||
        ![response isKindOfClass:NSHTTPURLResponse.class] ||
        ((NSHTTPURLResponse *)response).statusCode != 200) {
        return responseData;
    }

    NSData *legacy = legacyRemoteConfigResponseData();
    if (legacy.length) {
        appendTrace([NSString stringWithFormat:
            @"[%@] REMOTE-CONFIG translated v2->legacy; cdsiLibsignal=0 chatLibsignal=0 shadowing=0",
            timestamp()]);
        return legacy;
    }
    return responseData;
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

    // Signal 7.19.1 still asks for /v1/config/, which is retired and now returns
    // 404. Modern clients use /v2/config/. The response is translated back to
    // the old schema in our NSURLSession completion hook.
    if (isLegacyRemoteConfigRequest(request)) {
        NSURLComponents *components =
            [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
        if (components) {
            components.path = @"/v2/config/";
            components.query = nil;
            if (components.URL) copy.URL = components.URL;
        }
    }

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


static NSUInteger patchCStringInLoadedImage(const char *imageNeedle,
                                             const char *oldText,
                                             const char *newText) {
    if (!imageNeedle || !oldText || !newText) return 0;

    const size_t oldLength = strlen(oldText);
    const size_t newLength = strlen(newText);
    if (!oldLength || oldLength != newLength) return 0;

    NSUInteger patchCount = 0;
    const uint32_t imageCount = _dyld_image_count();

    for (uint32_t imageIndex = 0; imageIndex < imageCount; imageIndex++) {
        const char *imageName = _dyld_get_image_name(imageIndex);
        if (!imageName || !strstr(imageName, imageNeedle)) continue;

        const struct mach_header *rawHeader = _dyld_get_image_header(imageIndex);
        if (!rawHeader || rawHeader->magic != MH_MAGIC_64) continue;

        const struct mach_header_64 *header = (const struct mach_header_64 *)rawHeader;
        const intptr_t slide = _dyld_get_image_vmaddr_slide(imageIndex);
        const uint8_t *commandCursor = (const uint8_t *)(header + 1);

        for (uint32_t commandIndex = 0; commandIndex < header->ncmds; commandIndex++) {
            const struct load_command *loadCommand = (const struct load_command *)commandCursor;

            if (loadCommand->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *segment =
                    (const struct segment_command_64 *)loadCommand;

                if (!strcmp(segment->segname, "__TEXT") && segment->filesize >= oldLength) {
                    uint8_t *segmentStart =
                        (uint8_t *)(uintptr_t)(segment->vmaddr + (uint64_t)slide);
                    const size_t segmentLength = (size_t)segment->filesize;

                    for (size_t offset = 0; offset + oldLength <= segmentLength; offset++) {
                        uint8_t *candidate = segmentStart + offset;
                        if (memcmp(candidate, oldText, oldLength) != 0) continue;

                        const vm_size_t pageSize = (vm_size_t)getpagesize();
                        const vm_address_t address = (vm_address_t)(uintptr_t)candidate;
                        const vm_address_t pageStart = address & ~(pageSize - 1);
                        const vm_address_t pageEnd =
                            (address + oldLength + pageSize - 1) & ~(pageSize - 1);
                        const vm_size_t protectLength = pageEnd - pageStart;

                        kern_return_t kr = vm_protect(
                            mach_task_self(),
                            pageStart,
                            protectLength,
                            FALSE,
                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
                        );

                        if (kr != KERN_SUCCESS) {
                            kr = vm_protect(
                                mach_task_self(),
                                pageStart,
                                protectLength,
                                FALSE,
                                VM_PROT_READ | VM_PROT_WRITE
                            );
                        }

                        if (kr == KERN_SUCCESS) {
                            memcpy(candidate, newText, oldLength);
                            patchCount++;
                            (void)vm_protect(
                                mach_task_self(),
                                pageStart,
                                protectLength,
                                FALSE,
                                segment->initprot
                            );
                            offset += oldLength - 1;
                        }
                    }
                }
            }

            if (loadCommand->cmdsize == 0) break;
            commandCursor += loadCommand->cmdsize;
        }
    }

    return patchCount;
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
    logHttpRequestMetadata(rewritten, finalData);
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
    logHttpRequestMetadata(rewritten, finalData);
    logRequest(sequence, request, rewritten, finalData);
    if (isAccountRegistrationRequest(rewritten) && finalData != data) {
        appendTrace([NSString stringWithFormat:@"[%@] [R%03lu] Injected-Capability: spqr=true",
                     timestamp(), (unsigned long)sequence]);
    }

    void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
    ^(NSData *responseData, NSURLResponse *response, NSError *error) {
        logHttpResponseMetadata(rewritten, response, error);
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
    logHttpRequestMetadata(rewritten, rewritten.HTTPBody);
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
    logHttpRequestMetadata(rewritten, rewritten.HTTPBody);
    logRequest(sequence, request, rewritten, rewritten.HTTPBody);

    void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
    ^(NSData *responseData, NSURLResponse *response, NSError *error) {
        NSData *finalResponseData =
            rewriteRemoteConfigResponseData(request, rewritten, responseData, response, error);
        logHttpResponseMetadata(rewritten, response, error);
        logResponse(sequence, rewritten, response, finalResponseData, error);
        if (completion) completion(finalResponseData, response, error);
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

static BOOL isCdsiWebSocketURL(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString ?: @"";
    NSString *path = url.path.lowercaseString ?: @"";
    return [host isEqualToString:@"cdsi.signal.org"] &&
           [path hasPrefix:@"/v1/"] &&
           [path hasSuffix:@"/discovery"];
}

static BOOL isTrackedSignalWebSocketURL(NSURL *url) {
    return isLegacyChatWebSocketURL(url) || isCdsiWebSocketURL(url);
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

static NSMutableURLRequest *rewriteLegacyChatWebSocket(id sessionObject,
                                                        NSURLRequest *sourceRequest,
                                                        NSURL *sourceURL) {
    NSURL *url = sourceRequest.URL ?: sourceURL;
    if (!isTrackedSignalWebSocketURL(url)) return nil;

    NSURLComponents *components =
        [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (!components) return nil;

    NSString *originalHost = components.host.lowercaseString ?: @"";
    BOOL isCdsi = [originalHost isEqualToString:@"cdsi.signal.org"];

    if ([originalHost isEqualToString:@"ud-chat.signal.org"]) {
        components.host = @"chat.signal.org";
    }

    if (isCdsi) {
        NSString *path = components.path ?: @"";
        NSString *oldEnclave = [NSString stringWithUTF8String:oldCdsiMrEnclave];
        NSString *newEnclave = [NSString stringWithUTF8String:newCdsiMrEnclave];
        if ([path containsString:oldEnclave]) {
            components.path = [path stringByReplacingOccurrencesOfString:oldEnclave
                                                              withString:newEnclave];
        }
    }

    NSString *login = nil;
    NSString *password = nil;
    NSMutableArray<NSURLQueryItem *> *remaining = [NSMutableArray array];

    if (!isCdsi) {
        for (NSURLQueryItem *item in components.queryItems ?: @[]) {
            NSString *name = item.name.lowercaseString ?: @"";
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
        components.queryItems = remaining.count ? remaining : nil;
    }

    BOOL hadLegacyQueryAuth = login.length || password.length;

    NSURL *finalURL = components.URL ?: url;
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:finalURL];
    request.HTTPMethod = sourceRequest.HTTPMethod ?: @"GET";

    // Signal 7.19.1 normally starts its websocket from URL only and stores
    // headers on the URLSession configuration. Preserve those first.
    copySessionHeaders(sessionObject, request);

    for (NSString *key in sourceRequest.allHTTPHeaderFields ?: @{}) {
        NSString *value = sourceRequest.allHTTPHeaderFields[key];
        if (key.length && value.length) {
            [request setValue:value forHTTPHeaderField:key];
        }
    }

    [request setValue:workingUserAgent forHTTPHeaderField:@"User-Agent"];

    // Current Signal-Server's WebSocketAccountAuthenticator reads the
    // Authorization header. Bare UUID remains valid for primary device 1.
    if (login.length && password.length) {
        NSString *credentials = [NSString stringWithFormat:@"%@:%@", login, password];
        NSData *credentialData = [credentials dataUsingEncoding:NSUTF8StringEncoding];
        NSString *encoded = [credentialData base64EncodedStringWithOptions:0];
        if (encoded.length) {
            [request setValue:[@"Basic " stringByAppendingString:encoded]
           forHTTPHeaderField:@"Authorization"];
        }
    }

    NSString *authMode = @"anonymous";
    if (login.length && password.length) {
        authMode = @"query->basic";
    } else if (hadLegacyQueryAuth) {
        authMode = @"incomplete-query";
    }

    if (isCdsi) {
        appendTrace([NSString stringWithFormat:
            @"[%@] CDSI-WEBSOCKET host=%@ path=/v1/<enclave>/discovery auth=%@ ua=8.29",
            timestamp(),
            finalURL.host ?: @"?",
            [request valueForHTTPHeaderField:@"Authorization"].length ? @"basic" : @"missing"]);
    } else {
        appendTrace([NSString stringWithFormat:
            @"[%@] CHAT-WEBSOCKET host=%@->%@ path=%@ auth=%@ ua=8.29",
            timestamp(),
            originalHost.length ? originalHost : @"?",
            finalURL.host ?: @"?",
            finalURL.path ?: @"/",
            authMode
        ]);
    }

    return request;
}

static NSURLSessionWebSocketTask *webSocketRequestTask(id self,
                                                        SEL sel,
                                                        NSURLRequest *request) {
    NSMutableURLRequest *rewritten = rewriteLegacyChatWebSocket(self, request, nil);
    return originalWebSocketRequest(self, sel, rewritten ?: request);
}

static NSURLSessionWebSocketTask *webSocketURLTask(id self, SEL sel, NSURL *url) {
    if (isTrackedSignalWebSocketURL(url) && originalWebSocketRequest) {
        NSMutableURLRequest *rewritten = rewriteLegacyChatWebSocket(self, nil, url);
        if (rewritten) {
            return originalWebSocketRequest(self,
                                            @selector(webSocketTaskWithRequest:),
                                            rewritten);
        }
    }

    return originalWebSocketURL(self, sel, url);
}

// MARK: - Websocket diagnostics
// These hooks record only lifecycle, HTTP status, error domain/code and binary
// frame sizes. Message bodies, websocket credentials and recipient identifiers
// are never written to the log.

static NSURL *webSocketTaskURL(NSURLSessionTask *task) {
    if (!task) return nil;
    return task.currentRequest.URL ?: task.originalRequest.URL;
}

static BOOL isSignalChatWebSocketTask(id taskObject) {
    if (![taskObject isKindOfClass:NSURLSessionWebSocketTask.class]) return NO;
    return isLegacyChatWebSocketURL(webSocketTaskURL((NSURLSessionTask *)taskObject));
}

static BOOL isTrackedSignalWebSocketTask(id taskObject) {
    if (![taskObject isKindOfClass:NSURLSessionWebSocketTask.class]) return NO;
    return isTrackedSignalWebSocketURL(webSocketTaskURL((NSURLSessionTask *)taskObject));
}

static NSString *webSocketTaskTarget(id taskObject) {
    NSURL *url = webSocketTaskURL((NSURLSessionTask *)taskObject);
    if (!url) return @"?";
    if (isCdsiWebSocketURL(url)) {
        return [NSString stringWithFormat:@"%@/v1/<enclave>/discovery", url.host ?: @"?"];
    }
    return [NSString stringWithFormat:@"%@%@", url.host ?: @"?", url.path ?: @"/"];
}

static NSUInteger webSocketMessageSize(NSURLSessionWebSocketMessage *message) {
    if (!message) return 0;
    if (message.type == NSURLSessionWebSocketMessageTypeData) {
        return message.data.length;
    }
    if (message.type == NSURLSessionWebSocketMessageTypeString) {
        return [message.string lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    }
    return 0;
}


// MARK: - Signal websocket envelope metadata diagnostics

static NSMutableDictionary<NSString *, NSString *> *gWebSocketRequests;

static BOOL wsReadVarint(NSData *data, NSUInteger *offset, uint64_t *valueOut) {
    if (!data || !offset || !valueOut) return NO;

    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;
    uint64_t value = 0;
    unsigned shift = 0;

    while (*offset < length && shift < 64) {
        uint8_t byte = bytes[(*offset)++];
        value |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) {
            *valueOut = value;
            return YES;
        }
        shift += 7;
    }
    return NO;
}

static BOOL wsReadBytes(NSData *data, NSUInteger *offset, NSData **valueOut) {
    uint64_t count64 = 0;
    if (!wsReadVarint(data, offset, &count64)) return NO;
    if (*offset > data.length) return NO;

    uint64_t remaining = (uint64_t)(data.length - *offset);
    if (count64 > remaining) return NO;

    NSUInteger count = (NSUInteger)count64;
    if (valueOut) {
        *valueOut = [data subdataWithRange:NSMakeRange(*offset, count)];
    }
    *offset += count;
    return YES;
}

static BOOL wsSkipField(NSData *data, NSUInteger *offset, uint32_t wireType) {
    switch (wireType) {
        case 0: {
            uint64_t ignored = 0;
            return wsReadVarint(data, offset, &ignored);
        }
        case 1:
            if (*offset > data.length || data.length - *offset < 8) return NO;
            *offset += 8;
            return YES;
        case 2:
            return wsReadBytes(data, offset, NULL);
        case 5:
            if (*offset > data.length || data.length - *offset < 4) return NO;
            *offset += 4;
            return YES;
        default:
            return NO;
    }
}

static NSString *wsString(NSData *data) {
    if (!data.length) return nil;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static NSString *safeWebSocketPath(NSString *path) {
    if (!path.length) return @"?";

    NSString *clean = [[path componentsSeparatedByString:@"?"] firstObject] ?: path;
    if ([clean hasPrefix:@"/v1/messages/"]) return @"/v1/messages/<recipient>";
    if ([clean hasPrefix:@"/v2/keys/"]) return @"/v2/keys/<recipient>";
    if ([clean hasPrefix:@"/v1/profile/"]) return @"/v1/profile/<recipient>";
    if ([clean hasPrefix:@"/v1/usernames/"]) return @"/v1/usernames/<id>";
    return clean;
}

static NSString *webSocketAuthKind(id taskObject) {
    if (![taskObject isKindOfClass:NSURLSessionTask.class]) return @"?";
    NSURLRequest *request = ((NSURLSessionTask *)taskObject).currentRequest ?:
                            ((NSURLSessionTask *)taskObject).originalRequest;
    NSString *authorization = [request valueForHTTPHeaderField:@"Authorization"];
    return authorization.length ? @"auth" : @"anon";
}

static NSString *wsRequestMapKey(id taskObject, uint64_t requestId) {
    return [NSString stringWithFormat:@"%p:%llu", taskObject, requestId];
}

static void rememberWebSocketRequest(id taskObject,
                                     uint64_t requestId,
                                     NSString *verb,
                                     NSString *path) {
    NSString *summary = [NSString stringWithFormat:@"%@ %@",
                         verb.length ? verb : @"?",
                         safeWebSocketPath(path)];
    NSString *key = wsRequestMapKey(taskObject, requestId);

    @synchronized (NSFileHandle.class) {
        if (!gWebSocketRequests) gWebSocketRequests = [NSMutableDictionary dictionary];
        gWebSocketRequests[key] = summary;
    }
}

static NSString *takeWebSocketRequest(id taskObject, uint64_t requestId) {
    NSString *key = wsRequestMapKey(taskObject, requestId);
    @synchronized (NSFileHandle.class) {
        NSString *summary = gWebSocketRequests[key];
        if (summary) [gWebSocketRequests removeObjectForKey:key];
        return summary;
    }
}

static void traceWebSocketRequestProto(NSData *proto,
                                       NSString *direction,
                                       id taskObject) {
    NSUInteger offset = 0;
    NSString *verb = nil;
    NSString *path = nil;
    uint64_t requestId = 0;
    BOOL hasRequestId = NO;

    while (offset < proto.length) {
        uint64_t key = 0;
        if (!wsReadVarint(proto, &offset, &key)) return;

        uint32_t field = (uint32_t)(key >> 3);
        uint32_t wire = (uint32_t)(key & 7);

        if ((field == 1 || field == 2) && wire == 2) {
            NSData *bytes = nil;
            if (!wsReadBytes(proto, &offset, &bytes)) return;
            NSString *string = wsString(bytes);
            if (field == 1) verb = string;
            if (field == 2) path = string;
            continue;
        }

        if (field == 4 && wire == 0) {
            if (!wsReadVarint(proto, &offset, &requestId)) return;
            hasRequestId = YES;
            continue;
        }

        if (!wsSkipField(proto, &offset, wire)) return;
    }

    if (!hasRequestId) return;

    appendTrace([NSString stringWithFormat:
        @"[%@] WS-PROTO %@ socket=%@ REQUEST id=%llu verb=%@ path=%@",
        timestamp(),
        direction ?: @"?",
        webSocketAuthKind(taskObject),
        requestId,
        verb.length ? verb : @"?",
        safeWebSocketPath(path)]);

    if ([direction isEqualToString:@"OUT"]) {
        rememberWebSocketRequest(taskObject, requestId, verb, path);
    }
}

static void traceWebSocketResponseProto(NSData *proto,
                                        NSString *direction,
                                        id taskObject) {
    NSUInteger offset = 0;
    uint64_t requestId = 0;
    uint64_t status = 0;
    NSUInteger messageBytes = 0;
    BOOL hasRequestId = NO;
    BOOL hasStatus = NO;

    while (offset < proto.length) {
        uint64_t key = 0;
        if (!wsReadVarint(proto, &offset, &key)) return;

        uint32_t field = (uint32_t)(key >> 3);
        uint32_t wire = (uint32_t)(key & 7);

        if (field == 1 && wire == 0) {
            if (!wsReadVarint(proto, &offset, &requestId)) return;
            hasRequestId = YES;
            continue;
        }

        if (field == 2 && wire == 0) {
            if (!wsReadVarint(proto, &offset, &status)) return;
            hasStatus = YES;
            continue;
        }

        if (field == 3 && wire == 2) {
            NSData *message = nil;
            if (!wsReadBytes(proto, &offset, &message)) return;
            messageBytes = message.length;
            continue;
        }

        if (!wsSkipField(proto, &offset, wire)) return;
    }

    if (!hasRequestId || !hasStatus) return;

    NSString *matched = [direction isEqualToString:@"IN"]
        ? takeWebSocketRequest(taskObject, requestId)
        : nil;

    appendTrace([NSString stringWithFormat:
        @"[%@] WS-PROTO %@ socket=%@ RESPONSE id=%llu status=%llu for=%@ messageBytes=%lu",
        timestamp(),
        direction ?: @"?",
        webSocketAuthKind(taskObject),
        requestId,
        status,
        matched.length ? matched : @"<unmatched>",
        (unsigned long)messageBytes]);
}

static void traceWebSocketEnvelope(NSData *data,
                                   NSString *direction,
                                   id taskObject) {
    if (!data.length) return;

    NSUInteger offset = 0;
    uint64_t type = 0;
    NSData *requestProto = nil;
    NSData *responseProto = nil;

    while (offset < data.length) {
        uint64_t key = 0;
        if (!wsReadVarint(data, &offset, &key)) return;

        uint32_t field = (uint32_t)(key >> 3);
        uint32_t wire = (uint32_t)(key & 7);

        if (field == 1 && wire == 0) {
            if (!wsReadVarint(data, &offset, &type)) return;
            continue;
        }

        if ((field == 2 || field == 3) && wire == 2) {
            NSData *nested = nil;
            if (!wsReadBytes(data, &offset, &nested)) return;
            if (field == 2) requestProto = nested;
            if (field == 3) responseProto = nested;
            continue;
        }

        if (!wsSkipField(data, &offset, wire)) return;
    }

    if (type == 1 && requestProto.length) {
        traceWebSocketRequestProto(requestProto, direction, taskObject);
    } else if (type == 2 && responseProto.length) {
        traceWebSocketResponseProto(responseProto, direction, taskObject);
    }
}

typedef void (*WebSocketSendMessageFn)(id, SEL, NSURLSessionWebSocketMessage *, void (^)(NSError *));
typedef void (*WebSocketReceiveMessageFn)(id, SEL, void (^)(NSURLSessionWebSocketMessage *, NSError *));

static WebSocketSendMessageFn originalWebSocketSendMessage;
static WebSocketReceiveMessageFn originalWebSocketReceiveMessage;

static void tracedWebSocketSendMessage(id self,
                                       SEL sel,
                                       NSURLSessionWebSocketMessage *message,
                                       void (^completion)(NSError *)) {
    BOOL tracked = isTrackedSignalWebSocketTask(self);
    if (!tracked) {
        originalWebSocketSendMessage(self, sel, message, completion);
        return;
    }

    NSUInteger size = webSocketMessageSize(message);
    appendTrace([NSString stringWithFormat:
        @"[%@] WS-FRAME OUT target=%@ bytes=%lu type=%@",
        timestamp(),
        webSocketTaskTarget(self),
        (unsigned long)size,
        message.type == NSURLSessionWebSocketMessageTypeData ? @"data" : @"string"]);
    if (isSignalChatWebSocketTask(self) &&
        message &&
        message.type == NSURLSessionWebSocketMessageTypeData) {
        traceWebSocketEnvelope(message.data, @"OUT", self);
    }

    void (^wrapped)(NSError *) = ^(NSError *error) {
        appendTrace([NSString stringWithFormat:
            @"[%@] WS-FRAME OUT-COMPLETE target=%@ error=%@",
            timestamp(),
            webSocketTaskTarget(self),
            error ? [NSString stringWithFormat:@"%@/%ld", error.domain, (long)error.code] : @"none"]);
        if (completion) completion(error);
    };

    originalWebSocketSendMessage(self, sel, message, wrapped);
}

static void tracedWebSocketReceiveMessage(id self,
                                          SEL sel,
                                          void (^completion)(NSURLSessionWebSocketMessage *, NSError *)) {
    BOOL tracked = isSignalChatWebSocketTask(self);
    if (!tracked) {
        originalWebSocketReceiveMessage(self, sel, completion);
        return;
    }

    void (^wrapped)(NSURLSessionWebSocketMessage *, NSError *) =
    ^(NSURLSessionWebSocketMessage *message, NSError *error) {
        appendTrace([NSString stringWithFormat:
            @"[%@] WS-FRAME IN target=%@ bytes=%lu type=%@ error=%@",
            timestamp(),
            webSocketTaskTarget(self),
            (unsigned long)webSocketMessageSize(message),
            message ? (message.type == NSURLSessionWebSocketMessageTypeData ? @"data" : @"string") : @"none",
            error ? [NSString stringWithFormat:@"%@/%ld", error.domain, (long)error.code] : @"none"]);
        if (isSignalChatWebSocketTask(self) &&
            message &&
            message.type == NSURLSessionWebSocketMessageTypeData) {
            traceWebSocketEnvelope(message.data, @"IN", self);
        }
        if (completion) completion(message, error);
    };

    originalWebSocketReceiveMessage(self, sel, wrapped);
}

typedef void (*OWSWebSocketDidOpenFn)(id, SEL, NSURLSession *, NSURLSessionWebSocketTask *, NSString *);
typedef void (*OWSWebSocketDidCloseFn)(id, SEL, NSURLSession *, NSURLSessionWebSocketTask *, NSInteger, NSData *);
typedef void (*OWSTaskDidCompleteFn)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *);

static OWSWebSocketDidOpenFn originalOWSWebSocketDidOpen;
static OWSWebSocketDidCloseFn originalOWSWebSocketDidClose;
static OWSTaskDidCompleteFn originalOWSTaskDidComplete;

static void tracedOWSWebSocketDidOpen(id self,
                                      SEL sel,
                                      NSURLSession *session,
                                      NSURLSessionWebSocketTask *task,
                                      NSString *protocol) {
    if (isTrackedSignalWebSocketTask(task)) {
        NSInteger status = [task.response isKindOfClass:NSHTTPURLResponse.class]
            ? ((NSHTTPURLResponse *)task.response).statusCode : -1;
        appendTrace([NSString stringWithFormat:
            @"[%@] WS-OPEN target=%@ http=%ld protocol=%@",
            timestamp(),
            webSocketTaskTarget(task),
            (long)status,
            protocol.length ? protocol : @"<none>"]);
    }
    originalOWSWebSocketDidOpen(self, sel, session, task, protocol);
}

static void tracedOWSWebSocketDidClose(id self,
                                       SEL sel,
                                       NSURLSession *session,
                                       NSURLSessionWebSocketTask *task,
                                       NSInteger closeCode,
                                       NSData *reason) {
    if (isTrackedSignalWebSocketTask(task)) {
        appendTrace([NSString stringWithFormat:
            @"[%@] WS-CLOSE target=%@ code=%ld reasonBytes=%lu",
            timestamp(),
            webSocketTaskTarget(task),
            (long)closeCode,
            (unsigned long)reason.length]);
    }
    originalOWSWebSocketDidClose(self, sel, session, task, closeCode, reason);
}

static void tracedOWSTaskDidComplete(id self,
                                     SEL sel,
                                     NSURLSession *session,
                                     NSURLSessionTask *task,
                                     NSError *error) {
    if (isTrackedSignalWebSocketTask(task)) {
        NSInteger status = [task.response isKindOfClass:NSHTTPURLResponse.class]
            ? ((NSHTTPURLResponse *)task.response).statusCode : -1;
        appendTrace([NSString stringWithFormat:
            @"[%@] WS-TASK-COMPLETE target=%@ http=%ld error=%@",
            timestamp(),
            webSocketTaskTarget(task),
            (long)status,
            error ? [NSString stringWithFormat:@"%@/%ld", error.domain, (long)error.code] : @"none"]);
    } else {
        NSURLRequest *request = task.currentRequest ?: task.originalRequest;
        if (request && isSignalHost(request.URL.host)) {
            logHttpResponseMetadata(request, task.response, error);
        }
    }
    originalOWSTaskDidComplete(self, sel, session, task, error);
}


static void install(Class cls, SEL selector, IMP replacement, IMP *original);

typedef BOOL (*RemoteConfigBoolGetterFn)(id, SEL);
static RemoteConfigBoolGetterFn originalCdsiLookupObjCGetter;
static BOOL gLoggedCdsiGetter = NO;

static BOOL forcedCdsiLookupObjCGetter(id self, SEL sel) {
    if (!gLoggedCdsiGetter) {
        gLoggedCdsiGetter = YES;
        appendTrace([NSString stringWithFormat:
            @"[%@] CDSI-FLAG Objective-C getter forced false.",
            timestamp()]);
    }
    return NO;
}

typedef BOOL (*RemoteConfigSwiftBoolGetterFn)(void);
static RemoteConfigSwiftBoolGetterFn originalCdsiLookupSwiftGetter;
static BOOL gLoggedCdsiSwiftGetter = NO;

static BOOL forcedCdsiLookupSwiftGetter(void) {
    if (!gLoggedCdsiSwiftGetter) {
        gLoggedCdsiSwiftGetter = YES;
        appendTrace([NSString stringWithFormat:
            @"[%@] CDSI-FLAG Swift getter forced false.",
            timestamp()]);
    }
    return NO;
}

static void installCdsiRemoteConfigForce(void *provider) {
    BOOL objcInstalled = NO;
    BOOL swiftInstalled = NO;

    Class remoteConfigClass = NSClassFromString(@"SignalServiceKit.RemoteConfig");
    if (!remoteConfigClass) remoteConfigClass = objc_getClass("_TtC16SignalServiceKit12RemoteConfig");
    if (!remoteConfigClass) remoteConfigClass = objc_getClass("RemoteConfig");

    SEL getter = NSSelectorFromString(@"cdsiLookupWithLibsignal");
    if (remoteConfigClass && class_getClassMethod(remoteConfigClass, getter)) {
        Class meta = object_getClass(remoteConfigClass);
        if (meta) {
            install(meta,
                    getter,
                    (IMP)forcedCdsiLookupObjCGetter,
                    (IMP *)&originalCdsiLookupObjCGetter);
            objcInstalled = originalCdsiLookupObjCGetter != NULL;
        }
    }

    // Swift 5 mangled symbol for:
    // SignalServiceKit.RemoteConfig.cdsiLookupWithLibsignal.getter : Swift.Bool
    if (hookFunction) {
        void *symbol = dlsym(provider ?: RTLD_DEFAULT,
            "$s16SignalServiceKit12RemoteConfigC23cdsiLookupWithLibsignalSbvgZ");
        if (!symbol) {
            symbol = dlsym(RTLD_DEFAULT,
                "$s16SignalServiceKit12RemoteConfigC23cdsiLookupWithLibsignalSbvgZ");
        }
        if (symbol) {
            hookFunction(symbol,
                         (void *)forcedCdsiLookupSwiftGetter,
                         (void **)&originalCdsiLookupSwiftGetter);
            swiftInstalled = YES;
        }
    }

    appendTrace([NSString stringWithFormat:
        @"CDSI remote-config force: objc=%@ swift=%@ class=%@.",
        objcInstalled ? @"yes" : @"no",
        swiftInstalled ? @"yes" : @"no",
        NSStringFromClass(remoteConfigClass) ?: @"<none>"]);
}

typedef void (*SetHiddenFn)(id, SEL, BOOL);
static SetHiddenFn originalExpirationNagSetHidden;

static void expirationNagSetHidden(id self, SEL sel, BOOL hidden) {
    // ExpirationNagView is the local reminder used for both app/OS expiry.
    // v1.5.7 only prevents this reminder view from becoming visible; it does
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

        // v1.5.0 persisted these switches in the app-group defaults. Reset them
        // before ChatConnectionManagerImpl is created so reverting the tweak
        // genuinely returns to Signal 7.19.1's original SSK websocket transport.
        NSUserDefaults *transportDefaults =
            [[NSUserDefaults alloc] initWithSuiteName:@"group.org.whispersystems.signal.group"];
        if (transportDefaults) {
            [transportDefaults setBool:NO forKey:@"UseLibsignalForIdentifiedWebsocket"];
            [transportDefaults setBool:NO forKey:@"UseLibsignalForUnidentifiedWebsocket"];
            [transportDefaults setBool:NO forKey:@"EnableShadowingForUnidentifiedWebsocket"];
            [transportDefaults synchronize];
        }

        appendTrace(@"\n============================================================");
        appendTrace([NSString stringWithFormat:
            @"NEW SIGNAL LAUNCH %@\nSignalBypass14 v1.5.7 forced native CDSI\nApp: %@ (%@)\niOS: %@\nV1.5.6 proved /v2/config returns 200 but the old client still stayed on the libsignal CDSI path. This build directly forces RemoteConfig.cdsiLookupWithLibsignal=false and also hardens v2->legacy config translation.\n",
            timestamp(),
            [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?",
            [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"?",
            NSProcessInfo.processInfo.operatingSystemVersionString ?: @"?"
        ]);

        NSUInteger cdsiPatchCount = patchCStringInLoadedImage(
            "SignalServiceKit.framework/SignalServiceKit",
            oldCdsiMrEnclave,
            newCdsiMrEnclave
        );
        appendTrace([NSString stringWithFormat:
            @"CDSI enclave compatibility: %@ (%lu occurrence%@ patched).",
            cdsiPatchCount ? @"ready" : @"old constant not found",
            (unsigned long)cdsiPatchCount,
            cdsiPatchCount == 1 ? @"" : @"s"]);

        void *provider = dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        hookMessage = (HookMessage)dlsym(provider ?: RTLD_DEFAULT, "MSHookMessageEx");
        hookFunction = (HookFunction)dlsym(provider ?: RTLD_DEFAULT, "MSHookFunction");
        if (!hookMessage) {
            appendTrace(@"MSHookMessageEx unavailable.");
            return;
        }

        installCdsiRemoteConfigForce(provider);

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
            @"Legacy websocket hooks: URL=%@ request=%@.",
            originalWebSocketURL ? @"yes" : @"no",
            originalWebSocketRequest ? @"yes" : @"no"]);

        // Hook the concrete NSURLSessionWebSocketTask implementation used on
        // this OS so we can see whether encrypted frames are actually leaving
        // and whether any frames come back, without inspecting their contents.
        NSURLSession *probeSession =
            [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration];
        NSURLSessionWebSocketTask *probeTask =
            [probeSession webSocketTaskWithURL:[NSURL URLWithString:@"wss://127.0.0.1/"]];
        Class webSocketTaskClass = [probeTask class];

        install(webSocketTaskClass,
                NSSelectorFromString(@"sendMessage:completionHandler:"),
                (IMP)tracedWebSocketSendMessage,
                (IMP *)&originalWebSocketSendMessage);

        install(webSocketTaskClass,
                NSSelectorFromString(@"receiveMessageWithCompletionHandler:"),
                (IMP)tracedWebSocketReceiveMessage,
                (IMP *)&originalWebSocketReceiveMessage);

        [probeTask cancel];
        [probeSession invalidateAndCancel];

        // Signal's OWSURLSession receives the websocket delegate callbacks after
        // its private forwarding box. Hook those callbacks to capture the actual
        // upgrade status/close reason before Signal reduces them to "spinning".
        Class owsURLSessionClass = NSClassFromString(@"SignalServiceKit.OWSURLSession");
        if (!owsURLSessionClass) {
            owsURLSessionClass = objc_getClass("_TtC16SignalServiceKit13OWSURLSession");
        }

        install(owsURLSessionClass,
                NSSelectorFromString(@"URLSession:webSocketTask:didOpenWithProtocol:"),
                (IMP)tracedOWSWebSocketDidOpen,
                (IMP *)&originalOWSWebSocketDidOpen);

        install(owsURLSessionClass,
                NSSelectorFromString(@"URLSession:webSocketTask:didCloseWithCode:reason:"),
                (IMP)tracedOWSWebSocketDidClose,
                (IMP *)&originalOWSWebSocketDidClose);

        install(owsURLSessionClass,
                NSSelectorFromString(@"URLSession:task:didCompleteWithError:"),
                (IMP)tracedOWSTaskDidComplete,
                (IMP *)&originalOWSTaskDidComplete);

        appendTrace([NSString stringWithFormat:
            @"Websocket diagnostics: taskClass=%@ send=%@ receive=%@ ows=%@ open=%@ close=%@ complete=%@.",
            NSStringFromClass(webSocketTaskClass),
            originalWebSocketSendMessage ? @"yes" : @"no",
            originalWebSocketReceiveMessage ? @"yes" : @"no",
            NSStringFromClass(owsURLSessionClass),
            originalOWSWebSocketDidOpen ? @"yes" : @"no",
            originalOWSWebSocketDidClose ? @"yes" : @"no",
            originalOWSTaskDidComplete ? @"yes" : @"no"]);

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
        appendTrace([NSString stringWithFormat:
            @"Transport defaults restored: identified=%d unidentified=%d shadowing=%d",
            transportDefaults ? [transportDefaults boolForKey:@"UseLibsignalForIdentifiedWebsocket"] : -1,
            transportDefaults ? [transportDefaults boolForKey:@"UseLibsignalForUnidentifiedWebsocket"] : -1,
            transportDefaults ? [transportDefaults boolForKey:@"EnableShadowingForUnidentifiedWebsocket"] : -1]);
    }
}
