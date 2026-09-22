#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// Minimal rootful runtime patch for Signal 7.19.1 on iOS 14.
// v1.3.0 intentionally contains no network interception, HTTP status rewriting,
// diagnostic UI, runtime log files, OS-version spoof, or URLSession hooks.

typedef void (*HookMessage)(Class, SEL, IMP, IMP *);
typedef void (*HookFunction)(void *, void *, void **);

static HookMessage hookMessage;
static HookFunction hookFunction;

static BOOL returnFalseObjC(id self, SEL sel) {
    (void)self;
    (void)sel;
    return NO;
}

static NSUInteger returnZeroObjC(id self, SEL sel) {
    (void)self;
    (void)sel;
    return 0;
}

// The exact Swift expiry/update paths exported by SignalServiceKit in
// Signal 7.19.1 (208). ARM64 permits us to ignore unused incoming arguments.
static BOOL swiftReturnFalse(void) { return NO; }
static NSUInteger swiftReturnZero(void) { return 0; }
static void swiftNoop(void) {}

static void hookSwift(const char *symbol, void *replacement) {
    if (!hookFunction) return;
    void *target = dlsym(RTLD_DEFAULT, symbol);
    if (target) hookFunction(target, replacement, NULL);
}

static void hookObjC(Class cls, NSString *name, IMP replacement) {
    if (!hookMessage || !cls) return;
    SEL selector = NSSelectorFromString(name);
    if (class_getInstanceMethod(cls, selector)) {
        hookMessage(cls, selector, replacement, NULL);
    }
}

static void installExpiryHooks(void) {
    // Local expiry result.
    hookSwift("$s16SignalServiceKit13AppExpiryImplC9isExpiredSbvg",
              (void *)&swiftReturnFalse);
    hookSwift("$s16SignalServiceKit13AppExpiryImplC9isExpiredSbvgTq",
              (void *)&swiftReturnFalse);

    // HTTP 499 normally persists "expired at current version". Do not let that
    // state be written for this compatibility build.
    hookSwift("$s16SignalServiceKit13AppExpiryImplC06setHasD23ExpiredAtCurrentVersion2dbyAA2DB_p_tF",
              (void *)&swiftNoop);
    hookSwift("$s16SignalServiceKit13AppExpiryImplC06setHasD23ExpiredAtCurrentVersion2dbyAA2DB_p_tFTq",
              (void *)&swiftNoop);

    // Status code used by Signal's app-expiry path.
    hookSwift("$s16SignalServiceKit13AppExpiryImplC20appExpiredStatusCodeSuvgZ",
              (void *)&swiftReturnZero);

    // Registration can independently classify an unknown challenge as
    // requiring an app update.
    hookSwift("$s16SignalServiceKit19RegistrationSessionV37hasUnknownChallengeRequiringAppUpdateSbvg",
              (void *)&swiftReturnFalse);

    // Objective-C-visible fallbacks, if present in this build.
    Class expiryClass = NSClassFromString(@"SignalServiceKit.AppExpiryImpl");
    if (!expiryClass) expiryClass = objc_getClass("_TtC16SignalServiceKit13AppExpiryImpl");

    hookObjC(expiryClass, @"isExpired", (IMP)returnFalseObjC);
    hookObjC(object_getClass(expiryClass), @"appExpiredStatusCode", (IMP)returnZeroObjC);
    hookObjC(NSClassFromString(@"AppExpiry"), @"isExpired", (IMP)returnFalseObjC);
}

__attribute__((constructor)) static void start(void) {
    @autoreleasepool {
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"org.whispersystems.signal"]) {
            return;
        }

        void *provider = dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        void *scope = provider ?: RTLD_DEFAULT;
        hookMessage = (HookMessage)dlsym(scope, "MSHookMessageEx");
        hookFunction = (HookFunction)dlsym(scope, "MSHookFunction");

        if (!hookFunction && !hookMessage) return;
        installExpiryHooks();
    }
}
