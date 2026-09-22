#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/stat.h>
#import <pthread.h>
#import <stdarg.h>
#import <time.h>
#import <stdlib.h>
#import <stdio.h>
#import <limits.h>

static int diagnosticFD = -1;
static pthread_mutex_t diagnosticLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned diagnosticCount;
static void trace(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void trace(const char *format, ...) {
    if (diagnosticFD < 0) return;
    pthread_mutex_lock(&diagnosticLock);
    if (diagnosticCount++ < 250) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        char text[1536];
        int prefix = snprintf(text, sizeof(text), "[%lld.%03ld] ", (long long)now.tv_sec, now.tv_nsec / 1000000);
        va_list args;
        va_start(args, format);
        vsnprintf(text + prefix, sizeof(text) - (size_t)prefix, format, args);
        va_end(args);
        size_t length = strlen(text);
        if (length < sizeof(text)-1) text[length++] = '\n';
        // Flush each checkpoint: preserve evidence if launch is killed.
        (void)write(diagnosticFD, text, length);
        (void)fsync(diagnosticFD);
    }
    pthread_mutex_unlock(&diagnosticLock);
}

static void startTrace(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    char folder[PATH_MAX], path[PATH_MAX], previous[PATH_MAX];
    if (snprintf(folder, sizeof(folder), "%s/Documents", home) >= (int)sizeof(folder)) return;
    (void)mkdir(folder, 0700);
    if (snprintf(path, sizeof(path), "%s/SignalBypass14-startup.log", folder) >= (int)sizeof(path)) return;
    if (snprintf(previous, sizeof(previous), "%s/SignalBypass14-startup.previous.log", folder) >= (int)sizeof(previous)) return;
    (void)rename(path, previous);
    diagnosticFD = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW, 0600);
    trace("v1.1.0 injected; process=%s pid=%d", getprogname(), getpid());
}

static BOOL (*originalDidFinish)(id, SEL, UIApplication *, NSDictionary *);
static BOOL didFinish(id self, SEL sel, UIApplication *application, NSDictionary *options) {
    trace("didFinishLaunching ENTER");
    BOOL result = originalDidFinish(self, sel, application, options);
    trace("didFinishLaunching RETURN result=%d", result);
    return result;
}

static void (*originalSetDelegate)(id, SEL, id);
static void setDelegate(id self, SEL sel, id delegate) {
    static BOOL installed;
    if (delegate && !installed) {
        trace("application delegate=%s", object_getClassName(delegate));
        Class cls = object_getClass(delegate);
        SEL launch = @selector(application:didFinishLaunchingWithOptions:);
        if (class_getInstanceMethod(cls, launch)) {
            hookMessage(cls, launch, (IMP)didFinish, (IMP *)&originalDidFinish);
            installed = YES;
        }
    }
    originalSetDelegate(self, sel, delegate);
}

static void (*originalSetRoot)(id, SEL, UIViewController *);
static void setRoot(id self, SEL sel, UIViewController *controller) {
    trace("window=%s setRoot=%s ENTER", object_getClassName(self), controller ? object_getClassName(controller) : "nil");
    originalSetRoot(self, sel, controller);
    trace("setRoot RETURN");
}

static void (*originalMakeVisible)(id, SEL);
static void makeVisible(id self, SEL sel) {
    trace("makeKeyAndVisible ENTER window=%s", object_getClassName(self));
    originalMakeVisible(self, sel);
    trace("makeKeyAndVisible RETURN");
}

static NSURL *(*originalGroupURL)(id, SEL, NSString *);
static NSURL *groupURL(id self, SEL sel, NSString *identifier) {
    BOOL signalGroup = [identifier hasPrefix:@"group.org.whispersystems.signal."];
    if (signalGroup) trace("Signal shared-container lookup ENTER");
    NSURL *result = originalGroupURL(self, sel, identifier);
    if (signalGroup) trace("Signal shared-container lookup RETURN available=%d", result != nil);
    return result;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void installStartupDiagnostics(void) {
    if (diagnosticFD < 0) return;
    install(UIApplication.class, @"setDelegate:", (IMP)setDelegate, (IMP *)&originalSetDelegate);
    install(UIWindow.class, @"setRootViewController:", (IMP)setRoot, (IMP *)&originalSetRoot);
    install(UIWindow.class, @"makeKeyAndVisible", (IMP)makeVisible, (IMP *)&originalMakeVisible);
    install(NSFileManager.class, @"containerURLForSecurityApplicationGroupIdentifier:", (IMP)groupURL, (IMP *)&originalGroupURL);
    for (NSNumber *delay in @[@2, @8, @20]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delay.longLongValue * NSEC_PER_SEC),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            trace("background checkpoint %ds; requesting main-thread snapshot", delay.intValue);
            dispatch_async(dispatch_get_main_queue(), ^{
                UIApplication *app = UIApplication.sharedApplication;
                trace("main-thread checkpoint %ds; state=%ld protectedDataAvailable=%d windows=%lu",
                      delay.intValue, (long)app.applicationState, app.protectedDataAvailable, (unsigned long)app.windows.count);
                for (UIWindow *window in app.windows) {
                    UIViewController *root = window.rootViewController;
                    trace("window=%s hidden=%d alpha=%.2f level=%.0f root=%s presented=%s",
                          object_getClassName(window), window.hidden, (double)window.alpha, (double)window.windowLevel,
                          root ? object_getClassName(root) : "nil",
                          root.presentedViewController ? object_getClassName(root.presentedViewController) : "nil");
                }
            });
        });
    }
    trace("startup observers installed; no UI, database or keychain state changed");
}
#pragma clang diagnostic pop
