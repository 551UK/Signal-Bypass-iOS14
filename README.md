# Signal Bypass iOS 14

Experimental rootful compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.3.0: minimal expiry-functions build

v1.3.0 deliberately removes the broad runtime instrumentation used during diagnosis and keeps the test focused on Signal's actual expiry/update paths.

### What changed

- New local AppVersion identity: **8.29.0.1868**
- New local BuildDetails timestamp: **22 Sep 2026 17:00 UTC**
- Hooks SignalServiceKit's pure-Swift `AppExpiryImpl.isExpired` getter to return false.
- Hooks `setHasAppExpiredAtCurrentVersion(db:)` so an HTTP 499 cannot persist a new "expired at this version" state.
- Hooks `AppExpiryImpl.appExpiredStatusCode` to return 0.
- Hooks `RegistrationSession.hasUnknownChallengeRequiringAppUpdate` to return false.
- Retains small Objective-C expiry fallbacks if those selectors are visible.

### Removed from the runtime tweak

- URLSession and request-header hooks
- User-Agent forcing
- HTTP 499-to-400 rewriting
- diagnostic alert modification
- injection canary popup
- startup/runtime log files
- OS-version spoofing
- runtime NSBundle metadata hooks

The package installer still writes the local bundle metadata before Signal launches. Moving from local build **1867** to **1868** prevents Signal 7.19.1 from restoring an AppExpiry record whose stored appVersion exactly matches the previous identity.

This build is intended to answer one question cleanly: whether blocking the actual expiry/update functions is enough without the extra networking and diagnostic machinery.
