# Signal Bypass iOS 14

Experimental rootful compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.2.0: fresh local AppExpiry identity

This build stays on the stable v1.1.1 runtime path and tests a specific Signal 7.19.1 behavior.

Signal stores its AppExpiry state together with `AppVersionImpl.currentAppVersion`. It only restores that stored expiry state when the version matches exactly. Earlier builds locally identified as `8.29.0.1866`, so if Signal had already persisted `mode = immediately` for that identity after an HTTP 499, changing only the build date would not clear it.

v1.2.0 therefore separates the local and server-facing identities:

- local `CFBundleShortVersionString`: **8.29**
- local `CFBundleVersion`: **1867**
- local AppVersion identity: **8.29.0.1867**
- local BuildDetails timestamp: **22 Sep 2026 13:00 UTC**
- server-facing User-Agent remains the genuine supplied 8.29 identity: **Signal-iOS/8.29.0.1866 iOS/16.3**

The Signal 8.29 commit/Xcode metadata remains from the supplied IPA. The 1867 build number is intentionally local-only; it is used to prevent Signal 7.19.1 from restoring an AppExpiry record cached under 8.29.0.1866.

No new launch hooks are introduced.
