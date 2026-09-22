# IPA comparison and initial implementation

Inspected the supplied IPA metadata and SignalServiceKit binaries, then checked upstream source at the older app's exact commit.

| Property | Older IPA | Newer IPA |
| --- | --- | --- |
| App version | 7.19.1 | 8.29 |
| Build | 208 | 1866 |
| Minimum iOS | 14.0 | 15.0 |
| Bundle ID | org.whispersystems.signal | org.whispersystems.signal |

The older app's BuildDetails identifies commit `dc04157b3adef68af2136a12478f455e41e5d2e0` and timestamp `1720643557` (10 July 2024). The corresponding upstream tag is `7.19.1.208`.

Verified source paths:

- [AppVersion.swift](https://github.com/signalapp/Signal-iOS/blob/7.19.1.208/SignalServiceKit/Util/AppVersion.swift): constructs the four-component version from CFBundleShortVersionString and CFBundleVersion; reads BuildDetails.Timestamp for buildDate.
- [AppExpiry.swift](https://github.com/signalapp/Signal-iOS/blob/7.19.1.208/SignalServiceKit/Util/AppExpiry.swift): default expiry is buildDate + 90 days; restores stored expiry only if its version matches; expiry has default, immediate and explicit-date modes. Its Swift implementation is not entirely routed through Objective-C.
- [OWSHttpHeaders.swift](https://github.com/signalapp/Signal-iOS/blob/7.19.1.208/SignalServiceKit/Network/OWSHttpHeaders.swift): builds `Signal-iOS/<four-component version> iOS/<UIDevice.systemVersion>`.
- [HTTPUtils.swift](https://github.com/signalapp/Signal-iOS/blob/7.19.1.208/SignalServiceKit/Network/API/HTTPUtils.swift): HTTP 499 records server-triggered expiry.

The old binary contains `AppExpiry`, `_TtC16SignalServiceKit13AppExpiryImpl`, `isExpired`, and the matching source-path strings. The new binary instead contains `_TtC16SignalServiceKit9AppExpiry`, so its expiry implementation is structurally different. Blindly copying frameworks or lowering the newer IPA's minimum OS does not establish iOS 14 compatibility.

The initial tweak changes source-verified inputs: app version, reported OS string and build timestamp. It uses Objective-C expiry accessors only as supplementary coverage. It does not claim a Swift-wide remote-expiry bypass or protocol backport.

Next decision depends on the device result: local expiry remaining requires checking injection and persisted remote-expiry mode; a server error requires its status and failing operation; a crash requires its stack trace. No endpoint, status-code or cryptographic changes should be guessed without that evidence.
