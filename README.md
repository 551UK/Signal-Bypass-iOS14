# Signal Bypass iOS 14

Experimental rootful tweak for **Signal 7.19.1 (208) on iOS 14**. This is an initial compatibility build, not a confirmed working Signal client.

## Included

- Reports app version 8.29 / build 1866 through Signal's bundle metadata.
- Reports iOS 16.3 through `UIDevice.systemVersion`, including Signal's standard user-agent construction.
- Refreshes Signal's in-memory build timestamp to address its 90-day local expiry, including Swift code that reads the timestamp directly.
- Overrides the two known Objective-C `isExpired` accessors when present.
- Applies to Signal, its notification extension and share extension; remains inactive on other iOS/app versions.
- Logs activation and Foundation HTTP error status/host only. Does not log message contents, request bodies, tokens or phone numbers.

OS availability checks remain genuine so iOS 14 does not attempt to call unavailable iOS 15/16 APIs. The tweak does not modify the system clock, database, encryption, TLS verification, or server response status codes.

## Install / test

1. Keep Signal **7.19.1 (208)** installed on your jailbroken iOS 14 device. Do not replace it with 8.29 or delete its data.
2. Download the rootful DEB from the latest successful [Actions build](https://github.com/551UK/Signal-Bypass-iOS14/actions).
3. Install with your package manager, respring, and launch Signal. Allow tweak injection into Signal and its extensions if using Choicy.
4. Check whether the expiry screen clears. Then test registration if needed, sending, receiving with Signal open, and receiving while locked. Confirm delivery from another device.
5. Report the first failing step and exact error/screenshot. For a crash, include the Signal `.ips` report. The startup marker is `[SignalBypass14]`.

Uninstall the tweak and restart Signal to remove its hooks. Signal may retain its own version bookkeeping; no automatic database cleanup is performed.

## Limits

The older app's protocol and cryptographic implementation remain unchanged. Registration, current service endpoints, contact discovery, attachment handling and messaging compatibility still require device testing. HTTP 499 remains an error and can persist server-triggered expiry for the spoofed version. The Objective-C expiry hooks do not intercept all Swift calls. The build-date override handles default expiry but does not erase persisted remote expiry for the same spoofed version.

Foundation HTTP diagnostics do not cover every native libsignal/WebSocket path. This package has no device validation yet. See [the comparison notes](docs/ipa-comparison.md) for verified findings.

## Build

On macOS with Xcode's iPhoneOS SDK, `brew install ldid dpkg`, then `bash scripts/build.sh`. GitHub Actions performs the same build. No IPA or account data is committed.
