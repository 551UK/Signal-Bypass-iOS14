# Signal Bypass iOS 14

Experimental rootful compatibility tweak for **Signal 7.19.1 (208) on iOS 14**.

## Version 0.7.0: persist the working 8.29 identity

The previous builds changed Signal's version mostly at runtime. That left a gap: Signal 7.19.1's `AppVersionImpl` is pure Swift and constructs `currentAppVersion` directly from the app bundle. The registration stack then uses that value when it creates its own User-Agent and expiry state.

v0.7.0 therefore applies the version at the source instead of depending on a later Objective-C hook.

On install it backs up the original metadata, then writes the exact values from the supplied working **Signal 8.29 (1866)** IPA:

- `CFBundleShortVersionString = 8.29`
- `CFBundleVersion = 1866`
- the matching 8.29 `BuildDetails` timestamp, commit and Xcode version

The app binary is still Signal 7.19.1 and `MinimumOSVersion` is left at 14.0. The v0.3 launch fix remains unchanged: the NSProcessInfo iOS-10000 spoof is not restored.

This is intentionally different from v0.4-v0.6: Signal's own Swift version object should now initialize as **8.29.0.1866**, so registration should create the current identity itself rather than us trying to rewrite it later in Foundation.

Uninstall restores the original 7.19.1 (208) metadata.

## Install

1. Fully close Signal. Keep Signal **7.19.1 (208)** installed on the rootful iOS 14 device.
2. Remove **FuckSignalExpiry** and other Signal spoofers. The new package declares a conflict with the supplied package because it incorporates its hooks.
3. Install the DEB from [Releases](https://github.com/551UK/Signal-Bypass-iOS14/releases). Confirm the installer prints that the Info.plist dates were changed.
4. Respring, open Signal, then test registration, sending/receiving, locked-phone notifications and calls separately.

The installer only edits the main app's two build-date fields and keeps their original BuildDetails dictionary alongside Info.plist. It does not erase Signal's database or account. Uninstall restores those two fields if they still match this tweak's values, preserving later manual changes. Reinstalling/updating the app can remove the edit; reinstall this tweak afterwards.

The reference user recommends a TrollStore-installed IPA, but the reason the App Store copy fails has not been established. Do not delete an existing installation or its data to switch installation methods without a data-preservation plan. App-bundle edits can affect signature validation depending on the installation/jailbreak setup.

If Signal remains black, report whether it stays open or closes, the installation method, and a crash report if one exists. Logs use `[SignalBypass14]`. No request bodies, tokens or phone numbers are logged by this tweak.

## Limits

No protocol or cryptographic backport is included. Pure Swift calls can bypass Objective-C hooks, including the error-code getter. Previously persisted remote expiry for the spoofed version is not erased. Foundation diagnostics do not cover every native libsignal/WebSocket path. Successful compilation does not establish device functionality.

## Build

macOS with Xcode's iPhoneOS SDK: `brew install ldid dpkg`, then `bash scripts/build.sh`. GitHub Actions builds the package and publishes a prerelease. See [comparison notes](docs/ipa-comparison.md).
