# Signal Bypass iOS 14

Experimental rootful tweak for **Signal 7.19.1 (208) on iOS 14**. Version 0.2.0 reproduces the supplied expiry tweak's hooks and the reported Info.plist edit. It is not confirmed to fix the black screen, registration, messaging or calls. The reference setup still reports failed calls.

## Changes in 0.2.0

- Installer sets `BuildDetails.Timestamp` to `4070908800` and `BuildDetails.DateTime` to `Thu Jan 01 00:00:00 UTC 2099` in the installed Signal app's Info.plist. These represent the same UTC date. Runtime bundle hooks report the same values.
- Adds the supplied FuckSignalExpiry 0.9.0 behavior: `AppExpiryImpl.appExpiredStatusCode` returns 0 and `NSProcessInfo.operatingSystemVersion` reports major version 10000, preserving minor/patch. This changes OS-version decisions inside Signal and may select unsupported code paths; device testing is necessary.
- Keeps the Signal 8.29 / build 1866 spoof and UIDevice version string 16.3 used for the standard user agent. The two OS APIs intentionally differ to reproduce the reference tweak while retaining the existing network identity.
- Uses the kernel release for the iOS 14 gate so another NSProcessInfo spoof cannot disable activation.
- Keeps supplementary Objective-C expiry accessors and bounded HTTP status/host diagnostics. Actual HTTP responses are not rewritten.

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
