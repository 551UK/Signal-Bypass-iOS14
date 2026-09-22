# Signal Bypass iOS 14

Experimental rootful compatibility tweak for **Signal 7.19.1 (208) on iOS 14**.

## Version 0.4.0: registration update-required bypass

This build keeps the **v0.3.0 launch-working baseline**: the unsafe NSProcessInfo iOS 10000 override stays removed, so the change that allowed Signal to open is preserved.

The next blocker is now source-identified. In Signal 7.19.1, the service can return **HTTP 499**. Signal handles that by calling `setHasAppExpiredAtCurrentVersion`, and the registration coordinator then returns `.appUpdateBanner`. That is the **“Update Required”** alert shown after submitting the phone number.

v0.4.0 targets that point without pretending a rejected 499 response was successful:

- Requests to Signal service hosts are forced to the exact network identity from the supplied working **Signal 8.29 (1866)** IPA: `Signal-iOS/8.29.0.1866 iOS/16.3`.
- The local synthetic app build is **8.29.0.1867**. This is intentionally one build different from the network identity so an immediate-expiry state persisted during the previous 8.29.0.1866 test is not restored on the next launch.
- The 2099 build-date handling, expiry compatibility hooks and startup diagnostics remain.
- The removed NSProcessInfo iOS 10000 spoof is **not** reintroduced.
- HTTP 499 is still logged rather than rewritten to 200; changing only the status would leave Signal with an error response body and would not make the SMS request succeed.

After installing v0.4.0, fully close Signal, respring, reopen it and submit the number again. If the service still rejects registration, `SignalBypass14-startup.log` plus the HTTP status line will tell us whether the request is still receiving 499.

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
