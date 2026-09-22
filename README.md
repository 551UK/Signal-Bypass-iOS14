# Signal Bypass iOS 14

Experimental rootful compatibility tweak for **Signal 7.19.1 (208) on iOS 14**.

## Version 0.5.0: registration 499 follow-up

The v0.4.0 device result is useful: registration first shows **“Something went wrong”**, and only after dismissing it does Signal show **“Update Required.”** That matches Signal 7.19.1's source path for a service error such as HTTP 499: the registration request maps the unknown status to a generic error, while Signal separately marks the app version as remotely expired. On the next registration step, `appExpiry.isExpired` produces the update banner.

v0.5.0 keeps the **v0.3.0 launch-working baseline** and does not restore the NSProcessInfo iOS-10000 hook.

Changes:

- Uses local synthetic build **8.29.0.1868**, isolating it from remote-expiry state persisted by the 1866/1867 test builds.
- Forces the exact supplied working 8.29 network identity, `Signal-iOS/8.29.0.1866 iOS/16.3`, in two places: while NSMutableURLRequest headers are written and again when NSURLSession tasks are created.
- Records the outgoing Signal User-Agent before/after the task hook and the returned HTTP status in `SignalBypass14-startup.log`; no phone number, request body, token or URL path is logged.
- If Signal still receives **499**, it is exposed to the old app as **400**, not 200. This prevents 7.19.1 from persisting a second “Update Required” lock while preserving the fact that the registration request failed. A rejected response is never fabricated as successful.
- Hooks the resolved `AppExpiryImpl` Objective-C class directly as supplementary local-expiry coverage.

The important test is whether the first registration request now stops returning 499. If it succeeds, Signal can proceed to the actual SMS/session flow. If it still fails, send `Documents/SignalBypass14-startup.log`; the new log will show the Signal host, status and User-Agent without exposing the phone number.

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
