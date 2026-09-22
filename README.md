# Signal Bypass iOS 14

Experimental rootful compatibility tweak for **Signal 7.19.1 (208) on iOS 14**.

## Version 0.8.0: hook the registration gate in Swift

v0.7 still produced the same **Something went wrong → Update Required** sequence. The important source-level finding is that Signal 7.19.1 can produce `.appUpdateBanner` from only two registration conditions:

1. `AppExpiry.isExpired`
2. `RegistrationSession.hasUnknownChallengeRequiringAppUpdate`

Both are pure Swift paths. Earlier builds mainly used Objective-C/Foundation hooks, so they could leave these actual Swift getters untouched.

v0.8.0 resolves the exported Swift symbols from the exact supplied **Signal 7.19.1 (208)** `SignalServiceKit` binary and hooks them directly with `MSHookFunction`:

- `AppExpiryImpl.isExpired` → always false
- the AppExpiry dispatch thunk → always false
- `setHasAppExpiredAtCurrentVersion(db:)` → no-op
- its dispatch thunk → no-op
- `appExpiredStatusCode` → 0
- `RegistrationSession.hasUnknownChallengeRequiringAppUpdate` → always false

The working v0.3 launch change is preserved: the unsafe NSProcessInfo iOS-10000 override is still **not** used. v0.7's exact Signal 8.29.0.1866 persisted version/build metadata is also retained.

If the Update Required alert still appears, v0.8 appends an `SB14 v0.8` diagnostic line directly to that alert. `swift=6` means all six expected Swift symbols were found and hooked.

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
