# Signal Bypass iOS 14

Experimental rootful compatibility tweak for **Signal 7.19.1 (208) on iOS 14**.

## Version 0.9.0: prove tweak injection first

v0.8 still produced the same **Something went wrong → Update Required** sequence, and no startup log or SB14 diagnostic text appeared. That makes tweak injection itself the first thing to prove before changing more registration code.

v0.9.0 intentionally does not add another guessed registration bypass. Instead:

- The MobileSubstrate filter now matches the known-working FuckSignalExpiry package exactly: the main Signal bundle only.
- The startup log no longer depends on the process name being exactly `Signal`.
- About three seconds after Signal opens, the main app should show a one-time **SB14 v0.9 loaded** alert.
- The alert reports whether `MSHookMessageEx` and `MSHookFunction` resolved and how many of the expected pure-Swift hooks installed.
- Existing v0.8 Swift expiry/challenge hooks and the exact 8.29.0.1866 persisted metadata remain unchanged.

If the SB14 v0.9 alert does **not** appear, the dylib is not reaching the main Signal process and the next work belongs in the loader/injection setup, not the registration logic.

If it does appear, send the three values shown in that alert and then reproduce registration once.

## Build

macOS with Xcode's iPhoneOS SDK: `brew install ldid dpkg`, then `bash scripts/build.sh`. GitHub Actions builds the package and publishes a prerelease.
