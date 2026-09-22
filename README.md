# Signal Bypass iOS 14

Experimental **rootful** compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.0.1: fix rootful dylib permissions

The previous build still did not inject. The rootful package comparison found the concrete cause in the DEB itself:

- known-working FuckSignalExpiry dylib: **0755**
- SignalBypass14 v1.0.0 dylib: **0644**

The build script was applying `chmod 644` to every file in `/Library/MobileSubstrate/DynamicLibraries`, including the dylib. That is wrong for a rootful MobileSubstrate tweak.

v1.0.1 now packages:

- `SignalBypass14.dylib` as **0755**
- `SignalBypass14.plist` as **0644**
- universal **arm64 + arm64e** dylib
- rootful path `/Library/MobileSubstrate/DynamicLibraries`

CI verifies the dylib mode before packaging.

After installing, fully close Signal, respring, then open it and wait about three seconds. You should see **SB14 v1.0.1 loaded**. If that appears, injection is finally confirmed and we can continue with the registration bypass itself.

## Build

macOS with Xcode's iPhoneOS SDK: `brew install ldid dpkg`, then `bash scripts/build.sh`.
