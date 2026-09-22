# Signal Bypass iOS 14

Experimental **rootful** compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.0.0: rootful arm64e injection fix

The missing v0.9 canary changed the diagnosis. Comparing our package with the supplied FuckSignalExpiry 0.9.0 package found a concrete packaging difference:

- the known-working tweak dylib contains **arm64 + arm64e**
- our previous SignalBypass14 dylib was compiled as **arm64 only**
- the working package uses the same rootful path: `/Library/MobileSubstrate/DynamicLibraries`
- both use package architecture `iphoneos-arm`

On an A12-or-newer iPhone, Signal runs as arm64e. A rootful MobileSubstrate tweak without an arm64e slice may simply fail to inject, which matches the missing log and missing canary.

v1.0.0 therefore builds the tweak dylib as a universal **arm64 + arm64e** binary and CI verifies both slices before packaging. The visible **SB14 v1.0 loaded** popup remains so injection is obvious.

The existing Signal compatibility work is otherwise retained: the v0.3 launch fix, exact 8.29.0.1866 metadata, and the Swift registration expiry/challenge hooks.

After install, fully close Signal, respring and open it. If **SB14 v1.0 loaded** appears, send a screenshot of that popup.

## Build

macOS with Xcode's iPhoneOS SDK: `brew install ldid dpkg`, then `bash scripts/build.sh`.
