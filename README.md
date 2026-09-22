# Signal Bypass iOS 14

Experimental **rootful** compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.0.2: match the known-working rootful loader format

v1.0.1 still did not show the injection canary. A direct Mach-O comparison with the supplied FuckSignalExpiry package found another concrete difference.

The known-working tweak has:

- arm64 + arm64e
- dylib mode 0755
- a binary MobileSubstrate filter plist
- a direct `LC_LOAD_DYLIB` dependency on `/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate`

v1.0.2 now mirrors all four of those loader-level properties. CI verifies the Substrate load command before signing and packaging.

No new registration behaviour is guessed in this build. The existing compatibility hooks are retained, and the **SB14 v1.0.2 loaded** popup remains the test for whether the dylib is actually entering Signal.

Install, fully kill Signal, respring, open Signal and wait about three seconds.

## Build

macOS with Xcode's iPhoneOS SDK: `brew install ldid dpkg`, then `bash scripts/build.sh`.
