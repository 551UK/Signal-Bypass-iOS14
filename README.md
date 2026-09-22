# Signal Bypass iOS 14

Experimental rootful compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.0.4: crash-safe runtime marker

v1.0.3 closed Signal immediately because the earliest constructor diagnostic used Foundation objects before the app was ready.

v1.0.4 keeps the same working rootful package baseline but replaces that diagnostic with plain C file I/O only. The first constructor action writes:

`SignalBypass14-runtime-marker.txt`

to Signal's Documents directory using `open/write/fsync/close`. No Foundation, UIKit, bundle lookups or Objective-C objects are used for that marker.

After installing, fully close Signal, respring, open Signal once, then check Documents for the marker. If it exists, runtime injection is confirmed.

The universal arm64 + arm64e dylib, 0755 permissions, persisted 8.29.0.1866 metadata and existing registration compatibility hooks are otherwise unchanged.
