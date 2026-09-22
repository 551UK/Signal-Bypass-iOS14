# Signal Bypass iOS 14

Experimental rootful compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.1.1: stability rollback

v1.1.0 caused Signal to close immediately on launch.

v1.1.1 restores the exact runtime constructor and hook ordering from v1.0.4, which was confirmed to open Signal normally on the test device. This build intentionally adds no new registration changes; it is a clean rollback so testing can continue from a stable launch state.

It retains the universal arm64 + arm64e dylib, 0755 permissions, persisted 8.29.0.1866 metadata and the existing registration compatibility hooks.
