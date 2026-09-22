# Signal Bypass iOS 14

Experimental rootful compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.0.3: definitive runtime marker

The popup was not a reliable injection test because Signal may not have a view controller ready when the delayed alert fires.

v1.0.3 is based on the last known-compiling rootful package layout and writes a marker immediately when the dylib constructor runs, before hook setup or version checks.

After installing, fully close Signal, respring and open it once. Then check Signal's Documents directory for:

`SignalBypass14-runtime-marker.txt`

If that file exists, runtime dylib injection is confirmed even if no popup appears. The file contains only the tweak version, process name, PID and bundle identifier.

The build otherwise retains the universal arm64 + arm64e dylib, 0755 permissions, persisted 8.29.0.1866 metadata and existing registration compatibility hooks.
