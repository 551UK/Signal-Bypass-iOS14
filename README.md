# Signal Bypass iOS 14

Experimental rootful compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.1.0: registration path, not injection

The v1.0.3 launch change demonstrated that the runtime dylib is loading. The missing Documents file and delayed popup were therefore poor injection tests.

v1.1.0 fixes a more important problem in the constructor: previous builds required both `MSHookMessageEx` and `MSHookFunction`. If the rootful hook provider exposed the message hook but not the function hook, the constructor returned before installing **any** of the expiry, networking or alert hooks.

v1.1.0 now:

- requires only `MSHookMessageEx`, matching the primitive used by the supplied working FuckSignalExpiry tweak
- installs the Objective-C AppExpiry hooks even if `MSHookFunction` is unavailable
- keeps the exact 8.29.0.1866 persisted metadata
- installs the request/User-Agent and HTTP diagnostics regardless of private Swift hook availability
- attempts the private Swift hooks only when `MSHookFunction` exists
- removes the process-name restriction from the startup log
- appends a compact `SB14 v1.1` diagnostic line to the real **Update Required** alert

After installing and respringing, reproduce registration once. If Update Required still appears, send a screenshot of the whole alert; the SB14 line is more useful than a Documents log.
