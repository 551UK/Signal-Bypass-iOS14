# Signal Bypass iOS 14

## v1.4.5 — known-good clean login baseline

**v1.4.5 is preserved unchanged.** It is the first build confirmed to complete a fresh iOS 14 registration through:

`verification -> /v1/registration 200 -> /v2/keys 204`

Do not modify the v1.4.5 release/tag when testing later fixes.

## v1.4.6 — unsupported-iOS banner only

After successful login, Signal 7.19.1 can show:

`Signal no longer works on this device. To use Signal again, update your device to a newer version of iOS.`

This is not the normal app build-expiry timer. Signal 7.19.1 contains a separate `OsExpiry` rule with:

- minimum iOS: **15**
- enforced after: **2024-10-01 UTC**

Therefore changing `BuildDetails.Timestamp` / `DateTime` does not target this particular banner. Those fields feed the separate app-expiry calculation.

v1.4.6 is based on the exact v1.4.5 login/network code and adds one UI-only change: the runtime class `Signal.ExpirationNagView` is forced to stay hidden.

It does **not** globally spoof iOS, change UIDevice, alter registration requests, alter key uploads, rewrite server responses, or change BuildDate.m.

The registration trace remains at:

`Signal/Documents/SignalBypass14-Registration.log`
