# Signal Bypass iOS 14

## Version 1.4.4: required capability test

The verification flow is now fully accepted through:

`PUT /v1/verification/session/<session>/code -> HTTP 200 -> verified=true`

The next request is:

`POST /v1/registration`

v1.4.3 proved that request reaches Signal with the working Signal 8.29 User-Agent but the server returns:

`HTTP 499 - Missing required device capability`

The old client sends a legacy capabilities map. Current Signal-Server requires **SPQR** for new device registration.

v1.4.4 therefore keeps every working verification change untouched and modifies only the final account-registration JSON:

`accountAttributes.capabilities.spqr = true`

The server response is left genuine and is logged. No HTTP 499 rewriting is used.

### Important

This build is a compatibility test, not yet the final public solution. The older app's bundled LibSignalClient predates SPQR support, so even if this clears account creation we still need to validate message protocol compatibility before treating the tweak as finished.

Persistent sanitized log:

`Signal/Documents/SignalBypass14-Registration.log`
