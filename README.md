# Signal Bypass iOS 14

## Version 1.4.5: continue through authenticated Signal service requests

The v1.4.4 trace proves account creation now succeeds:

`PUT verification code -> HTTP 200 -> verified=true`

`POST /v1/registration -> HTTP 200`

The registration request is accepted after adding the currently server-required:

`accountAttributes.capabilities.spqr = true`

Immediately afterward, Signal uploads its prekeys:

`PUT /v2/keys`

FLEX showed that request still used the old client identity:

`Signal-iOS/7.40.0.1870 iOS/18`

and Signal returned an empty HTTP 499.

### v1.4.5 change

The proven final identity:

`Signal-iOS/8.29.0.1866 iOS/16.2`

is now applied to **all requests to `chat.signal.org`**, rather than only the verification and account-registration endpoints.

This keeps the server-facing identity consistent once the account has been created and prevents the same remote client-deprecation gate from reappearing immediately on `/v2/keys` or another chat-service endpoint.

The tweak still does **not** rewrite HTTP statuses or server responses. `/v2/keys` request data is left exactly as Signal generated it.

### Logging

Persistent logging remains at:

`Signal/Documents/SignalBypass14-Registration.log`

The trace now includes `/v2/keys`. Its large key-upload body is omitted automatically. Access-key fields are also redacted more aggressively.

### Compatibility note

Current Signal-Server required the old client to advertise SPQR before it would create the device. The old app's actual long-term SPQR/message-protocol compatibility still needs testing before this should be treated as a finished public compatibility solution.
