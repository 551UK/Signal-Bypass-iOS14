# Signal Bypass iOS 14

## Version 1.4.3: continue past verified SMS code

The v1.4.2 trace proved the complete verification-session flow is now accepted by Signal's server:

`POST session -> PATCH challenge -> POST /code -> PUT /code -> verified=true`

The next request in Signal's registration coordinator is:

`POST /v1/registration`

That request creates or re-registers the account using the already-verified session ID.

v1.4.3 keeps the working verification-session rewrite unchanged and extends the same final `NSURLSession` User-Agent identity to `/v1/registration`:

`Signal-iOS/8.29.0.1866 iOS/16.2`

Nothing else in the request is rewritten. In particular, the session ID, authorization, account attributes, prekeys and response status are left as Signal generated them.

### Logging

The same log now covers both stages:

- `/v1/verification/session...`
- `/v1/registration`

The log is no longer erased when Signal launches. Each app start adds a **NEW SIGNAL LAUNCH** separator, so a successful attempt is preserved even if Signal restarts.

Sensitive values are redacted more aggressively, including the phone number, session ID, push challenge, tokens, auth values, UUID/account identifiers, passwords and cryptographic key/prekey material.

Log location:

`Signal/Documents/SignalBypass14-Registration.log`

The local metadata identity stays at **8.29.0.1870** so this build changes only the next network compatibility stage and diagnostics.
