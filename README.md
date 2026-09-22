# Signal Bypass iOS 14

Experimental rootful compatibility tweak for Signal 7.19.1 (208) on iOS 14.

## Version 1.4.0: final registration User-Agent fix

v1.3.0 crashed on launch, so its pure-Swift expiry/update hooks have been removed completely.

The successful iOS 16 Signal 8.29 trace gave us a concrete reference:

- endpoint: `POST /v1/verification/session`
- User-Agent: `Signal-iOS/8.29.0.1866 iOS/16.2`
- X-Signal-Agent: absent
- response: HTTP 200

The failing iOS 14 capture showed that the server was still seeing the genuine Signal 7.19.1 / iOS 14 User-Agent and returning HTTP 499.

v1.4.0 therefore hooks the final concrete `NSURLSession` request methods used by Signal 7.19.1's `OWSURLSession`. For Signal verification-session traffic only, it replaces the User-Agent after Signal has finished preparing the request:

`Signal-iOS/8.29.0.1866 iOS/16.2`

Everything else is left untouched: URL, method, body, authorization, language headers, push token and response status are not modified.

This build does **not**:
- hook private Swift expiry functions
- rewrite HTTP 499
- add X-Signal-Agent
- modify registration JSON
- show diagnostic popups

The installer advances the local metadata identity to **8.29.0.1869** only to avoid reusing an exact AppExpiry identity from earlier tests. The server-facing User-Agent remains the genuine working **8.29.0.1866** identity.
