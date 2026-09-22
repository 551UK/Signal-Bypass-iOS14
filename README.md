# Signal Bypass iOS 14

## Version 1.4.2: side-by-side registration trace

This keeps the **v1.4.0 User-Agent fix** unchanged. That build removed the Update Required popup by forcing the final verification-session request to the exact identity observed in the successful iOS 16 trace:

`Signal-iOS/8.29.0.1866 iOS/16.2`

v1.4.2 adds detailed, sanitized logging so the iOS 14 attempt can be compared directly with the successful iOS 16 registration flow:

`POST session -> PATCH session -> POST /code -> PUT /code`

The log records for every verification-session request:

- sequence number
- method and redacted endpoint
- original User-Agent before rewrite
- final User-Agent after rewrite
- X-Signal-Agent, Content-Type and Accept-Language
- sanitized request JSON
- real HTTP status
- selected response headers
- sanitized response JSON
- network error domain/code

Sensitive values are redacted, including phone number, session ID, push token, captcha token, verification code, credentials and authorization values.

Log location:

`Signal/Documents/SignalBypass14-Registration.log`

No HTTP status rewriting, private Swift expiry hooks, request-body changes or diagnostic popups are used.

The local metadata identity remains **8.29.0.1870** so this logging build does not change another variable while we diagnose the spinner.
