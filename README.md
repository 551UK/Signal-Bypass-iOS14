# Signal Bypass iOS 14

## v1.4.5 — known-good clean login baseline

v1.4.5 is preserved unchanged.

## v1.4.6 — known-good login + banner baseline

v1.4.6 is preserved unchanged and is the baseline for the next compatibility work.

## v1.4.8 — normal chat WebSocket compatibility only

v1.4.8 is rebuilt directly from v1.4.6. It intentionally does **not** include the CDSI/contact-discovery experiment from v1.4.7.

FLEX showed Signal 7.19.1 attempting:

`chat.signal.org/v1/websocket/?login=...&password=...`

and receiving a bad server response. It also attempted the old anonymous host:

`ud-chat.signal.org/v1/websocket/`

which no longer resolves.

The old app also sent its old User-Agent on those WebSocket upgrades.

v1.4.8 changes only that transport layer:

- `ud-chat.signal.org` is routed to `chat.signal.org`
- legacy `login` / `password` query parameters are removed
- identified WebSocket credentials are moved to HTTP Basic `Authorization`
- anonymous WebSocket remains unauthenticated
- WebSocket User-Agent becomes `Signal-iOS/8.29.0.1866 iOS/16.2`

Registration, SPQR, `/v1/registration`, `/v2/keys`, the existing REST UA rewrite, and the unsupported-iOS banner fix are copied unchanged from v1.4.6.

The trace remains at:

`Signal/Documents/SignalBypass14-Registration.log`

WebSocket log lines contain only host/path/auth-mode information and never the login/password values.
