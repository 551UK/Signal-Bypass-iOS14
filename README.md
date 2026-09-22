# Signal Bypass iOS 14

## Stable checkpoints

- **v1.4.5** — known-good fresh login/registration.
- **v1.4.6** — same working login plus unsupported-iOS banner suppression.
- **v1.4.7** — v1.4.6 baseline plus post-login WebSocket and CDSI compatibility.

The earlier releases/tags remain unchanged.

## v1.4.7 — Find by Phone Number / WebSocket compatibility

After login, FLEX showed three useful facts:

1. `GET /v2/directory/auth` already succeeds with HTTP 200 and the Signal 8.29 User-Agent.
2. The old identified chat WebSocket still uses `login` and `password` URL query parameters and receives a bad server response.
3. The old anonymous WebSocket still targets `ud-chat.signal.org`, which no longer resolves.

Current Signal-Server expects authenticated WebSocket credentials as HTTP Basic Authorization. v1.4.7 therefore moves the existing credentials from the URL query into the `Authorization` header and removes them from the URL. It also maps the retired anonymous host to `chat.signal.org`.

### CDSI enclave update

Signal 7.19.1 embeds an obsolete Contact Discovery Service enclave identity:

`0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57`

The supplied Signal 8.29 IPA's LibSignalClient 0.102.0 contains:

`15637fa1e54fe655176d3df1a9f94b87c01ed377acaa570682dc5d72c95ef07b`

v1.4.7 replaces the old 64-byte string **in memory only** inside the loaded SignalServiceKit image before CDSI initializes. This updates both the `/v1/<mrenclave>/discovery` path produced by the old code and the enclave value passed into its existing Cds2Client attestation logic.

No app binary is modified on disk.

### Unchanged from v1.4.6

Registration/session behavior, `spqr=true`, `POST /v1/registration`, `PUT /v2/keys`, the existing HTTP User-Agent rewrite, and the expiry-banner hook are unchanged.

Persistent sanitized trace:

`Signal/Documents/SignalBypass14-Registration.log`
