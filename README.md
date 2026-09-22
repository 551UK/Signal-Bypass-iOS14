# Signal Bypass iOS 14

## Known-good baselines

- **v1.4.5**: first confirmed fresh registration/login baseline.
- **v1.4.6**: same working login plus unsupported-iOS banner suppression.

Those releases remain unchanged.

## v1.5.0 — use Signal 7.19.1's built-in libsignal chat transport

The post-login failure is now isolated from registration.

Observed on the iOS 14 client:

- registration completes
- `PUT /v2/keys` completes
- `GET /v1/certificate/delivery` returns 200
- outgoing messages remain spinning before an actual `/v1/messages` submission
- incoming messages sent from a working iOS 16 client remain at one tick
- the legacy Signal 7.19.1 SSK websocket does not establish a usable chat connection

Signal 7.19.1 already includes a second chat transport backed by `LibSignalClient.Net`. The app chooses between the two very early at startup using app-group UserDefaults.

v1.5.0 forces:

`UseLibsignalForIdentifiedWebsocket = YES`

`UseLibsignalForUnidentifiedWebsocket = YES`

and disables the old unidentified shadowing path.

This is done before `ChatConnectionManagerImpl` is created. No websocket URL or auth-header rewriting from the earlier experiments is included.

All known-good registration, SPQR, key-upload and banner behavior is preserved.

The local spoof build is advanced to **1872** while keeping the 2027 BuildDetails timestamp so a prior persisted AppExpiry state cannot be reused.
