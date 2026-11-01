# Additional endpoints found in the APK

Every entry names where it appears and what level of evidence supports it.
Nothing here is listed as functional on the strength of a string alone.

## Confirmed client-side network calls

### Game login host RPCs (same host the API already uses)

| Route | Evidence | Notes |
|---|---|---|
| `/GenerateNickname` | metadata RPC table; live 200 | Returns a server-issued nickname. Already implemented in the API. |
| `/MajorLogin` | metadata RPC table; live 200 | Implemented. |
| `/MajorRegister` | metadata RPC table; live 400 | Maps to `PlatformRegisterReq`. Needs a platform credential the API lacks. |
| `/GetLoginData` | metadata RPC table; live 401 | Requires a signed JWT. |
| `/MajorGuestBind` | metadata RPC table; live 401 | `PlatformGuestBindReq`. Requires a signed JWT. |
| `/MajorSecondaryAccountBind` | metadata RPC table | `PlatformSecondaryAccountBindReq`. |
| `/ActivateAccount` | metadata RPC table; live 401 | Requires a signed JWT. |
| `/UpdateAuthInspect` | metadata RPC table; live 401 | Requires a signed JWT. |

### Garena OAuth service (`com.beetalk.sdk.A0`)

| Route | Parameters recovered | Live result |
|---|---|---|
| `/api/v2/oauth/guest:register` | — | 200, returns uid |
| `/api/v2/oauth/guest/token:grant` | uid, password, response_type, client_type, client_id, client_secret, device_id | 200, returns open_id + access_token + platform |
| `/oauth/token/refresh` | grant_type=refresh_token, refresh_token, client_id, client_secret | 200, returns a fresh opaque token |
| `/oauth/token/exchange` | grant_type=authorization_code, code, redirect_uri, source, client_id, client_secret, login_scenario, device_id | `invalid_grant` for a guest-grant code |
| `/oauth/token/pgs/exchange` | google_auth_code, client_id, login_scenario, device_id | `error_params` |
| `/oauth/token/inspect` | token | `invalid_grant` / `invalid_request` |
| `/bind/app/platform/create` | — | not exercised |
| `/bind/app/platform/info/get` | — | not exercised |
| `/oauth/user/info/get` | — | not exercised |
| `/oauth/user/friends/get/v2` | — | not exercised |

Two request-encoding facts from `com.beetalk.sdk.networking.t`: form encoding by
default (`c.FORM`), and `redirect_uri = "gop" + client_id + "://auth/"`.

## Partially reconstructed

- **`server_url` / `ak` / `aiv` handoff.** `MajorLoginRes` carries
  `server_url`, `ak`, `aiv`, `kts`, `tp_url`, `app_server_id`. The field names
  are certain (metadata type table); the semantics are not. `ak`/`aiv` are very
  likely a rotating AES key and IV for the following session, and `server_url`
  is very likely the next host, but no response was captured that contains them,
  so neither is asserted as fact.
- **`PlatformRegisterReq` field usage.** Field names are certain
  (`access_token`, `platform_sdk_id`, `platform_register_info`,
  `register_signature`, `register_time`, `gin_report_data`, `is_newbie_choice`).
  Which fields are mandatory and how `register_signature` is computed is not
  recoverable from the metadata.
- **`GameConfig.SetOverrideGOPUrlFromVersion` / `OverrideGOPAuthUrl`.** Present
  in the metadata with log strings; indicates the GOP auth URL is version
  dependent. The version→URL mapping itself is not in the APK.

## Unverified candidates

- `version-internal.garenanow.com/sbt/` and `/sbt/ABHotUpdates/`, plus
  `sbt-auth.garenanow.com`, appear in the metadata URL list. They do not resolve
  from this environment (connection error), so they are listed as candidates
  only.
- `version.mocoindia.com/live/` (same situation).
- `chars.intro.{ind,sea,us}.freefiremobile.com/api/avatar` — avatar service,
  unrelated to login.

## Functionality requiring unavailable runtime evidence

- **The signed JWT.** Required by six routes. Not minted anywhere in the APK
  (`Jwt`, `JWT`, `SignToken`, `HS256`, `RS256` absent from the metadata). The
  issuer route refuses a guest-grant code. No way to produce it from the two
  supplied repositories.
- **The login host itself.** Not hardcoded; delivered as `server_url` in a
  login response. Static analysis cannot confirm or contradict the API's value.
- **Vodka voice protocol.** `base/http.proto` (`CSMajorLoginReq` with
  `app_key`/`app_secret`) and `base/signalingservice.proto` are a separate voice
  stack. Its `MajorLoginFailed` error code lives in `libil2cpp.so`. Not part of
  the game login path and deliberately not implemented.

## Explicitly not done

- No route was added to the API from this list. The candidates that are not
  already implemented all require the signed JWT, so adding them would produce
  endpoints that cannot work — the opposite of the requirement to avoid fake
  functionality.
