# APK-derived evidence for the login protocol

Every claim below names the artifact it came from. Nothing is inferred from an
embedded string alone; each finding is tied to a class, a message schema, or a
live response.

## Artifacts used

| Artifact | What it contains |
|---|---|
| `base/classes.dex`, `classes2.dex`, `classes3.dex` | Garena MSDK / Beetalk SDK Java |
| `base/AndroidManifest.decoded.xml` | package id, version, SDK meta-data |
| `asset/global-metadata.dec.dat` | IL2CPP metadata (game assembly strings + type tables) |
| `config/lib/arm64-v8a/*.so` | native libraries |
| `base/*.proto` | Vodka SDK protocol definitions |
| `base/assets/android/versioninfo` | build version |

## 1. Identity of this build

From `base/AndroidManifest.decoded.xml`:

```
package      com.garena.game.ffi
versionName  1.134.1
versionCode  2019121269
com.garena.sdk.applicationId       100067
com.garena.sdk.ApplicationSourceId 2
com.garena.sdk.applicationVariant  ind
```

From `asset/global-metadata.dec.dat`:

```
FFO_OB55_PRELive_1.134.1_2019121269_4653253_gp-india_unity2022_aab_sidekick_extend...
```

So the API's `RELEASEVERSION = "OB55"`, `GAME_VERSION = "1.134.1"`,
`GARENA_CLIENT_ID = "100067"` all match this APK. `source = 2` matches
`helper/t.k()`, which reads `com.garena.sdk.ApplicationSourceId` with default 2.

## 2. Unity version — API value does not match this build

`asset/assets/bin/Data/globalgamemanagers` reports:

```
2018.4.12f1
```

`config/lib/arm64-v8a/libunity.so` contains `2018.4.11f1`, `2018.4.12f1`,
`2018.3.0a1`. The API sends `X-Unity-Version: 2022.3.47f1`.

Live A/B test on `/MajorLogin` with the same account and body: the header value
made no difference (200 for `2022.3.47f1`, `2018.4.12f1`, `2018.4.11f1`, and
when omitted entirely). So this is a real mismatch in the API's config but it is
not currently load-bearing.

## 3. Where the login host lives — not in this APK

Searched every artifact (all three dex files, the metadata, every `.so` in
`config/lib/arm64-v8a`, all asset files) for `ggpolarbear`, `blueshark`,
`loginbp`, `clientbp`. Zero occurrences.

The APK never hardcodes the game login host. `MajorLoginRes` returns it:

```
MajorLoginRes
  agora_environment
  new_active_region
  recommend_regions
  server_url        <-- the game/login server the client should use
  queue_info
  tp_url
  app_server_id
  ip_city
  ip_subdivision
  kts
  ak
  aiv
  ffanti_url
  ff_anti_config_desc
  connection_seed_enabled
  connection_seed
```

`ak` and `aiv` are almost certainly a rotated AES key and IV handed to the
client at login; `server_url` is the host to continue on. `libil2cpp.so` and
`libFFWebRequest.so` contain no login host either, which is consistent with the
host arriving in the response.

This is why the API's `MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"`
is not something the APK can confirm or deny — the APK would have learned it
from a previous response.

## 4. Login-family RPC names (client method table)

From the metadata method registry:

```
GenerateNickname
MajorLogin
MajorRegister
GetLoginData
MajorGuestBind
MajorSecondaryAccountBind
ActivateAccount
UpdateAuthInspect
MajorGetGlobalLeaderboard
```

The client tracks these outcomes as distinct ret codes, including:

```
PropID_LoginRetOK   PropID_LoginRetNewUser   PropID_RegisterSuccess
PropID_MajorLoginSuccess   PropID_MajorRegisterResponed
PropID_GetLoginDataSuccess   PropID_PlatformBindSuccess
PropID_GuestBindSuccess   PropID_SDKLogin
```

`PropID_LoginRetNewUser` next to `PropID_RegisterSuccess` is the client's own
statement that "new user" is a normal state that is followed by registration,
not a hard failure.

## 5. Register / bind request schemas

From the metadata type table:

```
PlatformRegisterReq
  access_token
  platform_sdk_id
  editor_register_key
  platform_register_info
  is_newbie_choice
  register_signature
  register_time
  gin_report_data

PlatformGuestBindReq
  guest_open_id
  guest_platform_type
  guest_access_token
  client_type
  ip_address

PlatformSecondaryAccountBindReq
  secondary_open_id
  secondary_platform_type
  secondary_access_token

PlatformProfileReq
  external_icon_filter
```

Note the naming: `MajorRegister` corresponds to **platform** registration
(`PlatformRegisterReq`), and the guest path has its own bind message. A guest is
not registered through a platform account flow.

## 6. The game server requires a JWT, not the OAuth token

Live probe of the login host with a valid OAuth `access_token`:

| Route | With `Bearer <64-char access_token>` | With no header |
|---|---|---|
| `/GetLoginData` | `401 token contains an invalid number of segments` | `401 missing Authorization header` |
| `/MajorGuestBind` | `401 token contains an invalid number of segments` | `401 missing Authorization header` |
| `/ActivateAccount` | `401 token contains an invalid number of segments` | — |
| `/UpdateAuthInspect` | `401 token contains an invalid number of segments` | — |

`token contains an invalid number of segments` is a JWT parser rejecting a
token that has no `.` separators. Sending a structurally valid JWT
(`header.payload.signature`, base64url) changes the answer to
`401 key is of invalid type`, i.e. failure at the **signature** step, after
successful parsing. Also, `/GetLoginData` with `Authorization: <token>` (no
`Bearer`) answers `Authorization header must be Bearer {token}`, and with
`Bearer <open_id>` answers the same segments error — so the header shape is
enforced and the value is parsed as a JWT.

`/MajorLogin` is the exception: it accepts the opaque token.

## 7. Where the JWT could come from

The APK does not mint it. `Jwt`, `JWT`, `EncodeJwt`, `CreateJwt`,
`GenerateToken`, `SignToken`, `HS256`, `RS256` are all absent from the IL2CPP
metadata. The bundled `io.jsonwebtoken` (JJWT) classes in `classes3.dex` are
only referenced by the LINE SDK.

The OAuth service carries the routes (`com.beetalk.sdk.A0`):

```
A0.f() -> /oauth/token/pgs/exchange    google_auth_code, client_id, login_scenario, device_id
A0.g() -> /oauth/token/exchange        grant_type=authorization_code, code, redirect_uri,
                                       source, client_id, client_secret, login_scenario, device_id
A0.C() -> /api/v2/oauth/guest/token:grant
A0.P() -> /api/v2/oauth/guest:register
A0.i() -> /oauth/token/refresh
```

Two encoding facts recovered from `com.beetalk.sdk.networking.t`:

- the request builder defaults to form encoding (`c.FORM`), not JSON
- `redirect_uri` is built as `"gop" + client_id + "://auth/"` (`C0982g0.java:45`)

Live behaviour of those routes:

| Call | Result |
|---|---|
| `guest/token:grant` with `response_type=code` | 200, returns `code` + `platform:4` + `main_active_platform:4` |
| `/oauth/token/exchange` with that code, form-encoded, `redirect_uri=gop100067://auth/` | `{"error":"invalid_grant"}` |
| `/oauth/token/exchange` same but JSON | `{"error":"invalid_request"}` |
| `/oauth/token/refresh` with `refresh_token` (no `device_id`) | 200, returns a fresh **64-char opaque** `access_token` |

The refresh route confirms the token the OAuth service issues is opaque, not a
JWT. The exchange refuses a guest-grant code with `invalid_grant`.

## 8. Vodka SDK (voice) protos

`base/http.proto`, `base/account.proto`, `base/signalingservice.proto` are the
Vodka voice SDK, not the game login protocol:

```
CSMajorLoginReq  { app_key, app_secret, account_id, region, filter_values, server_id }
```

This is a different, smaller message from the game's `MajorLogin`. `N2/c.java:37`
shows the Vodka client sending `X-GA: v1 1` plus `VodkaSDKVersion` to
`VodkaConfig.getServerUrl()` (= `httpServer + SIGNALING_SERVER_PATH`), and
`libil2cpp.so` contains a `MajorLoginFailed` Vodka error code. Both protocols
exist side by side; they must not be conflated.

## 9. Response schema the API must decode

Live 200 response from `/MajorLogin` for a profiled account, decoded with the
API's `MajorLogin_pb2.response`:

```
queueInfo { allow: true, needWaitSecs: 1781577563, reason: "Exploiting loopholes" }
appServerId { serverId: 1 }
```

No `token` and no `serverUrl` are present. Field numbers 13 and 15 line up with
the metadata declaration, so the API's field numbering is correct for this
build.

## 10. Unity version reality check

`X-Unity-Version` is the only client-version header the API sends that this APK
contradicts (section 2). `X-GA` is confirmed by `N2/b.java:210` and `N2/c.java:37`
(`"v1 1"`). `ReleaseVersion`/`X-GA-RV` must be `OB55`/`OB53`-class values; live
test: `OB55` → 200, `OB53` → 200, `1.134.1` → 503, `OB50` → 503, `OB56` → 503.
