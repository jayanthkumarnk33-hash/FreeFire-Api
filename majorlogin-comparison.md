# APK vs Python API — MajorLogin comparison

Each row separates what the APK proves from what the live service proves. Where
the APK is silent, the row says so rather than guessing.

| Component | APK evidence | Python API implementation | Finding |
|---|---|---|---|
| Login host | Not present anywhere in the APK. `MajorLoginRes.server_url` is the only source. | `MAJOR_LOGIN_URL = https://loginbp.ggpolarbear.com/MajorLogin` | Unverifiable from the APK. The host is learned from a response, so it cannot be contradicted or confirmed by static analysis. |
| HTTP method | `N2/c.java` builds a POST with `application/octet-stream` | `requests.post` | Match |
| `X-GA` header | `N2/b.java:210`, `N2/c.java:37` send `X-GA: "v1 1"` | `X_GA = "v1 1"` | Match |
| `ReleaseVersion` / `X-GA-RV` | Build string is `FFO_OB55_...` | `OB55` | Match. Live: `OB55`→200, `OB53`→200, `1.134.1`→503, `OB50`→503, `OB56`→503 |
| `X-Unity-Version` | `globalgamemanagers` says `2018.4.12f1`; `libunity.so` says `2018.4.12f1` | `2022.3.47f1` | **Mismatch (config), not load-bearing.** A/B test: no effect on the response |
| Client id | manifest `com.garena.sdk.applicationId = 100067` | `GARENA_CLIENT_ID = 100067` | Match |
| OAuth source | `helper/t.k()` → `ApplicationSourceId`, default `2` | not sent | API does not use the interactive exchange, so N/A |
| Request message | Field 22 `openid`, field 29 `logintoken`, field 99 `platform` | same | Match |
| Platform value | OAuth grant returns `platform:4`, `main_active_platform:4` | `"4"` | Match |
| Encryption | AES-CBC, 16-byte IV, PKCS padding (`P2/c.java`) | `MAIN_KEY` / `MAIN_IV`, CBC + pad | Match |
| AES key/IV values | APK `VodkaConst`: key `N!Qvw2!ePbfNF2lu`, IV `K*hKRuiSXZv!9enI` | key `Yg&tc%DEuh6%Zc^8`, IV `6oyZDr22E3ychjM%` | **Different values, but the API's are correct for the game login path** — confirmed by MajorLogin 200. The APK pair belongs to the Vodka voice SDK, a separate protocol. |
| Response framing | not visible in the APK | 64-byte prefix then protobuf | Works live; prefix is opaque and constant |
| Response schema | `MajorLoginRes` field list recovered from metadata (fields 1,8,10,13,15,18,19,20,21…) | `MajorLogin_pb2.response` | Match — decoded fields 13 and 15 line up exactly |
| `queue_info.reason` | metadata declares a field there | declared as `string` | Match with live bytes |
| Failure on new account | `PropID_LoginRetNewUser` then `PropID_RegisterSuccess` exist as separate ret codes | HTTP 404 was raised as a generic error | **Fixed** — see `majorlogin-fix.md` |

## Differences that matter, and why

### 1. The API treats "new account" as a failure (fixed)

Live: `/MajorLogin` for a fresh guest answers

```
HTTP 404  {"type": "account_not_found", "msg": "account not found", ...}
```

The client has a dedicated ret code for exactly this (`PropID_LoginRetNewUser`),
sitting next to `PropID_RegisterSuccess`. It is the expected state for an
account that has an OAuth identity but no game profile, and the client answers
it by registering. The API raised `MajorLoginError` for every non-200, so a new
guest produced a generic 500/401 instead of a clear "not registered yet".

This is the "404" seen in testing. It is not the login host being wrong and not
a protocol change.

### 2. Unity version string (config only)

The APK is a Unity 2018.4.12f1 build; the API claims 2022.3.47f1. Live A/B shows
the header is not validated, so this does not cause failures today. Left as-is
pending evidence that it matters, but recorded because it is a genuine
divergence from the artifact.

### 3. The register path is not the platform path

`MajorRegister` maps to `PlatformRegisterReq` (platform accounts). Guests have
`PlatformGuestBindReq` (`guest_open_id`, `guest_platform_type`,
`guest_access_token`). The API has no guest bind step. This matters because the
`BR_PLATFORM_INVALID_PLATFORM` result from `MajorRegister` is consistent with
calling a platform-registration RPC without a platform credential.

### 4. The token the API holds is not the token these routes want

`/GetLoginData`, `/MajorGuestBind`, `/ActivateAccount`, `/UpdateAuthInspect` all
answer `401 token contains an invalid number of segments` for the OAuth
`access_token`. A well-formed JWT moves the failure to `401 key is of invalid
type` (signature step). So those routes need a signed JWT that this API has no
way to obtain: the APK does not mint one, and the OAuth exchange that would
(`/oauth/token/exchange`) refuses a guest-grant code with `invalid_grant`.

## What could not be reconstructed

- The login host: not in the APK by design.
- A signed JWT: not produced by any code path in the supplied artifacts.
- The `MajorLogin` request field list: absent from the metadata (only the
  response schema is present), so the API's `MajorLogin.proto` request field
  numbering rests on the live 200 result, not on the APK.
