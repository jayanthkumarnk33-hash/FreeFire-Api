# Which methods the APK uses for MajorLogin and MajorRegister

Everything below comes from the two supplied sources only: the Python API in
`api/` and the APK artifacts in `apk/` / `work/`. No external sources.

## 1. The client's RPC method registry

The game is Unity/IL2CPP. Its RPC method names live in one contiguous table in
`work/asset/global-metadata.dec.dat` (offset ~2666400). The relevant entries:

```
... GetAccountLifeSeasonStats  GetTeamMatchStatsHistory
    GenerateNickname  MajorLogin  MajorRegister  GetLoginData
    MajorGuestBind  MajorSecondaryAccountBind  SetAntiAddictionAgeState
    MajorGetGlobalLeaderboard  PlayerClaimRetentionReward ...
```

So the client's login-family "methods" are: `MajorLogin`, `MajorRegister`,
`GetLoginData`, `MajorGuestBind`, `MajorSecondaryAccountBind`,
`GenerateNickname`. Each is invoked as `POST /<MethodName>` against the login
server, with an AES-encrypted protobuf body.

Important: **no login host is hardcoded in the APK.** `N2/c.java` builds requests
from `this.f2722a.getServerUrl()`, and `VodkaConfig.Builder` defaults
`httpServer` to `VodkaConst.SIGNALING_SERVER_ADDRESS`. The real login host comes
from remote config at runtime. The hosts used by the Python API
(`loginbp.ggpolarbear.com`, `loginbp.ggblueshark.com`) are inherited from the
upstream repository's `Api/Account.py`, not from the APK.

## 2. MajorLogin — the method the APK uses

| Item | APK / live evidence |
|---|---|
| RPC name | `MajorLogin` (metadata RPC table) |
| HTTP | `POST /MajorLogin`, `Content-Type: application/octet-stream` |
| Body | protobuf, AES-128-CBC encrypted with the game key/IV |
| Transport headers | `X-GA: v1 1`, `X-GA-RV`, `X-GA-SV`, `X-Unity-Version`, `ReleaseVersion` |
| Java-side message | `CSMajorLoginReq` — `appKey`(1) `appSecret`(2) `accountId`(3) `region`(4) `filterValues`(5) `serverId`(6) |
| Game-side request | `MajorLoginReq` |
| Response | `MajorLoginRes` — `server_url`, `token`, `ak`, `aiv`, `queue_info`, ... |

The Python API's `Api/Account.py:get_major_login()` sends
`{openid:22, logintoken:29, platform:99="4"}` and this is **confirmed working
live** (HTTP 200 for an account with a profile; the configured account returns
`restricted: True`, reason `Exploiting loopholes`).

Platform value is pinned down exactly: field 99 is a **string**, and `"4"` is the
only value that proceeds. `"1","2","3","5","6"` all return
`BR_PLATFORM_INVALID_PLATFORM`.

Missing-field behaviour proves the field layout is right:

| Payload | MajorLogin answer |
|---|---|
| openid + logintoken + platform | `404 account_not_found` (or 200) |
| no platform | `400 BR_PLATFORM_INVALID_PLATFORM` |
| no openid | `400 BR_PLATFORM_INVALID_OPENID` |
| no logintoken | `400 BR_GOP_TOKEN_AUTH_FAILED` |

## 3. MajorRegister — the method the APK uses

| Item | Evidence |
|---|---|
| RPC name | `MajorRegister` (metadata RPC table) |
| HTTP | `POST /MajorRegister` — **route confirmed to exist** |
| Request message | **`PlatformRegisterReq`** |
| Response message | `MajorRegisterRes` (`is_nickname_success`) + `PlatformRegisterRes` |

`PlatformRegisterReq` fields, in declaration order from the metadata
(offset ~2770730):

```
1  access_token
2  platform_sdk_id
3  editor_register_key
4  platform_register_info
5  is_newbie_choice
6  register_signature
7  register_time
8  gin_report_data
```

`PlatformRegisterRes`: `first_game_open`, `br_tutorial_open`, `cs_tutorial_open`,
`cs_abtest`, `basic_guide_open`, `mode_teach`, `basic_tutorial_voice_open`,
`pop_up1_open`, `pop_up2_open`, `br_second_open`, `is_cs_first`, ...

The client flow that uses it (from metadata method names):
`UIModelLogin.RequestPlatformRegister()` -> `PlatformRegister` ->
`UIModelLogin.RequestRegionChoose()` -> `RequestGetPlatformProfile()`.
There is also a local helper `CreateChooseNewbieChoiceResByRegister()`.

### The route exists — proof
Against the same host, with the same headers:

| Path | Answer |
|---|---|
| `/NoSuchRouteZzz` | `404 page not found` |
| `/PlatformProfile` | `404 page not found` |
| `/MajorRegister` | `400 BR_PLATFORM_INVALID_PLATFORM` |

A missing route returns 404. `/MajorRegister` does not, so it is served.

### Why the Python API still fails here
`GenerateAccounts.py` posts **MajorLogin's** message (`openid`@22, `logintoken`@29,
`platform`@99) to `/MajorRegister`. The correct message is `PlatformRegisterReq`.
The service decrypts the payload successfully — invalid AES yields a bare 500,
valid AES yields the structured platform error — and then rejects it because the
register message is not what arrived.

Evidence that MajorRegister reads platform from somewhere else than MajorLogin:
it returns `BR_PLATFORM_INVALID_PLATFORM` for **every** payload tried, including
the exact payload MajorLogin accepts, whereas MajorLogin returns distinct errors
(`INVALID_OPENID`, `GOP_TOKEN_AUTH_FAILED`) for the corresponding omissions.

### What is missing
The **wire field numbers** for `PlatformRegisterReq`. The metadata stores the
field names in declaration order but does not expose the numbering, and no
embedded `FileDescriptorProto` exists in the artifacts (searched every `.dex`,
every `.so` and the metadata for length-delimited field-name encodings — none
found). `protohttp/Http.java` contains only `CSMajorLoginReq/Resp` and
`CSReportedUploadReq/Resp`, so the register message is not in the Java layer
either.

## 4. New working endpoint found: `/GenerateNickname`

`GenerateNickname` is in the RPC table, with `CSGenerateNicknameReq` /
`CSGenerateNicknameRes`. Posting the MajorLogin payload to `/GenerateNickname`
returned **HTTP 200** with a real generated nickname:

```
body (14 bytes): 0a 0c 4f 6d 65 67 61 35 77 34 65 30 56 34
decoded        : field 1 (string) = "Omega5w4e0V4"
```

This is an unencrypted protobuf response (plain varint + length-delimited
string), and it is a genuine server-generated value, not an echo.

## 5. New finding: some login routes require a JWT

These returned `401 token contains an invalid number of segments`:

| Path | Answer |
|---|---|
| `/MajorGuestBind` | `401 token contains an invalid number of segments` |
| `/MajorSecondaryAccountBind` | `401 token contains an invalid number of segments` |
| `/GetLoginData` | `401 token contains an invalid number of segments` |

That message is the standard Go JWT parser error, so these routes expect a
three-segment JWT rather than the opaque 64-char Garena access token. The guest
token grant response contains no JWT (checked every field), so the JWT must be
minted by a later step. `/MajorRegister` does **not** return this error, so it is
not JWT-gated in the same way.

## 6. Summary answer

- **MajorLogin**: the APK uses `POST /MajorLogin` with `MajorLoginReq` /
  `CSMajorLoginReq`, AES-CBC protobuf, `X-GA`/`X-GA-RV`/`X-GA-SV` headers. The
  Python API matches this and works.
- **MajorRegister**: the APK uses `POST /MajorRegister` with
  **`PlatformRegisterReq`**. The Python API sends MajorLogin's message instead.
  The route is live; the message field numbers are the missing piece.
- Additional login-family methods the APK uses: `GenerateNickname` (works),
  `GetLoginData` / `MajorGuestBind` / `MajorSecondaryAccountBind` (JWT-gated),
  `PlatformProfile`.
