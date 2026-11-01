# Final status: what works, what is blocked, and the exact evidence

## Objective
Generate a guest account, register it on the live server, authenticate, then look
up a separate target player UID (`11111111`, IND) through the main API.

## Honest result

| Step | Status | Evidence |
|---|---|---|
| 1. Guest account generation | **WORKS** | live `POST connect.garena.com/api/v2/oauth/guest:register` -> uid |
| 2. Credential persistence | **WORKS** | saved to `Configuration/AccountConfiguration.generated.json` |
| 3. Guest authentication | **WORKS** | token grant HTTP 200, 64-char access_token + open_id |
| 4. MajorLogin (main API auth) | **WORKS for profiled accounts** | HTTP 200; new guests -> `account_not_found` |
| 5. `/GenerateNickname` (new, added) | **WORKS** | live 200 -> `Paka7e0n4L4`, `Omega5w4e0V4`, `Yver1L7L5X0Y` |
| 6. In-game profile creation (MajorRegister) | **BLOCKED** | always `400 BR_PLATFORM_INVALID_PLATFORM` |
| 7. Target UID `11111111` lookup | **BLOCKED** | needs step 6 |

The end-to-end goal is **not** achieved. Steps 1-5 are verified working against the
live server. Step 6 has a concrete, documented blocker. Step 7 depends on step 6.

## The blocker, precisely

`POST /MajorRegister` exists and is served. It decrypts our AES-CBC payload
correctly and then rejects it with its own code `BR_PLATFORM_INVALID_PLATFORM`.

Proof the route exists (same host, same headers, known-bad body):
| Path | Answer |
|---|---|
| `/NoSuchRouteZzz` | `404 page not found` |
| `/PlatformRegister` | `404 page not found` |
| `/MajorRegister` | `400 BR_PLATFORM_INVALID_PLATFORM` |

Proof the payload decrypts: an invalid AES body yields a bare `500`; a valid
AES-CBC body yields the structured `400`. So the key/IV and transport are right.

## What was tried to clear it (all failed, all documented)

Body field sweeps on `POST /MajorRegister` with valid AES:
- MajorLogin schema: string field N = `"4"` for N in 1..101 -> all rejected
- int field N = 4 for N in 1..130 -> all rejected
- `PlatformRegisterReq` field 2 (`platform_sdk_id`) int 0..30 and string -> all rejected
- nested `platform_register_info` (field 4) variants -> all rejected
- nickname from `/GenerateNickname` appended at string fields 1..14 -> all rejected
- kitchen sink: every field 1..120 populated (5 different int/string schemes,
  240+ field/value combinations) -> all rejected
- `access_token`+`platform_sdk_id` permutations across fields 1..4 -> all rejected

Other transports:
- platform as HTTP header (`Platform`, `X-Platform`, `X-GA-Platform`, ...) -> all rejected
- platform as query parameter (5 names) -> all rejected
- platform as cookie (3 forms) -> all rejected
- platform in the path -> `404`
- `Authorization` variants (Bearer token/openid/JWT, raw, X-Auth-Token) -> no change
- `Content-Type` json / form / text / octet-stream -> no change (json+form -> 500)
- JSON and form-encoded bodies using the exact APK field names -> 500
- X-GA / X-GA-RV / X-GA-SV format variants -> no change
- both hosts, OB50/OB53/OB55, API AES keys and APK AES keys -> no change

Kitchen sink is the decisive experiment: if platform were any body field at all,
populating every field would have satisfied it. It did not.

## The missing evidence

`PlatformRegisterReq` **wire field numbers**. Confirmed absent from the supplied
artifacts:
- IL2CPP `global-metadata.dat` stores field names in declaration order only
- no embedded `FileDescriptorProto` anywhere (searched every `.dex`, every `.so`
  including `libil2cpp.so` / `libFFWebRequest.so`, and the metadata, for
  length-delimited field-name encodings)
- `protohttp/Http.java` has only `CSMajorLoginReq/Resp` and `CSReportedUploadReq/Resp`
- the 306 MB asset pack is Unity serialized assets (44,379 files), not descriptors
- no `.dll` assemblies ship (fully stripped IL2CPP)

## New findings this session (verified)

1. **`/GenerateNickname` works.** APK RPC-table entry; plain protobuf response
   (`0a0c...` -> field 1 string). Now implemented in `Api/Account.py`.
2. **Client RPC registry** recovered from metadata (~2666400):
   `MajorLogin, MajorRegister, GetLoginData, MajorGuestBind,
   MajorSecondaryAccountBind, GenerateNickname, PlatformProfile`.
3. **Some login routes are JWT-gated**: `/MajorGuestBind`,
   `/MajorSecondaryAccountBind`, `/GetLoginData` -> `401 token contains an invalid
   number of segments`. The guest token grant returns no JWT.
4. **`PlatformRegisterReq` field names** recovered (declaration order):
   `access_token, platform_sdk_id, editor_register_key, platform_register_info,
   is_newbie_choice, register_signature, register_time, gin_report_data`.
5. **App identity confirmed**: manifest `com.garena.sdk.applicationId=100067`,
   `applicationVariant=ind`, `ApplicationSourceId=2` — the API's client_id is right.
6. **MSDK signature scheme confirmed**: HMAC-SHA256 -> `Authorization: Signature <hex>`
   (`com/beetalk/sdk/networking/interceptor/a.java`, `helper/F.java`). The Python
   generator already does this correctly for register.
7. The APK bundles `io.jsonwebtoken`, but only for LINE SDK id-token parsing
   (`p193t6/a.java`) — not for game auth.

## What would unblock it
The `PlatformRegisterReq` field numbering. It is not in these artifacts. It needs
either a build that ships the client-side protobuf, or a device capture of one
real first-login. Everything on our side is correct: transport, AES, headers,
token, signature, endpoint, and payload decryption.

## Correction to earlier sessions
`loginbp.ggpolarbear.com` / `loginbp.ggblueshark.com` are **not** APK-derived. A
byte scan of every APK artifact finds them only in this session's scratch scripts
and the upstream repo's `Api/Account.py`. The APK resolves its login host from
remote config (`VodkaConfig.getServerUrl()`).
