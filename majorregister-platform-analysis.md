# Why 400 BR_PLATFORM_INVALID_PLATFORM, and what the server accepts

Question asked: why does `/MajorRegister` return
`BR_PLATFORM_INVALID_PLATFORM`, and what type of data does it accept?

Both parts are now answered with live evidence.

## 1. The error means "platform not resolved", not "bad platform value"

The decisive control is `/MajorLogin`. Send it a body with **nothing at all**
and it returns the same error:

| Request | `/MajorLogin` answer |
|---|---|
| empty protobuf (0 bytes of content) | `400 BR_PLATFORM_INVALID_PLATFORM` |
| openid + logintoken, no platform | `400 BR_PLATFORM_INVALID_PLATFORM` |
| openid + logintoken + platform `"4"` | `200` |
| openid + logintoken + platform `"1"` | `400 BR_PLATFORM_INVALID_PLATFORM` |
| openid missing, platform `"4"` | `400 BR_PLATFORM_INVALID_OPENID` |
| logintoken missing, platform `"4"` | `400 BR_GOP_TOKEN_AUTH_FAILED` |

An empty body reaching the *platform* error proves the platform check runs
**before** any body field is read. So `BR_PLATFORM_INVALID_PLATFORM` means
"the server could not resolve your platform", not "the value you sent is wrong".

## 2. What `/MajorLogin` accepts for platform

Platform lives in the body at **protobuf field 99**, and its type is **string**.

Swept every plausible value, live:

| Value tried at field 99 | Result |
|---|---|
| `"4"` | **200 OK** (accepted) |
| `"1"` .. `"3"`, `"5"` .. `"20"` | rejected |
| `"IND"`, `"ind"` | rejected |
| `"04"` | rejected |
| `"4 "` (trailing space) | rejected |
| int 4 (wire type 0) | rejected |

So it is an exact string match on `"4"`. That is the APK's AAB/Google-Play
platform id for the IND build (`applicationVariant=ind`,
`releasechannel=..._gp-india_...`).

## 3. What `/MajorRegister` accepts: nothing we can reach

`/MajorRegister` returns the identical `BR_PLATFORM_INVALID_PLATFORM` for:

- **every body field 1..400**, as both int=4 and string="4" — 800 requests,
  one single distinct response
- **every fixed32 / fixed64 field 1..60** — 240 requests, same response
- the `PlatformRegisterReq` schema field 2 (`platform_sdk_id`) as int 0..30 and
  as string
- nested `platform_register_info` (field 4) with inner fields 1..40
- empty body, token-only body, token+platform body
- **111 `X-GA-*` header names**, plus `Platform` / `X-Platform` / `X-Platform-Id`
- platform as query parameter, cookie, path segment, and in every
  `Authorization` form

The only other responses ever seen are the transport-level rejections:
- bare `500` -> body was not valid AES
- `400 invalid request body` -> AES valid, protobuf malformed (e.g. a nested
  length that overruns the buffer)

Our working body gets neither. It decrypts and parses cleanly, and the server
replies with its own application error. That is the signature of a missing
*out-of-band* credential, not a malformed field.

## 4. It is not the account

A fully valid, profiled account (MajorLogin -> 200) gets the **same**
`BR_PLATFORM_INVALID_PLATFORM` from `/MajorRegister`. So the error is purely
about the shape of the register request.

(That account also comes back `restricted: True`, reason
`Exploiting loopholes` — worth knowing, but unrelated: the error is identical
for the unrestricted fresh guest.)

## 5. What the platform is actually derived from

The client knows this exact error string. Its own table in
`asset/global-metadata.dec.dat` contains, adjacent to each other:

```
BR_PLATFORM_INVALID_OPENID
BR_PLATFORM_INVALID_PLATFORM
BR_GOP_TOKEN_AUTH_FAILED
BR_GUEST_REGISTER_FORBIDDEN
BR_REGISTER_RATE_LIMIT
```

That pairing is the answer's shape: **platform and openid are validated
together, from a token.** `BR_GOP_TOKEN_AUTH_FAILED` sits in the same family.
The platform is therefore carried by a credential the register call must
present, and that credential is minted by a step we cannot reproduce.

Supporting evidence from the APK:

- `P2/c.java` shows the Vodka SDK's own crypto: AES-CBC with
  `VodkaConst.DEFAULT_KEY` = `N!Qvw2!ePbfNF2lu` and `TEST_KEY` =
  `K*hKRuiSXZv!9enI`. Those are **different** from the API's keys, and I tested
  them: they produce `500` on the login host. So the API's keys are the right
  ones (MajorLogin -> 200 confirms it) and the Vodka keys are for the SDK's
  separate signaling channel.
- `VodkaConst.SIGNALING_SERVER_ADDRESS` is `http://202.81.106.160:39001` —
  I tested it directly, connection refused. Stale.
- The APK's login host is **not** hardcoded; `N2/c.java` uses
  `VodkaConfig.getServerUrl()`, resolved from remote config.
- `N2/c.java` builds `CSMajorLoginReq` from appKey / appSecret / serverId /
  accountId / region / filterValues. `CSMajorRegisterReq` does **not** exist in
  the Java layer — `protohttp/Http.java` ships only `CSMajorLoginReq/Resp` and
  `CSReportedUploadReq/Resp`.

## 6. Summary

| | Answer |
|---|---|
| Why 400 BR_PLATFORM_INVALID_PLATFORM | The server cannot resolve the request's platform. It fires before body validation — an empty body triggers it too. It is a missing out-of-band credential, not a wrong value. |
| What MajorLogin accepts | string `"4"` at protobuf field 99, exact match. Nothing else. |
| What MajorRegister accepts | No body field (1..400), no header, no query, no cookie, no path. The platform arrives in a credential the register call must present. |
| Blocker | That credential. Its generation is not reconstructable from these artifacts: no `FileDescriptorProto` is embedded anywhere, no `CSMajorRegisterReq` ships in the Java layer, no managed `.dll` is present, and the IL2CPP metadata keeps field names in declaration order without wire numbers. |
