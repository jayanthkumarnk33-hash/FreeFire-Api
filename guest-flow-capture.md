# Live capture: what actually happens when a brand-new user registers as a guest

I created a real guest account and recorded every response from every hop.
Account used: uid `8389831992` (IND). Nothing below is simulated.

## The flow, exactly as the APK performs it

`com.beetalk.sdk.n0.java` is the guest-login handler. It runs:

1. `j.z()` -> `POST connect.garena.com/api/v2/oauth/guest:register`
2. `n0.i(uid, password)` -> `j.t()` -> `j.c()` -> `POST .../api/v2/oauth/guest/token:grant`
3. hands the granted token to the game SDK (`C0975d.e`)

The redirect used by the code path is `"gop" + client_id + "://auth/"`
(`C0982g0.java:45`), and `source` is `ApplicationSourceId`, default `2`
(`helper/t.k()`).

## Raw responses captured

| # | Request | HTTP | Response body |
|---|---|---|---|
| 1 | `POST /api/v2/oauth/guest:register` (HMAC `Authorization: Signature`) | 200 | `{"code": 0, "data": {"uid": 8389831992}}` |
| 2 | `POST /api/v2/oauth/guest/token:grant` | 200 | `{"code":0,"data":{...,"open_id":"cad0c3...","access_token":"3fe3e0...","main_active_platform":4,"platform":4,"token_type":"Bearer","refresh_token":"e0ad75...","expires_in":1296000,"scope":[...]}}` |
| 3 | `POST /MajorLogin` (login host, AES + token) | **404** | `{"type": "account_not_found", "msg": "account not found", ...}` |
| 4 | `POST /GenerateNickname` | **200** | `\n\x08Tad0z0h7` -> nickname `Tad0z0h7` |
| 5 | `POST /MajorRegister` | **400** | `BR_PLATFORM_INVALID_PLATFORM` |
| 6 | `POST /GetLoginData` | **401** | `token contains an invalid number of segments` |
| 7 | `POST /MajorGuestBind` | **401** | `token contains an invalid number of segments` |
| 8 | `POST /MajorSecondaryAccountBind` | **401** | `token contains an invalid number of segments` |
| 9 | `POST /ActivateAccount` | **401** | `token contains an invalid number of segments` |
| 10 | `POST /UpdateAuthInspect` | **401** | `token contains an invalid number of segments` |

Two things stand out immediately and they were not visible before this capture:

### A. The account is real and the server knows it

`GenerateNickname` returns a genuine server-issued nickname (`Tad0z0h7`) for a
guest that was created seconds earlier. So registration on the OAuth side fully
works and the account exists.

### B. Most of the login-family routes want a **JWT**, not the OAuth token

Six routes answer `401 token contains an invalid number of segments`. That is a
JWT parser complaining: the game server tries to read the `Authorization`
credential as a JWT and our 64-char opaque `access_token` has no `.` segments.

I confirmed it is a real JWT check, not a generic auth failure, by sending a
**structurally valid** JWT (`header.payload.signature`, base64url, three
segments):

| Credential sent | `/GetLoginData` answer |
|---|---|
| opaque `access_token` | `401 token contains an invalid number of segments` |
| well-formed JWT (dummy sig) | `401 key is of invalid type` |

`key is of invalid type` is the verifier failing at the **signature** step,
after successfully splitting and decoding the token. So the route's contract is
"give me a signed JWT", and we do not have one.

`/MajorLogin` is the exception: it accepts the opaque token and returns a
structured answer, which is why it reports `account_not_found` rather than a
token error.

## Where the JWT comes from

The APK does not mint it. Searched and confirmed absent from
`asset/global-metadata.dec.dat`: `Jwt`, `JWT`, `EncodeJwt`, `CreateJwt`,
`GenerateToken`, `SignToken`, `HS256`, `RS256` — zero occurrences. The bundled
`io.jsonwebtoken` (JJWT) library is only used by the LINE SDK.

So the JWT is issued by the Garena OAuth service. The APK carries the routes for
it (`com.beetalk.sdk.A0`):

```
A0.f() -> /oauth/token/pgs/exchange     google_auth_code, client_id, login_scenario, device_id
A0.g() -> /oauth/token/exchange         grant_type=authorization_code, code, redirect_uri,
                                        source, client_id, client_secret, login_scenario, device_id
A0.C() -> /api/v2/oauth/guest/token:grant
A0.P() -> /api/v2/oauth/guest:register
```

Two encoding facts recovered from `networking/t.java`:

- the request builder defaults to **form encoding** (`c.FORM`), not JSON — my
  first attempts returned `invalid_request` purely because I sent JSON
- `redirect_uri` must be `gop<client_id>://auth/`

With form encoding and that redirect, the exchange stops returning
`invalid_request` and starts returning `invalid_grant` — i.e. the request shape
is accepted and only the authorization code is refused.

### Getting a code, and why it is refused

`POST /api/v2/oauth/guest/token:grant` accepts `response_type=code` and returns
a real code plus the account's platform:

```json
{"code":0,"data":{"code":"a59778c2f1e3cf68...","uid":8389831992,
 "open_id":"cad0c3...","platform":4,"main_active_platform":4,"scope":[...]}}
```

Feeding that code back into `/oauth/token/exchange` as form data returns
`invalid_grant`, even when the same `redirect_uri` is supplied on both legs.
`invalid_grant` means the code is not valid for this exchange — it was minted by
the guest grant, and the exchange expects a code from the interactive
authorization flow (the `gop<client_id>://auth/` redirect is a custom-scheme
callback that only a real device app can receive).

## The platform question, now sharper

The OAuth grant response states the platform plainly:

```
"platform": 4, "main_active_platform": 4
```

So the account's platform is known to the OAuth service and is `4`, matching the
value `/MajorLogin` accepts at body field 99. `BR_PLATFORM_INVALID_PLATFORM`
therefore is not about a missing platform value — the platform is already
recorded server-side for this account. It is about the register call failing to
present a credential the game server will trust, which is the same JWT the other
six routes demand.

That closes the loop with the earlier finding: `BR_PLATFORM_INVALID_PLATFORM`
fires before body validation (an empty body triggers it too) and is identical
for a fully profiled account, so it is a credential-resolution failure, not a
data-format failure.

## What is verified vs. what is not

Verified live:
- guest register -> uid
- token grant -> open_id, access_token, platform 4, main_active_platform 4
- GenerateNickname -> real nickname for the new account
- MajorLogin -> account_not_found for a new account, 200 for a profiled one
- six login-family routes require a JWT and reject an opaque token at parse time
- a well-formed JWT passes parsing and fails only at signature verification

Not resolved:
- how to obtain a signed JWT for a guest account from outside the app. The
  routes exist and are documented above; the code they need comes from an
  interactive authorization flow that terminates on a device-only custom scheme.
  This is the single remaining blocker for both MajorRegister and the UID lookup.
