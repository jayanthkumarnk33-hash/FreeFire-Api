# The exact errors, and what each one means

Captured live on 2026-11-01 against a **freshly created** guest account
(uid 8390179517, IND). Every string below is copied from the response body.

## Summary table

| Endpoint | HTTP | Exact body |
|---|---|---|
| `connect.garena.com` `/api/v2/oauth/guest:register` | 200 | `{"code":0,"data":{"uid":...}}` |
| `connect.garena.com` `/api/v2/oauth/guest/token:grant` | 200 | `{"data":{"open_id":"...","access_token":"...","platform":4}}` |
| `connect.garena.com` `/oauth/user/info/get` | 200 | `{"uid":...,"open_id":"...","platform":4,"nickname":"",...}` |
| `connect.garena.com` `/bind/app/platform/info/get` | 200 | `{"bounded_accounts": [], "available_platforms": []}` |
| `loginbp.ggpolarbear.com` `/MajorLogin` | **404** | `{"type": "account_not_found", "msg": "account not found", "server_time": ...}` |
| `loginbp.ggpolarbear.com` `/MajorRegister` | **400** | `BR_PLATFORM_INVALID_PLATFORM` |
| `loginbp.ggpolarbear.com` `/MajorGuestBind` | **401** | `token contains an invalid number of segments` |
| `loginbp.ggpolarbear.com` `/GetLoginData` | **401** | `token contains an invalid number of segments` |
| `loginbp.ggpolarbear.com` `/GenerateNickname` | 200 | (protobuf; a real nickname, e.g. `Crux1y0P1I1y`) |

## What each error actually means

### `/MajorLogin` → 404 `account_not_found`

The OAuth identity exists, but there is no game profile for it. A freshly
registered guest is always in this state, because registration step 3
(`/MajorRegister`) never completes. The server does **not** return a session
token, so `MajorLoginRes` carries only `queueInfo` + `appServerId` — no
`token` (8), `server_url` (10), `kts` (18), `ak` (19) or `aiv` (20).

### `/MajorRegister` → 400 `BR_PLATFORM_INVALID_PLATFORM`

"Platform could not be resolved", **not** "you sent a bad platform value".
Proof: the check runs before the body is read, so an empty body gives the same
error.

The root cause is in the APK's own schema. `PlatformRegisterReq` is:

```
access_token, platform_sdk_id, editor_register_key, platform_register_info,
is_newbie_choice, register_signature, register_time, gin_report_data
```

There is **no platform field**. Nothing in the request can tell the server which
platform this is. Swept to be sure, all identical:
`platform_sdk_id` over 9 values, `platform` across 10 header names and 7 query
parameters, 5 auth schemes, 2 body shapes.

### `/MajorGuestBind` and `/GetLoginData` → 401 `token contains an invalid number of segments`

The server parses the `Authorization` value as a **JWT** and the value has no
`.` separators. This is the game server's own JWT middleware, not anything in
this repo (`grep -rn "jwt" --include=*.py` finds no JWT code here).

Confirmed by sending a well-formed JWT instead: the error moves to
`401 key is of invalid type`, i.e. it parsed and failed at the key/signature
step. So these routes want a signed JWT, and the game session token the client
would send is `MajorLoginRes.token` — which is only issued when `/MajorLogin`
succeeds.

### `/GenerateNickname` → 200 with a real nickname

Worth noting: the service **does** answer this account on some routes. The
account is not blocked at the transport level, and the credential is valid.

## The loop

```
OAuth register      -> 200, uid                (works)
OAuth token grant   -> 200, access_token       (works)
user/info/get       -> 200, credential valid   (works)
bind/info/get       -> 200, nothing bound      (works)
MajorRegister       -> 400, no platform field exists in the request
MajorGuestBind      -> 401, wants the game session token
MajorLogin          -> 404, session token only issued for an admitted account
```

`MajorGuestBind` needs what `MajorLogin` produces, and `MajorLogin` only
produces it for an account the server admits. Nothing reachable from a guest
credential breaks the loop.

## API route behaviour (this project)

With a configured account that is server-restricted:

| Route | HTTP | Body |
|---|---|---|
| `/get_player_personal_show?server=IND&uid=11111111` | 401 | `code: MAJOR_LOGIN_FAILED`, `message: "Account is restricted by the server: Exploiting loopholes"` |
| `/get_player_stats?server=IND&uid=11111111&mode=BR` | 401 | `error: "Major login failed"`, `restricted: true` |
| `/diagnose_account?server=IND` | 200 | `credential_valid: true`, `platform_bound: false`, `major_login: "restricted"`, `diagnosis: "account provisioned but restricted by the server"` |

With **no** `AccountConfiguration.json` (fresh clone or zip extract):

| Route | HTTP | Body |
|---|---|---|
| `/get_player_personal_show?server=IND&uid=11111111` | 400 | `code: SERVER_NOT_FOUND`, `available_servers: []` |

That is expected: no credential file means no configured server. Copy
`Configuration/AccountConfiguration.example.json` to
`Configuration/AccountConfiguration.json` and fill in a guest uid/password.

## The one artifact that would change any of this

A mitmproxy or logcat capture from a **real device** running the app on first
launch. That would show:

1. the `/MajorRegister` request body — which field carries the platform
2. `register_signature` (server-issued)
3. the full `/bind/app/platform/create` parameter set
4. the `kts` / `ak` / `aiv` formats from an admitted login

None of it can be generated here: no qemu, no `/dev/kvm`, no CPU virtualisation
flags, no Android SDK, no adb, no emulator, and the APK is supplied as split
archives rather than an installable package.
