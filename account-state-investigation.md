# Account-state investigation: register, x-ga-rv, source

Date: 2026-11-01. Follow-up to the JWT hunt. Every claim is a live request or a
read of a supplied artifact.

---

## Correction to the framing

The suggestion ended with "the fix is in your API code, not Garena's — find where
those six routes call `jwt.decode(token, ...)` and stop handing it an opaque
token."

That does not apply. This repository has **no JWT code at all**:

```
grep -rn "jwt\|decode(" --include=*.py .   ->  no jwt.decode anywhere
```

`app.py` exposes three routes: `/get_search_account_by_keyword`,
`/get_player_stats`, `/get_player_personal_show`. All three call the **remote**
Garena game server. The `token contains an invalid number of segments` message
is produced by that remote server, not by anything here. There is no local
middleware to change.

---

## Step A — Fix MajorRegister and create a fresh account

### A fresh account was created successfully

The generator's register payload (`app_id` + `source` + HMAC `Signature`
header) works:

```
POST /api/v2/oauth/guest:register  ->  200 {"code":0,"data":{"uid":8390089713}}
POST /api/v2/oauth/guest/token:grant -> 200, open_id + 64-char access_token
```

So a genuinely new, never-flagged account is obtainable, and the whole
investigation below ran against such accounts.

### The fresh account's state, measured

Two Garena MSDK routes answer for a fresh guest, and both are in the APK's
endpoint table (`com.beetalk.sdk.A0`):

```
GET /oauth/user/info/get            (A0 line 222)
  -> 200 {"uid":8390089713,"open_id":"...","gender":0,
          "main_active_platform":4,"platform":4,"nickname":"",
          "icon":".../guest_icon_default.jpg"}

GET /bind/app/platform/info/get     (A0 line 256)
  -> 200 {"bounded_accounts": [], "available_platforms": []}
```

So a fresh guest has:

- a **valid** credential (user info answers 200 with real data)
- `platform: 4`, `main_active_platform: 4` — confirming the platform value
- **no platform bound** (`bounded_accounts` is empty)
- an **empty nickname**

### `/MajorLogin` on that fresh account

```
404 {"type": "account_not_found", "msg": "account not found"}
```

The full token bundle (`server_url` 10, `kts` 18, `ak` 19, `aiv` 20) is still
absent. A brand-new guest does **not** get the populated response.

### Why register fails, and what the APK says about it

`/MajorRegister` returns `BR_PLATFORM_INVALID_PLATFORM` for **every** variant
tried on fresh accounts:

| Variation | Result |
|---|---|
| MajorLogin-style body (fields 22, 29, 99) | 400 BR_PLATFORM_INVALID_PLATFORM |
| `?platform=4`, `?platform_id=4`, `?plat=4`, `?p=4`, 7 param names | same |
| 10 header names (`X-Platform`, `Platform`, `App-Platform`, …) | same |
| `PlatformRegisterReq` shape: field 1 = token, field 2 = value | same |
| `platform_sdk_id` = `4`, `android`, `Android`, `aab`, `google`, `googleplay`, `1`, `2`, `IND` | same |
| `app_id` header | same |
| auth: `Bearer`, `Signature`, none, `Basic`, raw token | same |
| path prefixes `/gop`, `/android`, `/v1`, `/api` | `404 page not found` (so the real route is at `/MajorRegister`) |

**The APK explains why.** `PlatformRegisterReq` — the message that
`MajorRegister` corresponds to — has **no platform field**:

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
```

The only platform-adjacent field is `platform_sdk_id`, a *value* rather than a
platform selector, and sweeping it changes nothing. There is no request field
that sets the platform, so the server cannot be told which platform this is —
which is exactly what "the server could not resolve your platform" means.

The client's own answer for this case is in the metadata as two separate
messages:

```
PlatformRegisterReq   -> platform registration (access_token based)
PlatformGuestBindReq  -> guest bind (guest_open_id, guest_platform_type,
                                       guest_access_token)
```

A guest is not meant to go through platform registration. `/MajorGuestBind` was
tested: `401 token contains an invalid number of segments` — it wants the same
game-session JWT that is unavailable.

### The Garena-host bind path exists but is incomplete

`A0` also exposes, on `connect.garena.com`:

```
/game/guest/bind              (A0 line 320)
/bind/app/platform/create     (A0 line 240)
/bind/app/platform/info/get   (A0 line 256)
```

`/bind/app/platform/create` is `{access_token, app_id, secondary_access_token}`
(from `service/j.e`). It answers `400 {"code":1002,"error":"error_params"}`, so
it accepts the shape but wants something not supplied. It is the route that would
populate `bounded_accounts`, but its full parameter set is not in the APK.

---

## Step B — `x-ga-rv` as a response-shape selector

### The finding: it is required, but it does not change the shape

`X-GA-RV` / `X-GA-SV` are **not** in the dex at all — the Java SDK only knows
`X-GA`. They are game-layer headers, and the metadata confirms both names.

The header is **required** on MajorLogin:

| Request | Result |
|---|---|
| with `X-GA-RV` + `X-GA-SV` | reaches the service (`404 account_not_found` for a guest) |
| without them | `400 SignError1` |

But it is **not** a shape selector. Sweeping 8 values on the same fresh account
gave an identical response every time:

```
X-GA-RV = 1, 2, OB55, OB53, 1.134.1, 2019121269, "v1 1", 0
   -> 404 {"type":"account_not_found"}  (identical)
```

So the hypothesis is disproved: there is no `x-ga-rv` value that unlocks the
full `MajorLoginRes`. The response shape depends on account state, not on the
header.

---

## Step C — `source=2` and where it is attached

`source` is attached at the **OAuth registration** call, not at MajorLogin.
From `com.beetalk.sdk.helper.t.k()`, it reads `ApplicationSourceId` (default 2),
and the working register body is:

```json
{"password":"<sha256 hex>","client_type":2,"app_id":100067,"source":2}
```

On MajorLogin it has no effect. Three placements were tested on a fresh account,
and all three broke the signature:

| Placement | Result |
|---|---|
| header `source: 2` | `400 SignError1` |
| body field 101 = `"2"` | `400 SignError1` |
| body field 5 = `"2"` | `400 SignError1` |

This is expected: `X-GA`/`X-GA-RV`/`X-GA-SV` sign a specific request shape, so
adding anything to it fails verification. `source` belongs to the OAuth leg.

---

## What was implemented

Two new capabilities, both grounded in the APK endpoint table:

### `Api/Account.py` — `get_account_state(access_token)`

Calls `/oauth/user/info/get` and `/bind/app/platform/info/get` and returns
`credentialValid`, `platformBound`, `userInfo`, `bindInfo`, `errors`. Neither
route is a game route, so neither needs the game-session JWT.

### `app.py` — `GET /diagnose_account?server=IND`

Reports why an account cannot reach the game routes. Live output for the
configured account:

```json
{
 "credential_valid": true,
 "platform_bound": false,
 "major_login": "restricted",
 "diagnosis": "account provisioned but restricted by the server",
 "user_info": {"uid": 4700657236, "platform": 4, "nickname": "", "...": "..."}
}
```

This turns "it doesn't work" into a specific state, which is the actionable part.

Tests: `tests/test_account_state.py`, 5 cases. Full suite **156 passed**.

---

## Answers to the three branching questions

- **"If kts appears and is three base64url segments → that's your JWT."**
  `kts` does not appear, for a fresh account or a profiled one. There is nothing
  to split.

- **"If kts appears but is opaque → send it in Authorization and see if the
  error changes."** Cannot be tested: `kts` is never populated.

- **"Otherwise the JWT never reaches the client and the six routes are
  server-internal."** This is what the evidence supports, with one addition:
  the client does not send the opaque OAuth token to those routes either. It
  sends the **game-session token from `MajorLoginRes.token`** (field 8), which is
  what `Api/InGame.py` already does. That token is only issued when MajorLogin
  succeeds, and it does not succeed for these accounts.

---

## Conclusion

The state problem is now precisely characterized rather than guessed:

1. A fresh guest gets a valid credential and **no platform bound**.
2. `MajorRegister` cannot provision it because `PlatformRegisterReq` has no
   platform field — the APK's schema says platform registration is not the guest
   path.
3. The guest path (`/MajorGuestBind`) needs the game-session JWT.
4. The game-session JWT comes only from a successful MajorLogin.
5. MajorLogin succeeds only for an account the server is willing to admit.

That is a closed loop from the client side. Breaking it needs either the
unavailable `register_signature` (a server-issued platform token) or the
`/bind/app/platform/create` parameter set, neither of which is present in the
supplied artifacts. `/diagnose_account` now reports exactly which loop
condition an account is stuck on.
