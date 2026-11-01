# The three login legs, and why they must not be mixed

The user's note is right and worth making explicit: the OAuth leg and the game
leg are separate SDK modules with separate parameters. This file records the
boundary precisely, because mixing them is the most likely way to send a
request that looks correct and is rejected.

## Leg 1 — Garena OAuth (MSDK)

**Host:** `connect.garena.com` in the APK (`com.beetalk.sdk.A0`), and
`ffmconnect.live.gop.garenanow.com` in this API's config. Both issue tokens.

**Code:** `com.beetalk.sdk.A0`, `com.beetalk.sdk.n0` (guest handler),
`com.beetalk.sdk.networking.service.j`.

**Parameters that belong to this leg only:**

| Parameter | Value | Where it comes from |
|---|---|---|
| `app_id` | `100067` | `com.garena.sdk.applicationId` |
| `source` | `2` | `com.garena.sdk.ApplicationSourceId` (`helper.t.k()`) |
| `client_type` | `2` | OAuth client type |
| `client_id` / `client_secret` | `100067` / … | MSDK public client pair |
| `device_id` | 32 hex | `device.deviceId.g.f()` |

**Result:** `open_id` + an opaque 64-char `access_token`. Not a JWT.

**What this leg proves:** the credential is valid. `GET /oauth/user/info/get`
answers 200 with the account's uid and platform.

## Leg 2 — Garena platform binding (MSDK, after OAuth)

**Host:** `connect.garena.com`.

**Code:** `com.beetalk.sdk.A0` lines 240/256, `service/j.e` / `service/j.f`.

| Route | Parameters | Live result |
|---|---|---|
| `/bind/app/platform/create` | `access_token`, `app_id`, `secondary_access_token` | `400 error_params` |
| `/bind/app/platform/info/get` | `access_token`, `app_id` | `200 {"bounded_accounts":[],"available_platforms":[]}` |

`app_id` is a **leg-2 parameter**. Sending it on a game route does nothing.

**State this leg reports:** whether a platform account is bound. For every
account tested, `bounded_accounts` is empty — including accounts that later
returned a 200 on MajorLogin. So binding is not what MajorLogin gates on.

## Leg 3 — Game login (the game module, IL2CPP)

**Host:** `loginbp.ggpolarbear.com` (learned from remote config;
`MajorLoginRes.server_url` is the only source, and the host appears **zero**
times in the APK).

**Code:** the IL2CPP game assembly, not Java.

Evidence that this is a separate module and not the same code path:

```
RPC name          dex    IL2CPP metadata
MajorRegister      0        4
MajorGuestBind     0        1
GetLoginData       0        2
GenerateNickname   0        8
MajorLogin        19*       6
```

`*` The 19 dex hits are all `protohttp.Http$CSMajorLoginReq` — the **Vodka
voice SDK**, sitting next to `Signalingservice` and `org.webrtc.PeerConnection`.
It is a different, smaller `MajorLogin` for voice signalling, not the game login.
`base/http.proto` documents it:

```
CSMajorLoginReq { app_key, app_secret, account_id, region, filter_values, server_id }
```

So the game RPCs exist only in IL2CPP, and the one `MajorLogin` the Java layer
knows is a decoy for this purpose.

**Parameters that belong to this leg only:** protobuf field 22 `openid`,
field 29 `logintoken`, field 99 `platform` (`"4"`), plus the
`X-GA`/`X-GA-RV`/`X-GA-SV` signature headers. The body is AES-CBC encrypted.

**Result:** on success, `MajorLoginRes` with `token` (8) and `server_url` (10).
On an unprovisioned or restricted account, `queueInfo` (13) + `appServerId` (15)
only.

## Where `register_signature` enters

`register_signature` is a field of `PlatformRegisterReq` — a **leg-3**
message that corresponds to `MajorRegister`:

```
PlatformRegisterReq
  access_token
  platform_sdk_id
  editor_register_key
  platform_register_info
  is_newbie_choice
  register_signature      <-- server-issued; not derivable
  register_time
  gin_report_data
```

Note what is **absent**: there is no platform field. That is why
`/MajorRegister` answers `BR_PLATFORM_INVALID_PLATFORM` — the request cannot tell
the server which platform it is. The server resolves platform from the
credential, and for a guest credential there is nothing to resolve, which is why
the client uses `PlatformGuestBindReq` (`/MajorGuestBind`) instead — and that
route wants the leg-3 session token.

So `register_signature` is not something to compute. It is issued by the server
during a platform-registration flow that a guest account never enters.

## The closed loop, stated in leg terms

```
leg 1  OAuth          -> opaque token            (works)
leg 2  bind           -> bounded_accounts []     (works, nothing bound)
leg 3a MajorRegister  -> BR_PLATFORM_INVALID_PLATFORM
                         (no platform field exists in the request)
leg 3b MajorGuestBind -> 401, wants the leg-3 session token
leg 3c MajorLogin     -> 404 account_not_found
                         (session token only issued for an admitted account)
```

Leg 3b needs what leg 3c produces, and leg 3c only produces it for an account
the server admits. Nothing in leg 1 or leg 2 unlocks leg 3, and no leg-1
parameter (`app_id`, `source`, `client_type`) changes a leg-3 response.

## What only a real device trace can supply

Everything below requires watching the real client talk to the server, because
none of it is in the supplied artifacts:

1. The **leg-3 request body** for `MajorRegister` — specifically which field
   carries the platform, since the request message has no such field.
2. `register_signature` — a server-issued value.
3. The **`/bind/app/platform/create` parameter set** (it wants more than
   `access_token` + `app_id` + `secondary_access_token`).
4. The **`kts` / `ak` / `aiv` formats**, which only appear once a login is
   admitted.

A first-launch trace on a production device would show 1-4 at once. This
environment cannot produce it:

```
qemu / kvm      : absent
/dev/kvm        : absent
CPU virt flags  : none
Android SDK     : absent
adb / emulator  : absent
```

There is no virtualisation available, so no emulator can run, and the APK is
supplied as split archives rather than an installable package. A logcat or
mitmproxy capture from a device that has the app is the single artifact that
would break the loop, and it cannot be generated here.
