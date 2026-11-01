# APK gap analysis — auth call graph

Evidence source: `work/asset/global-metadata.dec.dat` (decrypted IL2CPP metadata),
`work/jadx-out/sources/` (decompiled DEX), `work/base/account.proto`.

## The critical finding: the Python `MajorLogin.request` schema has no APK basis

Of the 31 field names in the Python `Proto/MajorLogin.proto` `request` message,
only **2** appear anywhere in the APK metadata:

| Present | Absent (29 of 31) |
|---|---|
| `accountid` (2), `nickname` (19) | `gameserverid`, `eventtime`, `gameid`, `platid`, `zoneareaid`, `clientversion`, `systemsoftware`, `systemhardware`, `telecomoper`, `screenwidth`, `screenhight`, `glrender`, `deviceid`, `clientip`, `openidtype`, `devicemodel`, `ipregion`, `logintoken`, `platformsdkid`, `platformuid`, `signaturemd5`, `emulatorscore`, `loginby`, `libpath`, `libtoken`, `channeltype`, `releasechannel`, `ifpush`, `isvpn` |

`MajorLoginReq` / `MajorLoginRequest` do not exist in the metadata at all.
**EVIDENCE: NONE for the Python request contract.** It is a community
reconstruction, not something the client ships.

## The client uses a different message and a different endpoint

Decompiled `N2/c.java` (the class that performs MajorLogin):

```java
Http.CSMajorLoginReq.Builder b = Http.CSMajorLoginReq.newBuilder();
b.setAppKey(this.f2722a.getAppKey());
b.setAppSecret(this.f2722a.getAppSecret());
b.setServerId(this.f2722a.getServerId());
b.setAccountId(str);
b.setRegion(region);
b.addAllFilterValues(c());
Http.CSMajorLoginReq req = b.build();
B bA = a(P2.c.b(req.toByteArray()));     // AES-CBC before sending
```

`CSMajorLoginReq` fields (`protohttp/Http.java`):

| # | Name | Type |
|---|---|---|
| 1 | appKey | string |
| 2 | appSecret | string |
| 3 | accountId | string |
| 4 | region | string |
| 5 | filterValues | repeated ParamFilterValue |
| 6 | serverId | uint32 |

Encryption is `P2.c.b()` → AES/CBC/PKCS5 with `VodkaConst.DEFAULT_KEY` as the key
and `VodkaConst.TEST_KEY` as the IV. Those are **not** the Python `MAIN_KEY` /
`MAIN_IV`. `VodkaConst.SIGNALING_SERVER_PATH = "/MajorLogin"` points at the Vodka
signalling server (`SIGNALING_SERVER_ADDRESS = http://202.81.106.160:39001`), not
at `loginbp.ggpolarbear.com`.

`CSMajorLoginResp` carries **`values`** (config key/value pairs) and is consumed
by `VodkaNetConfigs.updateData(...)` — i.e. this message distributes runtime
network config. It is not the game-session login.

## Interpretation, and why the Python code still works

The client's login is layered:

1. **Vodka SDK** — `CSMajorLoginReq` → appKey/appSecret/accountId/region →
   returns config values. This is what ships in the APK.
2. **Game session** — reached afterwards via the protobuf/TCP signalling service
   (`pbtcp`, per `option go_package` in `account.proto`), which is where
   `EAccount.Proto_INVALID_CLIENT_VERSION_NTF` and
   `Proto_ACCOUNT_IN_BLACKLIST_NTF` are defined.

`loginbp.ggpolarbear.com/MajorLogin` is a **separate HTTP entry point** that the
supplied APK does not contain. It is reachable and it processes requests
correctly (invalid input → HTTP 400), but its request schema is not derivable
from these artifacts.

**Consequence:** the Python request contract cannot be corrected from the APK.
Any change would be invented, which the task forbids. Recorded as an open question.

## Call-graph gap table

| Step | APK evidence | Python match | Delta |
|---|---|---|---|
| guest_register | `EVIDENCE: NONE` — `/oauth/guest/register` and host `ffmconnect` have 0 occurrences; client uses `SDKManager`/`LoginSDK_Garena()`/`PlatformGuestBindReq` (`guest_open_id`, `guest_access_token`, `client_type`) | present (`Additional/GenerateAccounts.py`) | **Contract unverifiable**; returns 404 `error_not_found` |
| guest_login | `EVIDENCE: NONE` — `/oauth/guest/token/grant` absent | present (`get_garena_token`) | Works live (HTTP 200). Contract unverifiable but functional |
| major_login | `CSMajorLoginReq` (appKey/appSecret/accountId/region/filterValues/serverId) + AES(VodkaConst keys) | `MajorLogin.request`, 3 fields sent | **Different message, different endpoint, different keys.** Python contract has no APK basis |
| game_session | `pbtcp` signalling service; `EAccount.Proto_*` codes; `SecPlayerLoginReq` (`client_version_code`, `client_architecture`, `is_new_client`, `is_reconnect`) | none | Client uses a TCP signalling service the Python API does not implement |
| uid_lookup | `CSGetPlayerPersonalShowReq`-equivalent not located by name; `PlayerPersonalShow` schema is in the repo | present (`get_player_personal_show`) | Not reached (blocked at major_login) |

## Response schema — APK fields the Python schema is missing

From the `MajorLoginRes` name table (metadata offset 2885333), the client's
response carries fields the Python `MajorLogin.response` lacks:

`agora_environment`, `new_active_region`, `recommend_regions`, `server_url`,
`queue_info`, `tp_url`, `app_server_id`, `ip_city`, `ip_subdivision`, `kts`,
`ak`, `aiv`, `ffanti_url`, `ff_anti_config_desc`, `connection_seed_enabled`,
`connection_seed`, plus `is_nickname_success` / `MajorRegisterRes`.

The Python schema covers most of these. It does **not** cover
`connection_seed_enabled` / `connection_seed` / `ff_anti_config_desc` — and the
live server does not send them in the restricted response, so there is nothing to
decode. No change made.

`ak` / `aiv` (fields 19/20) are `bytes`. The name pairing and the fact the
response also carries `kts` (field 18) strongly suggest the server issues a
per-session key/IV pair that the client uses for the game-session handshake.
Not confirmed — the restricted response omits them, so they cannot be observed.
Recorded as an open question.
