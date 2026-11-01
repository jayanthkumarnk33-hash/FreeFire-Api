# Auth chain verification — live, 2026-11-01

Auth account (guest): `4700657236` · Lookup target (player): `11111111` · Region: IND

| Step | Status | Token type confirmed | Evidence |
|---|---|---|---|
| 1. guest_register | **BLOCKED** — HTTP 404 `error_not_found` | n/a | route present (GET→405, empty POST→400); no account created |
| 2. guest_login (token grant) | **OK** — HTTP 200 | Garena OAuth `access_token`, len 64, plus `refresh_token`, `open_id` (len 32), `expires_in`, `scope`, `token_type` | `debug_lookup.py` step 1 |
| 3. major_login | **BLOCKED** — HTTP 200, but **no session token** | n/a — no token issued | `EVIDENCE/step_2_majorlogin_20261101.txt` |
| 4. game_session | **not reached** | n/a | requires step 3 token |
| 5. uid_lookup | **not reached** | n/a | requires step 4 session |

## Token-type check (why step 2 is genuinely OK and step 3 is genuinely blocked)

Step 2 returns a Garena OAuth response: JSON, `token_type` field present, paired
with `refresh_token` and `refresh_expiry_time`. That is an OAuth token, not a
game session.

Step 3 returns a **binary** body (`content-type: application/octet-stream`) whose
decoded protobuf contains only `queueInfo` and `appServerId`. Fields 8 (`token`)
and 10 (`serverUrl`) are **absent**. There is no token of any kind in the
response, so there is nothing for step 4 to consume. The chain is not being
mis-wired — it has no input.

## Step 3 is not a request-construction defect

Four materially different valid payloads produced an identical 100-byte response:

| Payload | Result |
|---|---|
| A. `{openid, logintoken, platform:"4"}` | HTTP 200, 100 bytes, reason `Exploiting loopholes` |
| B. A + `clientversion:"1.134.1"`, `region:"IND"` | HTTP 200, 100 bytes, same reason |
| C. B + `platformsdkid:4`, `devicemodel:"A063"`, `releasechannel:"FFO_OB55_PRELive_1.134.1"` | HTTP 200, 100 bytes, same reason |
| D. A with `platform:"1"` (invalid) | HTTP 400, 29 bytes |

The server distinguishes valid from invalid input (D differs) but returns the
**same** answer for every valid contract. A wrong request shape would change the
response. The restriction is bound to the account.

## Blocker

Account-level enforcement: `Exploiting loopholes` (IND/ID/BD) or
`Protection Bypass` (10 other regions), with `needWaitSecs` = 1781577563
(2026-06-16 UTC, in the past). No code change can lift it.
