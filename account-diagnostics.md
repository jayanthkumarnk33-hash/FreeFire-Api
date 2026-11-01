# Account diagnostics

Date: 2026-11-01. Credentials are never printed. Only UIDs, HTTP status codes,
body lengths and the server-supplied reason strings are reported.

## Configured accounts

`Configuration/AccountConfiguration.json` holds 13 guest accounts, one per
region, each with a 10-digit UID and a 64-character (SHA-256 hex) password.
They were produced by `Additional/GenerateAccounts.py`.

## Diagnostic table

| Region | UID | Guest token grant | MajorLogin | Body len | Reason | `needWaitSecs` | Expiry (UTC) |
|---|---|---|---|---|---|---|---|
| IND | 4700657236 | 200 | HTTP 200 | 100 | Exploiting loopholes | 1781577563 | 2026-06-16 02:39 |
| SG | 4700657292 | 200 | HTTP 200 | 97 | Protection Bypass | 1782626736 | 2026-06-28 06:05 |
| RU | 4700657343 | 200 | HTTP 200 | 97 | Protection Bypass | 1782626776 | 2026-06-28 06:06 |
| ID | 4700657370 | 200 | HTTP 200 | 100 | Exploiting loopholes | 1777084310 | 2026-04-25 02:31 |
| TW | 4700657402 | 200 | HTTP 200 | 97 | Protection Bypass | 1782849791 | 2026-06-30 20:03 |
| US | 4700657418 | 200 | HTTP 200 | 97 | Protection Bypass | 1782334260 | 2026-06-24 20:51 |
| VN | 4700657442 | 200 | HTTP 200 | 97 | Protection Bypass | 1782849791 | 2026-06-30 20:03 |
| TH | 4700657462 | 200 | HTTP 200 | 97 | Protection Bypass | 1782628957 | 2026-06-28 06:42 |
| ME | 4700657485 | 200 | HTTP 200 | 97 | Protection Bypass | 1782849791 | 2026-06-30 20:03 |
| PK | 4700657512 | 200 | HTTP 200 | 97 | Protection Bypass | 1782849796 | 2026-06-30 20:03 |
| CIS | 4700657536 | 200 | HTTP 200 | 97 | Protection Bypass | 1782849801 | 2026-06-30 20:03 |
| BR | 4700657561 | 200 | HTTP 200 | 97 | Protection Bypass | 1782849801 | 2026-06-30 20:03 |
| BD | 4700657632 | 200 | HTTP 200 | 100 | Exploiting loopholes | 1779525773 | 2026-05-23 08:42 |

All 13 accounts: token grant succeeds, MajorLogin returns HTTP 200, and **no
session token is issued**. The result is uniform, so the failure is
account-level and common to all of them.

## Assessment against each hypothesis

| Hypothesis | Verdict | Evidence |
|---|---|---|
| Credentials invalid or expired | **Rejected** | `/oauth/guest/token/grant` returns HTTP 200 with a valid `access_token` and `open_id` for all 13 accounts. Invalid credentials produce a plain-text HTTP 400 (`BR_GOP_TOKEN_AUTH_FAILED`), which was not observed. |
| Explicit server restriction | **Confirmed** | Every response carries a server-supplied enforcement reason: `Exploiting loopholes` (IND, ID, BD) or `Protection Bypass` (the other 10), plus an expiry timestamp. The strings are absent from the APK, so they originate server-side. |
| Outdated protocol | **Rejected** | The request is accepted (HTTP 200, not `SignError1`). The APK's release channel is `FFO_OB55_...` and the API sends `X-GA-RV`/`ReleaseVersion` `OB55` and Unity `2022.3.47f1`, matching the shipped client. `platform=4` is the only accepted value and is the one used. |
| Login queue | **Rejected for these responses** | `queueInfo.allow` is `true` and `queue_is_full` is absent/false. A queue would block admission; here the server explicitly allows and then returns an enforcement reason with an expiry. |
| Server rejects the client configuration | **Rejected** | Changing `region`, `deviceid`, `clientversion`, `secureToken` and `sessionId` does not change the outcome. Only `platform` matters, and `platform=4` is accepted. |
| Python API misinterprets the response | **Partially confirmed (fixed)** | Two real Python defects were found and fixed: (1) the reason string was discarded because the schema typed `queueInfo` field 4 as `bool` while the server sends a string; (2) the framing decoder accepted a spurious parse at offset 48 for the ID account. Neither caused the restriction, but both caused the API to misreport it. |

## Answer to "is this a ban?"

The evidence supports a **server-side account restriction with an expiry**, not a
guess:

1. A server-supplied enforcement string naming an anti-cheat violation.
2. An expiry timestamp in the enforcement slot, in the past relative to
   observation, i.e. an expired or still-flagged restriction window.
3. No `token` and no `serverUrl` in any of the 13 responses.
4. Uniform across all 13 independent accounts, while the token grant for each
   succeeds — so it is the game-session layer, not the credential layer.

Caveat, stated plainly: the field is *named* `need_wait_secs`. The "expiry
timestamp" reading is an inference from the value shape and the neighbouring
schema (`signature_ban_expire_time`, `BlacklistInfoRes.expire_duration`,
`ban_time`). It is high-confidence but not name-proven.

## Why the accounts are restricted

All 13 accounts were mass-registered by `Additional/GenerateAccounts.py` using
the same app identity (`client_id=100067`), the same MSDK user agent, and
sequential UIDs. They share no independent device history. The enforcement
strings (`Protection Bypass` — the anti-cheat bypass category) plus the uniform,
simultaneous restriction across all 13 are consistent with the service flagging
the account group. This is stated as the most likely explanation, not as a
proven cause.

## Security observation (pre-existing, not introduced here)

`Configuration/AccountConfiguration.json` is **tracked in git** and contains
live guest-account passwords (SHA-256 hex). This is a pre-existing condition in
the upstream project, and the file was **not modified** in this work (it does not
appear in `git status`). Recommendation: move it to an untracked file or load the
credentials from the environment, and rotate the affected accounts. No credential
from this file was printed, logged, or copied into any report, test or script.

## No further action taken

- No attempt was made to evade the restriction.
- No replacement accounts were created to work around it (see
  `account-comparison-results.md` for the reasoning).
- The original `AccountConfiguration.json` was not modified.
