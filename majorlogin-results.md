# MajorLogin results

Date: 2026-11-01. Live results for `POST https://loginbp.ggpolarbear.com/MajorLogin`.

## Request side: fixed and confirmed

| Property | Value | Status |
|---|---|---|
| Endpoint | `https://loginbp.ggpolarbear.com/MajorLogin` | confirmed |
| Method | POST | confirmed |
| `Content-Type` | `application/octet-stream` | confirmed |
| Body | protobuf `MajorLogin.request`, AES-CBC (`MAIN_KEY`/`MAIN_IV`) | confirmed |
| Required headers | `X-GA`, `X-GA-RV`, `X-GA-SV`, `ReleaseVersion`, `X-Unity-Version` | confirmed |
| `platform` field | `"4"` — the only accepted value | confirmed |

Evidence: HTTP 400 `SignError1` when the `X-GA-RV`/`X-GA-SV` pair is missing;
HTTP 200 when present. `platform` 1,2,3,5,6 all return
`BR_PLATFORM_INVALID_PLATFORM`.

## Response side: two schema defects found and fixed this pass

### D7 - `MajorLoginRes` field 15 declared `uint32`, but is a sub-message
The wire carries wire type 2 (length-delimited) for field 15:

```
field 15: wiretype 2, len 2: 0801   -> nested { field 1: 1 }
```

A `uint32` can never produce wire type 2, so the field was **silently discarded**
and `appServerId` read as `0`. That `0` was a parsing artefact, not a real value.
Corrected to a message type `AppServerInfo { uint32 serverId = 1; }`; it now
decodes as `serverId = 1`.

### D8 - `LoginQueueInfo` field 4 declared `bool`, but the server sends a string
The client metadata names field 4 `queue_is_full` (bool), but the server sends a
**string**: the enforcement reason. A `bool` declaration silently drops it.

```
f13 (queueInfo) len 30
  f1 varint = 1                  -> allow = true
  f3 varint = 1781577563         -> needWaitSecs
  f4 bytes[20] = "Exploiting loopholes"
```

Corrected to `string reason = 4;`. The API now reports `_restricted` and
`_restrictionReason`, and every route surfaces the reason. A wire-level fallback
reader (`extract_queue_info`) is retained so the reason survives even if the
schema is ever regenerated from the client metadata.

Both fixes were applied to `Proto/MajorLogin.proto` and the module regenerated
with `grpc_tools.protoc`. They are pinned by
`tests/test_response_framing.py::AppServerIdTypeTests` and
`::QueueInfoReasonTests`.

## Response framing: confirmed

```
prefix[0:64]   opaque, deterministic, varies only with X-GA-SV
tail[64:...]   plaintext protobuf
```

Parsing the whole body raises `DecodeError`; parsing from offset 64 succeeds.
The decoder locates the message by scoring 16-byte-aligned offsets against the
APK-derived field set, which also prevents a spurious parse at offset 48 (which
decodes as `ipRegion`, a field the client's `MajorLoginRes` cannot contain).

## Live decoded result

| Field | Value |
|---|---|
| `queueInfo.allow` | `true` |
| `queueInfo.needWaitSecs` | `1781577563` (= 2026-06-16 02:39 UTC, in the past) |
| `queueInfo.reason` | `"Exploiting loopholes"` |
| `appServerId.serverId` | `1` |
| `token` | **absent** |
| `serverUrl` | **absent** |

## Authentication outcome

**MajorLogin HTTP 200 does not mean authentication succeeded.** The response is a
restriction notification: it carries an enforcement reason and an expiry
timestamp, and **no `token` and no `serverUrl`**.

All 13 configured accounts behave the same way:

| Reason | Regions | Count |
|---|---|---|
| `Protection Bypass` | SG, RU, TW, US, VN, TH, ME, PK, CIS, BR | 10 |
| `Exploiting loopholes` | IND, ID, BD | 3 |

The reason strings are absent from the entire APK, so they are server-supplied.
See `account-diagnostics.md` and `queue-authentication-investigation.md`.

## Error classification

| Condition | HTTP | Body | Handled as |
|---|---|---|---|
| missing `X-GA-RV`/`X-GA-SV` | 400 | `SignError1` | `MajorLoginError` |
| `platform` != 4 | 400 | `BR_PLATFORM_INVALID_PLATFORM` | `MajorLoginError` |
| bad `logintoken` | 400 | `BR_GOP_TOKEN_AUTH_FAILED` | `MajorLoginError` |
| bad `openid` | 400 | `BR_PLATFORM_INVALID_OPENID` | `MajorLoginError` |
| valid request, restricted account | 200 | framed restriction message | decoded; `_authenticated = False`, `_restricted = True` |
| plaintext (unencrypted) request body | 500 | `\n` | `MajorLoginError` |

No error path reports success. A decodable 200 without a `token` is explicitly
reported as unauthenticated rather than treated as a login.

## Blocker

Every configured account is restricted at the game-session layer. This is a
server-side decision, not a Python defect. A session cannot be obtained without
an account that is not subject to the enforcement action.
