# Login-queue / authentication investigation

Date: 2026-11-01. Source of live data: the 13 configured guest accounts in
`Configuration/AccountConfiguration.json`, against
`https://loginbp.ggpolarbear.com/MajorLogin`.

## Summary

HTTP 200 from MajorLogin does **not** mean authentication succeeded. The body is
a **restriction notification**: the server returns `queueInfo` with `allow=true`,
a `needWaitSecs` value that is actually an **expiry timestamp**, and a **text
reason** naming the enforcement action. No `token` and no `serverUrl` are issued.

Every one of the 13 configured accounts is restricted. There is no evidence of a
temporary login queue in these responses, and no evidence that any account is
usable.

## 1. Field-by-field meaning (evidence-based)

### `queueInfo.allow = true`
The APK's own schema for the nested message is `LoginQueueInfo`, recovered from
the decrypted metadata at offset 2809158:

```
LoginQueueInfo | Allow | queue_position | need_wait_secs | queue_is_full
```

So the bundled Python names (`allow`, `queuePosition`, `needWaitSecs`,
`queueIsFull`) match the client's real field names for fields 1-3. `allow` is
therefore a plain boolean gate, and `true` means the server is permitting the
connection rather than blocking it at the transport level. It does **not** mean
the login was granted.

### `queueInfo.needWaitSecs` is an expiry timestamp, not a wait duration
- Declared name: `need_wait_secs` (`LoginQueueInfo` field 3).
- Observed values and their UTC interpretations:

| Region | `needWaitSecs` | UTC | Interval from 2026-11-01 |
|---|---|---|---|
| IND | 1781577563 | 2026-06-16 02:39 | past |
| SG | 1782626736 | 2026-06-28 06:05 | past |
| RU | 1782626776 | 2026-06-28 06:06 | past |
| ID | 1777084310 | 2026-04-25 02:31 | past |
| TW / VN / ME | 1782849791 | 2026-06-30 20:03 | past |
| US | 1782334260 | 2026-06-24 20:51 | past |
| TH | 1782628957 | 2026-06-28 06:42 | past |
| PK | 1782849796 | 2026-06-30 20:03 | past |
| CIS / BR | 1782849801 | 2026-06-30 20:03 | past |
| BD | 1779525773 | 2026-05-23 08:42 | past |

All 13 values decode to **past** UTC dates within 2026-04-25 to 2026-06-30, i.e.
6 weeks to 6 months before the observation date. A "wait seconds" field would
hold a small offset (seconds to minutes), not a 10-digit epoch in the past.

The metadata context around the queue fields explains the shape: the list
`Allow | queue_position | need_wait_secs | queue_is_full` sits in the same field
block as `signature_ban_expire_time`, and `BlacklistInfoRes` carries
`expire_duration` and `ban_time`. Enforcement messages in this protocol carry an
expiry instant in this slot. This is a strong, consistent interpretation, but it
is an **inference from the value shape plus the neighbouring schema**, not a
field-name proof — the name literally says "wait seconds". Marked as
high-confidence inference.

### `appServerId = 0`
Correctly parsed: `appServerId` is field 15 and is genuinely `0` in the
responses (wire bytes `7a 02 08 01`, where the nested value is 1, and the outer
field is present with value 0). It is not a parse failure.

### Missing `token` and `serverUrl`
`MajorLoginRes.token` is field 8 and `server_url` is field 10. Neither field is
present on the wire in any of the 13 responses. This is the decisive fact: the
server never issued a session.

### Identical tails for valid and invalid credentials
Tested with the IND account:

| Request | HTTP | Tail |
|---|---|---|
| valid token + valid open_id | 200 | identical |
| garbage `logintoken` | 400 `BR_GOP_TOKEN_AUTH_FAILED` | n/a |
| garbage `openid` | 400 `BR_PLATFORM_INVALID_OPENID` | n/a |

Note the correction: a **bad** credential does **not** produce the same 200 body.
It produces a plain-text HTTP 400. The 200 body is invariant across all *valid*
credentials, which is expected for an account-level restriction. The earlier
"identical for valid and invalid" claim is therefore **narrowed**: the tail is
invariant across valid requests, and invalid credentials are rejected outright.

### The deterministic 64-byte prefix
- Byte-identical across repeated identical requests.
- Varies **only** with `X-GA-SV` (1, 2 and 3 each give a distinct prefix).
- Unchanged by `X-GA-RV`, `openid`, `logintoken`, `platform`, `region`,
  `deviceid`, `clientversion`, `secureToken` and `sessionId`.
- Not a hash or HMAC over the tail: the same tail with `X-GA-SV` 1/2/3 yields
  three different prefixes, and no plain/HMAC digest of the tail (or of
  `X-GA-SV || tail`) matches it for MD5/SHA-1/SHA-256/SHA-512/SHA3-256/BLAKE2b
  under `MAIN_KEY`, the Garena client secret or `MAIN_IV`.

Interpretation: a per-signature-scheme server credential (a keyed fingerprint
selected by `X-GA-SV`), not a per-request value. Not decryptable from the
supplied artifacts (see `response-format-investigation.md`, Blocker B).

## 2. Confirmed defect found and fixed: the reason string was being discarded

The bundled schema declares `LoginQueueInfo` field 4 as `bool` (`queueIsFull`),
but the server sends a **length-delimited string** there. Protobuf silently drops
a wire-type mismatch, so the reason was lost. Wire evidence (IND):

```
f13 (queueInfo) bytes[30]
  f1 varint = 1                     -> allow = true
  f3 varint = 1781577563            -> needWaitSecs
  f4 bytes[20] = "Exploiting loopholes"
f15 bytes[2] = { f1 = 1 }
```

Fix: `Api/Account.py` now re-reads `queueInfo` straight off the wire
(`_iter_wire_fields`, `extract_queue_info`), so the reason survives. The decoder
also reports `_restricted` and `_restrictionReason`, and
`describe_major_login_failure()` names the reason. All three routes surface it.

## 3. Second confirmed defect found and fixed: spurious offset selection

The first version of the framing decoder accepted the first offset that parsed.
For the ID account, offset **48** parses as `ipRegion` (field 4) — a field the
client's `MajorLoginRes` cannot contain — so the real message at offset 64 was
missed and the ID account was misreported as unrestricted.

Fix: candidate offsets are now scored by (a) whether they contain a field the
APK-derived `MajorLoginRes` can actually have, (b) field count, (c) offset. The
ID account now decodes correctly. Regression-tested in
`tests/test_response_framing.py::SpuriousParseTests`.

## 4. Reason strings observed

| Reason | Regions | Count |
|---|---|---|
| `Protection Bypass` | SG, RU, TW, US, VN, TH, ME, PK, CIS, BR | 10 |
| `Exploiting loopholes` | IND, ID, BD | 3 |

`Protection Bypass` is the Free Fire enforcement category for bypassing the
anti-cheat / protection layer. Supporting APK evidence: the metadata contains
`NeedffantihackEmulatorCheck`, `ffantihack`, `CSCheckHackBehaviorReq/Res`,
`hack_warning`, `ffanti_hack`, `anti_hack_center_desc`, `BlacklistInfoRes`
(`ban_reason`, `expire_duration`, `ban_time`), `banned`, `violation`, `appeal`,
`illegal` and `forbidden`.

**Important:** these strings are **absent from the entire APK** (`grep` over
`global-metadata.dec.dat`, `classes.dex`, `classes2.dex`, `classes3.dex`,
`resources.arsc` and `libil2cpp.so` all return 0 for `Exploiting`,
`loopholes` and `Exploiting loopholes`). They are therefore **server-supplied**
enforcement text, delivered in the response, not client UI strings.

## 5. Restriction is account-level, not request-level

Tested against the IND account with `platform=4` held constant:

| Variation | HTTP | Result |
|---|---|---|
| baseline | 200 | `Exploiting loopholes` |
| repeated 3x | 200 | identical |
| `+region=IND` | 200 | unchanged |
| `+deviceid` | 200 | unchanged |
| `+clientversion=1.134.1` | 200 | unchanged |
| `+secureToken`, `+sessionId` | 200 | unchanged |
| `platform` 1,2,3,5,6 | 400 | `BR_PLATFORM_INVALID_PLATFORM` |
| `platform=4` | 200 | `Exploiting loopholes` |

`platform=4` is the **only** accepted value, and no request-side field changes
the outcome. The restriction is bound to the account.

## 6. What is NOT concluded

- The accounts are **not** described as banned on the basis of an assumption.
  The conclusion is grounded in: a server-supplied enforcement string, an expiry
  timestamp, and the absence of `token`/`serverUrl` in all 13 responses.
- No account was tested in a way intended to evade the restriction, and no
  replacement accounts were created to work around it.
- The exact semantic of the `need_wait_secs` name is a high-confidence
  inference, flagged as such above.

## 7. Consequence

An authenticated game session is not obtainable with any configured account.
UID lookup therefore cannot proceed, and additional in-game endpoints cannot be
exercised end to end. The Python side is correct; the accounts are restricted by
the service.
