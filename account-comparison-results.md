# Account comparison results

Date: 2026-11-01.

## Decision: no new test account was created

Phase 3 permitted creating at most one authorized test account *if* the service
supports it and it is permitted under the service's rules, and explicitly
forbade generating replacement accounts to evade confirmed bans, blacklists or
access restrictions.

The Phase 2 diagnostics established a **confirmed server-side restriction**:
every one of the 13 configured accounts returns a server-supplied enforcement
reason (`Protection Bypass` / `Exploiting loopholes`) with an expiry timestamp,
and no `token`/`serverUrl`. Creating a further account from the same generator
would have been exactly the prohibited pattern — working around a confirmed
access restriction — so it was not done.

The comparison was therefore performed **across the 13 existing accounts**, which
gives the same diagnostic signal (is the failure account-specific or common?)
without creating anything new.

## What was compared

`Additional/GenerateAccounts.py` was read to understand the account provenance
(see below). All 13 existing accounts were then exercised through the identical
flow: guest token grant, then MajorLogin.

## Results

| Dimension | Value across all 13 accounts |
|---|---|
| Guest token grant | HTTP 200 for all 13; `access_token` + `open_id` issued |
| MajorLogin | HTTP 200 for all 13 |
| Response framing | 64-byte prefix + plaintext protobuf tail for all 13 |
| `token` issued | No, for all 13 |
| `serverUrl` issued | No, for all 13 |
| Enforcement reason | Present for all 13 |
| `platform=4` required | Yes; 1,2,3,5,6 all rejected with `BR_PLATFORM_INVALID_PLATFORM` |

Reason distribution:

| Reason | Regions | Count |
|---|---|---|
| `Protection Bypass` | SG, RU, TW, US, VN, TH, ME, PK, CIS, BR | 10 |
| `Exploiting loopholes` | IND, ID, BD | 3 |

## Conclusion: common to all accounts, not account-specific

The failure is **not** account-specific. All 13 accounts behave identically at
every step that matters, and each carries an enforcement reason. Two distinct
reason strings appear, but both are enforcement strings and both accounts groups
fail the same way.

Because the token grant succeeds for every account while the game-session layer
refuses, the failure is located at the **game-session admission layer**, driven
by account-level enforcement, and is not a Python or protocol defect.

## Account provenance (from the generator, read-only)

`Additional/GenerateAccounts.py`:
- Registers via `POST /oauth/guest/register` with `app_id=100067`, a
  `Signature <HMAC-SHA256>` authorization header, and a `password` field that is
  the SHA-256 hex of a random 10-digit number.
- Then `POST /oauth/guest/token/grant`.
- Then `POST https://loginbp.ggblueshark.com/MajorRegister` with a hand-built
  protobuf payload that includes a decorative nickname prefixed `0xMe`.
- Uses one fixed app identity, one fixed MSDK user agent, and a plaintext-ish
  obfuscation for the `openid` field (XOR with a fixed byte pattern).

This explains the uniformity: the 13 accounts share one app identity, one user
agent and one registration pattern, with sequential UIDs and no independent
device history. That is the most likely trigger for a group-level enforcement
flag. Stated as the most likely explanation, not as a proven cause.

## What was deliberately not done

- No new accounts created (see decision above).
- No attempt to change device fingerprint, app identity or user agent to obtain
  a session — that would be evading the restriction.
- No modification of `Configuration/AccountConfiguration.json`.
- No credential was printed, logged or committed.

## What would legitimately unblock this

1. Use an account that is **not** subject to the enforcement action — e.g. an
   independently owned account with a normal play history, used with its owner's
   permission.
2. Wait for the enforcement window to lapse if it is genuinely temporary. The
   expiry timestamps observed are already in the past relative to the
   observation date, so this is unlikely to clear on its own; the restriction is
   more likely to be a standing flag than a countdown.

No further live testing was performed on the restricted accounts beyond the
diagnostic reads above.
