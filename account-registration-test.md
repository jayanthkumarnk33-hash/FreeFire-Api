# Account registration test

Date: 2026-11-01. Live result plus the local mock harness.

## Live result: registration is refused server-side

One authorized attempt, region IND, using the repository's own flow
(`Additional/GenerateAccounts.register`). No account was created.

| Step | HTTP | Body |
|---|---|---|
| 1. `/oauth/guest/register` | **404** | `{"code":1005,"error":"error_not_found"}` |

The flow stopped at step 1. Steps 2 and 3 were never reached, so no UID, no
access token and no game account were produced. No password was generated for a
successful account, and nothing was written to any config file.

## Classifying the failure

The 404 is **not** a local code defect. Four controlled probes separate
"endpoint missing" from "endpoint present, request rejected":

| Probe | Result | Reading |
|---|---|---|
| `GET /oauth/guest/register` | **405** `error_method_not_allowed` | the **path exists**; only the method is wrong |
| `GET /oauth/guest/token/grant` (control) | 405 | control behaves identically, confirming 405 = route exists |
| `POST /oauth/guest/register` with an empty body | **400** `error_params` | the route is reached and validates its parameters |
| `POST /oauth/guest/register` with `app_id` only | 404 `error_not_found` | params accepted, then refused |
| `POST` full valid params + `Signature` header | 404 `error_not_found` | identical refusal |

A route that returns 405 on GET, 400 `error_params` on an empty POST, and 404 on
a well-formed POST is **present and active**. The 404 is an application-level
refusal from the register handler, not an HTTP routing miss.

Conclusion: **the endpoint is present and actively refusing this request
contract.** The 404 is application-level, not a routing miss.

Important qualification (added in the final diagnostics pass): a 404 on every
well-formed attempt proves the endpoint does not accept *this* flow. It does
**not** prove the path is permanently retired. The generator's register URL is
absent from the supplied APK entirely, so its contract cannot be verified against
the client. See `registration-404-analysis.md` for the full evidence and the
limits of what can be concluded.

Registering more accounts cannot succeed with this contract, so the instruction
to avoid repeated unauthorized registration attempts was followed and no further
attempts were made.

## Why the previously generated accounts are not a fallback for creating more

The 13 accounts in `Configuration/AccountConfiguration.json` were created when
registration was still open. They still authenticate at the Garena token layer
but are restricted at the game-session layer (see `account-diagnostics.md`).
Creating replacements would be attempting to work around that restriction, which
is explicitly out of scope, so no replacement accounts were created.

## Local mock harness (offline, deterministic)

`tests/test_account_generator.py` — 32 tests, all passing. Network is replaced by
an injected `FakeSession`, so the harness never contacts the service.

Covered:

| Area | Tests |
|---|---|
| URL / method / order of the three steps | 1 |
| Step 1 parameter + HMAC signature construction | 2 |
| Step 2 parameter construction | 1 |
| Step 3 headers and AES block alignment | 2 |
| Timeout present on every request | 1 |
| Success result shape | 1 |
| Failure at each stage (non-200, missing uid, missing token fields, non-JSON) | 6 |
| Connection error / timeout handling | 2 |
| Failure detail truncation, password never in detail | 2 |
| Output writer: only successful accounts, refuse overwrite, `--force`, default path | 4 |
| Byte-for-byte equivalence with the original encoders | 4 |
| Wire-format validation rejects malformed payloads | 6 |
| Failure classification for every mode | 8 |
| Zero-varint fix proven (original is malformed) | 2 |
| Config integration + import does not modify the live config | 2 |

```
$ python -m unittest tests.test_account_generator
Ran 46 tests in 0.0NNs
OK
```

## Sanitized capture

The only live detail retained is the HTTP status and the service error code:

```
stage=register  status=404  detail={"code":1005,"error":"error_not_found"}
```

No password, token, open_id or credential appears in this report or in any log.

## Repair outcome

| Defect | Status |
|---|---|
| D1 no `__main__` guard; import overwrote the live config | **Fixed** |
| D2 malformed protobuf for zero-valued fields | **Fixed** |
| D3 no timeouts | **Fixed** |
| D4 silent failure, no step diagnostics | **Fixed** |
| D5 no overwrite protection | **Fixed** |
| D6 network errors escaped | **Fixed** |
| Failures were unclassified (404 indistinguishable from timeout) | **Fixed** - `classify_failure()` |
| Malformed payload could be posted without local validation | **Fixed** - `_validate_wire_message()` |
| Stale `OB50` / `2018.4.11f1` in step 3 | **Not changed** — would alter a live registration attempt; recorded as a likely mismatch |

## Unresolved external blocker

Guest registration is refused with 404 `error_not_found` for every well-formed
request. This is a server-side policy decision. It cannot be repaired in Python
without evading the service's own controls, which is out of scope.
