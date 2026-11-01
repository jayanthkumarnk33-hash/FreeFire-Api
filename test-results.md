# Test results

Date: 2026-11-01. Command: `python -m unittest discover -s tests`.

## Summary

```
Ran 101 tests in 0.045s
OK
```

| Module | Tests | Purpose |
|---|---|---|
| `test_majorlogin.py` | 12 | MajorLogin request contract: header triple, timeouts, AES payload, failure modes |
| `test_response_framing.py` | 24 | Response framing, queueInfo reason, field-15 type, spurious-offset rejection |
| `test_account_generator.py` | 46 | Account generator: request shape, failure modes, encoder equivalence, output safety, wire validation, failure classification |
| `test_uid_lookup.py` | 19 | UID lookup route, `InGame` construction, and end-to-end decode of a real protobuf response |
| **Total** | **101** | |

Plus an offline verification script:

```
$ python tests/verify_local.py
IND  prefix= 64 reason='Exploiting loopholes'   PASS
ID   prefix= 64 reason='Exploiting loopholes'   PASS
SG   prefix= 64 reason='Protection Bypass'      PASS
GRANT authenticated=True framed=False -> PASS

ALL CHECKS PASSED
```

No test requires network access or credentials. Every live response used in a
test is a captured, sanitized fixture with no token, open_id or credential.

## Test type breakdown

| Type | Count | Notes |
|---|---|---|
| Pure unit (offline) | 82 | No network; fixtures and injected fakes |
| Mocked integration (offline) | 19 | Flask test client + patched transport |
| Live checks (not part of the suite) | 5 | Run manually; recorded in the results reports |

## Confirmed fixes verified by tests

| Fix | Test |
|---|---|
| MajorLogin needs `X-GA` + `X-GA-RV` + `X-GA-SV` | `test_majorlogin` header tests |
| Response is `64-byte prefix + protobuf tail` | `FramingDetectionTests` |
| `queueInfo.reason` string no longer discarded | `QueueInfoReasonTests` |
| Field 15 is a sub-message, not `uint32` | `AppServerIdTypeTests` |
| Spurious offset 48 (`ipRegion`) rejected | `SpuriousParseTests` |
| Generator no longer runs on import | `ConfigIntegrationTests` |
| Generator zero-value varint no longer malformed | `EncoderEquivalenceTests` |
| Generator refuses to clobber the config | `OutputWriterTests` |
| Upstream error bodies are not printed raw | `ErrorSanitizationTests` |
| UID `11111111` is a valid player UID and not an account UID | `UidParameterTests` |
| Malformed protobuf payloads are rejected before sending | `WireValidationTests` |
| Every failure mode maps to a distinct category | `FailureClassificationTests` |
| A real protobuf response decodes end to end to player fields | `EndToEndDecodingTests` |
| The request uid reaches the serialized payload | `EndToEndDecodingTests` |

## Failed tests

None. No test is skipped or expected to fail.

## Live tests (manual, recorded separately)

| Check | Result | Report |
|---|---|---|
| Guest token grant (13 accounts) | HTTP 200, token issued | `guest-login-results.md` |
| Guest registration (IND, 1 attempt) | HTTP 404 `error_not_found` | `account-registration-test.md` |
| MajorLogin (13 accounts) | HTTP 200, restriction, no session token | `majorlogin-results.md` |
| `GET /get_player_personal_show?server=IND&uid=11111111` | HTTP 401, restriction reason surfaced | `uid-lookup-results.md` |
| `GET /get_player_stats` (same target) | HTTP 401, restriction reason surfaced | `uid-lookup-results.md` |

## Mocked vs real, stated explicitly

- The **101 suite tests are all mocked or offline**. They prove request
  construction, decoding and error handling; they do not prove the service works.
- The **live checks above are real responses** from the real endpoints. No result
  in any report is presented as live when it is mocked.
- No player data for UID `11111111` was ever obtained, and none is claimed. The
  route returns 401 before the lookup is reached, because the calling account is
  restricted.

## Environment

```
protobuf 7.34.1 (regenerated MajorLogin_pb2 with grpc_tools.protoc)
requests, pycryptodome, flask, flask_cors
```
