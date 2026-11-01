# MajorLogin response format investigation

Investigation date: 2026-11-01. All live observations are from the IND guest
account in `Configuration/AccountConfiguration.json`, against
`https://loginbp.ggpolarbear.com/MajorLogin`.

## 1. Observed raw response structure (no sensitive payload)

A successful HTTP 200 response is **100 bytes**, `content-type:
application/octet-stream`. No credential, token or server URL is carried in any
response header. The only non-standard header is `x-ga-rv: 1`.

```
HTTP 200, content-length 100
prefix[0:64]  opaque, not valid protobuf   (values vary only with X-GA-SV)
tail[64:100]  plaintext protobuf            (fixed across all valid requests)
```

Sanitized 100-byte fixture (a login-queue response; contains no credentials):

```
819269d3323b375288e7a62d442bb01b314f48040228c1b74fa978a4af65657e
c4c2deeb851ccfff5a92c75d6ee9dad6f01dc5bc34dd9ed3c44cc1f7dbcc3c04
6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801
```

Error responses are plain text, **not** framed:

| Condition | HTTP | Body |
|---|---|---|
| Invalid `logintoken` | 400 | `BR_GOP_TOKEN_AUTH_FAILED\n` |
| Invalid `openid` | 400 | `BR_PLATFORM_INVALID_OPENID\n` |
| `platform=2` | 400 | `BR_PLATFORM_INVALID_PLATFORM\n` |
| Missing `X-GA-SV` | 400 | `SignError1\n` |
| Plaintext (unencrypted) request body | 500 | `\n` (1 byte) |

## 2. Confirmed framing and protobuf evidence

**The 64-byte prefix is real.** Parsing the whole 100-byte body as
`MajorLogin.response` raises `google.protobuf.message.DecodeError`. The first
field tag decodes as field 215328 with wire type 5, which is not a valid
`MajorLoginRes` field. Parsing from offset 64 succeeds.

**The tail is a login-queue message, not a session grant.** Offset 64 parses to:

```
field 13 (queueInfo)  -> { allow: true, needWaitSecs: 1781577563 }
field 15 (appServerId) -> sub-message { field 1: 1 }
              (originally mis-parsed as 0; see CORRECTION below)
token:     absent
serverUrl: absent
ttl:       absent
accountId: absent
```

Field numbers verified against the schema recovered from the APK (§3):
`queueInfo` = 13, `appServerId` = 15. `6a` = (13<<3)|2, `1e` = 30 bytes,
`08 01` = queueInfo.allow = true,
`18 db ee c2 d1 06` = queueInfo.needWaitSecs = 1781577563.

**The prefix is deterministic and depends only on `X-GA-SV`.**

| Variation | Prefix | Tail |
|---|---|---|
| baseline | `819269d3…` | unchanged |
| repeated 3x, same request | identical | identical |
| `X-GA-RV=1.134.1` | identical | identical |
| `X-GA-RV=OB54` | identical | identical |
| `platform=2` (rejected) | 400 | n/a |
| `secureToken` / `sessionId` changed | identical | identical |
| `X-GA-SV=2` | `fb346e92…` | identical |
| `X-GA-SV=3` | `1ff75b09…` | identical |

It does not vary with the account token, the open_id, `X-GA-RV`, or any request
body field that was varied. This is consistent with a signature over the
signature-scheme version, and rules out "random nonce" and
"derived from the account token".

## 3. APK parser/decryption call-chain references

The DEX evidence shows the Free Fire **client** uses a *different* service from
the one the Python API calls, with a different wire format.

### 3a. The `MajorLogin` DEX class is the Garena Vodka voice SDK
- `protohttp/Http.java` (from `classes3.dex`) defines `CSMajorLoginReq`
  (`app_key`, `app_secret`, `account_id`, `region`, `filter_values`, `server_id`)
  and `CSMajorLoginResp` (`token`, `voice_service_address`, `server_timestamp`,
  `sdk_params`, `values`).
- `base/http.proto` ships the same definitions with
  `option go_package = "golang.garena.com/vodka/backend/internal/protocol/pbhttp"`.
- `N2/c.java` (from `classes.dex`) builds `CSMajorLoginReq` from
  `VodkaConfig` (`getAppKey`, `getAppSecret`, `getServerId`, `getRegion`) and
  posts it to `this.f2722a.getServerUrl()`.
- `com/garena/android/vodka/model/VodkaConst.java` sets
  `SIGNALING_SERVER_PATH = "/MajorLogin"` and
  `SIGNALING_SERVER_ADDRESS = "http://202.81.106.160:39001"`.
- Therefore the `MajorLogin` in the DEX is the **Vodka signaling login**
  (voice SDK), not the game session login. This was independently confirmed
  earlier: `com.garena.sdk.applicationId` is `gop100067` while the Python API
  uses `client_id=100067`, a different app registration.

### 3b. The DEX cipher is not the game-login cipher
- `P2/c.java` (from `classes.dex`):
  - `b(byte[])` = encrypt: `AES/CBC/PKCS5Padding`, key
    `VodkaConst.DEFAULT_KEY`, IV `VodkaConst.TEST_KEY`.
  - `a(byte[])` = decrypt: same cipher, `Cipher.DECRYPT_MODE`.
  - `VodkaConst.DEFAULT_KEY = "N!Qvw2!ePbfNF2lu"` (16 bytes),
    `VodkaConst.TEST_KEY = "K*hKRuiSXZv!9enI"` (16 bytes).
- `N2/c.java` response path: `Http.CSMajorLoginResp.parseFrom(P2.c.a(dC.a().b()))`
  — decrypt the body, then parse. Plain protobuf, no additional framing.
- **This cipher was applied to the live game response and did not decrypt it.**
  It produces high-entropy output at every offset (0, 16, 64) and every
  alignment. The same key/IV also does not decrypt the game request. This
  confirms the two services use independent crypto.

### 3c. The real `MajorLoginRes` schema (from IL2CPP metadata)
The response field names are recoverable from the decrypted metadata string
table at offset 2885333, in declaration order immediately after `MajorLoginRes`:

```
agora_environment, new_active_region, recommend_regions, server_url,
queue_info, tp_url, app_server_id, ip_city, ip_subdivision, kts, aiv,
ffanti_url, ff_anti_config_desc, connection_seed_enabled, connection_seed
```

`kts` and `aiv` are the fields that matter: `kts` is a key type selector and
`aiv` is the corresponding key/IV blob. The response schema contains **no
`lockRegion`, `notiRegion`, `ipRegion` or `emulatorScore`**, which means the
Python `MajorLogin_pb2.response` is a hand-built approximation, not the client
schema. The two schemas nevertheless agree on `queueInfo` = 13, `appServerId` =
15 and `kts` = 18, so the tail parses correctly.

## 4. Python implementation mismatches

| # | Mismatch | Impact |
|---|---|---|
| R1 | `decode_protobuf(response.content, MajorLogin.response)` parses the **whole** body, including the 64-byte prefix. | `DecodeError` on every HTTP 200 response. This was the actual blocker, and it is independent of the prefix cipher. |
| R2 | The parser treats any decodable response as an authenticated session. | HTTP 200 is a **queue** response. `get_major_login` would return a dict with no `token`, and callers would treat it as success. |
| R3 | No timeout / no status classification on the MajorLogin call. | Already fixed in the previous pass. |
| R4 | Response schema is an approximation (`lockRegion`, `emulatorScore`, … are absent from the client). | Parsing still works for the fields that matter; documented rather than rewritten, because the real `.proto` was not shipped in the APK. |

## 5. Actual corrections and regression tests

`Api/Account.py`:
- Added `MAJOR_LOGIN_PREFIX_LEN = 64` and `_parse_framed_message()`, which
  locates the protobuf message at a 16-byte-aligned offset instead of assuming
  offset 0. The prefix length is not advertised in the response, so the message
  is located by candidate offset rather than by a hardcoded slice.
- Added `decode_major_login_response()`, which returns the decoded fields plus
  `_framed`, `_prefixLen` and `_authenticated`. `_authenticated` is true only
  when a non-empty `token` was actually returned.
- `get_major_login()` now calls `decode_major_login_response()`.

`tests/test_response_framing.py` (new, 9 tests) pins:
- the fixture is 100 bytes with a 64-byte prefix;
- the whole body does **not** parse, the tail **does**;
- the decoder reports `_prefixLen = 64` and `_authenticated = False` for the
  live queue fixture;
- a synthetic response that *does* carry a token reports
  `_authenticated = True` and `_framed = False`;
- empty and undecodable bodies raise `MajorLoginError`;
- `get_major_login()` returns the decoded queue response end to end.

Test results:
```
$ python -m unittest discover -s tests
Ran 21 tests in 0.006s
OK
```
(12 existing MajorLogin tests + 9 new framing tests.)

Route behaviour after the fix: all three routes now return **HTTP 401** with an
accurate "major login failed" error, instead of the previous HTTP 500/502
"internal error". The underlying condition is unchanged and is now reported
truthfully.

## 5b. CORRECTION (2026-11-01, later pass): field 15 was mis-declared

The observation above that `appServerId` reads as `0` was a **parsing artefact**,
not a server value. The wire bytes are:

```
field 15: wiretype 2 (length-delimited), len 2: 0801  ->  nested { field 1: 1 }
```

Wire type 2 is a sub-message; a `uint32` can never produce it. Because the schema
declared field 15 as `uint32`, protobuf **silently discarded** the field and the
default `0` was reported. Fixed by declaring
`AppServerInfo appServerId = 15;` with `uint32 serverId = 1;`. It now decodes as
`serverId = 1`.

The `78 02` byte sequence quoted in section 2 as "field 15 varint 2" was also a
misreading; `7a 02 08 01` is the field-15 tag (`7a` = (15<<3)|2), length 2, then
the nested `08 01`.

Also corrected in the same pass: `LoginQueueInfo` field 4 was declared `bool`
while the server sends a string (the enforcement reason). Both fixes are in
`Proto/MajorLogin.proto` and pinned by tests.

## 6. Remaining blockers and supporting evidence

### Blocker A: HTTP 200 is not an authenticated session
The strongest evidence, in order:
1. The decoded tail contains **no `token` and no `serverUrl`** — the two fields
   every downstream call needs.
2. The body parses as a **login-queue** message (`queueInfo.allow = true`,
   `queueInfo.needWaitSecs = 1781577563`, `appServerId = {serverId: 1}`).
3. The `queueInfo` field number (13) and `appServerId` (15) are confirmed
   against the APK-derived `MajorLoginRes` schema, so the identification is not
   a guess.
4. The tail is **byte-identical** across a valid token, an invalid token and an
   invalid open_id. A real session grant could not be invariant across those.
5. `needWaitSecs = 1781577563` is a large future value, consistent with a
   queue-admission wait rather than a successful login.
6. Directly calling the in-game host with the Garena `access_token` returns
   `HTTP 401 "token contains an invalid number of segments"` — it requires a
   JWT-shaped token, i.e. the MajorLogin `token`, which this account never
   receives.

Interpretation: this account is being held in the login queue and is not being
granted a game session. That is a server-side admission decision, not a Python
defect. No evidence of a ban was observed; no evidence was fabricated.

### Blocker B: the 64-byte prefix is not decryptable from the supplied artifacts
The prefix is opaque, 64 bytes, deterministic, and varies only with `X-GA-SV`.
`kts`/`aiv` (the response key fields) are **absent** from this response, so the
key is not being negotiated in-band.

Ruled out against the live response (all failed to yield a parseable
`MajorLoginRes`):
- AES-128/192/256 in ECB, CBC, CFB, OFB and CTR, over every 16-byte-aligned
  (start, length) slice, with and without the plaintext tail, with and without
  the prefix; keys and IVs drawn from `MAIN_KEY`, `MAIN_IV`, the Garena
  `client_secret` (hex and ASCII), the Vodka `DEFAULT_KEY`/`TEST_KEY`, the
  response's own 16-byte blocks, and `md5`/`sha256`/HMAC derivations of the
  request and of the account token.
- Self-describing layouts (key at `[0:16]`, IV at `[16:32]`, ciphertext from
  32/48/64).
- Single-byte XOR over all 256 values.
- TEA/XXTEA block decryption.
- Decrypt-then-zlib / decrypt-then-raw-deflate.
- A sweep of every 16-character string in the metadata, `libil2cpp.so` and the
  DEX files as AES keys.

Conclusion: the key is not present in the supplied APK artifacts and is not
derivable from the request or the account token. This is documented as a
blocker rather than guessed at.

### Blocker C: no authoritative in-game response parser in the APK
`client.ind.freefiremobile.com` and the `ggpolarbear` / `ggblueshark` hostnames
do **not** appear anywhere in the metadata, `libil2cpp.so` or the DEX files.
The game resolves its service hosts at runtime from the remote version
directory (`MajorServerAddr`). Consequently the in-game response framing
(including whether `GetPlayerPersonalShow` is framed the same way) cannot be
confirmed from the supplied artifacts, and `Api/InGame.py` was deliberately left
on whole-body parsing rather than changed speculatively.

## Supported alternatives (no guessing)
1. Capture a real client session (authorized device + proxy) and diff the
   MajorLogin request/response. That would settle both the prefix cipher and
   whether a real login returns a token.
2. Use an account that is not queue-held, to obtain a 200 response that
   actually contains `token` and `serverUrl`. The framing decoder added here
   would then return `_authenticated = True` unchanged.
3. Poll the queue: if `needWaitSecs` decreases across attempts, that confirms
   Blocker A is an admission wait rather than a permanent state.
