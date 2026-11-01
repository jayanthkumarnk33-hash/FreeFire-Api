# Account generator debug

Date: 2026-11-01. Subject: `Additional/GenerateAccounts.py`.

## The generator's flow (read from source)

Three steps, in order:

| Step | Method | URL | Purpose |
|---|---|---|---|
| 1 | POST | `https://ffmconnect.live.gop.garenanow.com/oauth/guest/register` | allocate a UID |
| 2 | POST | `https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant` | uid + password -> access token |
| 3 | POST | `https://loginbp.ggblueshark.com/MajorRegister` | finalise the game account |

Step 1 sends `password` (SHA-256 hex, uppercased), `client_type=2`, `source=2`,
`app_id=100067`, plus an `Authorization: Signature <HMAC-SHA256(body)>` header
keyed with the Garena client secret. Step 3 sends a hand-built protobuf, AES-CBC
encrypted with `MAIN_KEY`/`MAIN_IV`.

## Defects found and fixed

### D1 (highest impact) - no `__main__` guard, and it overwrites the live config
The registration loop and the file write were at module level:

```
regions = [...]
accounts = {r: dict(zip(["uid","password"], register(r))) for r in regions}
with open("../Configuration/AccountConfiguration.json","w") as f:
```

Any `import GenerateAccounts` therefore **performed 13 live registrations and
overwrote `Configuration/AccountConfiguration.json`**, destroying the working
credentials. This also made the module untestable without side effects.

Fixed: logic moved into `register()`, `register_many()` and `main()`; the file
write now happens only under `if __name__ == "__main__"`.

### D2 - malformed protobuf when a field value is zero
The original varint encoder:

```
def ev(n):
    r = bytearray()
    while n:                      # loop never runs when n == 0
        ...
    return bytes(r)               # -> b""
```

`ev(0)` returns empty, so `ef(6, 0)` produces the single byte `30` - a field tag
with **no value byte**. That is corrupt protobuf:

```
orig_ef(6,0) = 30
MajorLogin.request().ParseFromString(b"\x30")
  -> DecodeError: Wire format was corrupt
```

Fixed: `_varint(0)` returns `b"\x00"`, which parses correctly as the value 0.
Pinned by `test_original_zero_field_is_malformed_and_ours_is_not`.

### D3 - no timeouts
Every `session.post` used `timeout=10`. Replaced with a `(connect, read)` tuple
`REQUEST_TIMEOUT = (10, 20)`, consistent with the rest of the API.

### D4 - silent failure, no diagnostics
The original returned `(None, None)` on every failure and never recorded which
step failed or why. The caller could not distinguish a 404 from a timeout.

Fixed: `register()` returns `{"ok", "uid", "password", "stage", "status",
"detail"}`, where `stage` is one of `validate`, `register`, `token`,
`major_register`, `done`. Failures are classified rather than swallowed.

### D5 - no protection against clobbering the config
Fixed: `_write_accounts()` raises `FileExistsError` unless `force=True`, and the
default output is `Configuration/AccountConfiguration.generated.json`, not the
live config.

### D6 - network errors propagated
`requests.ConnectionError` / `Timeout` now return a classified failure result
instead of escaping.

## APK cross-check

| Generator element | APK evidence | Verdict |
|---|---|---|
| `/oauth/guest/register`, `/oauth/guest/token/grant` | Not in the APK; hosts are runtime-resolved | Unverifiable from APK; both are live and reachable |
| `app_id=100067`, client secret | Matches the APK's `gop100067` MSDK app registration | Consistent |
| `AES-CBC(MAIN_KEY, MAIN_IV)` | Matches the API's own request cipher | Consistent |
| `ReleaseVersion: OB50`, `X-Unity-Version: 2018.4.11f1` | APK ships `OB55` / Unity `2022.3.47f1` | **Stale** - see note |
| `X-GA-SV` absent from MajorRegister | `X-GA-SV` is required on MajorLogin | Possibly stale |
| openid XOR mask (32 bytes) | **Not found anywhere in the APK** (searched 11,939 files) | Community invention, not verified |

Note on the stale version: the generator was left on `OB50` / `2018.4.11f1`
deliberately. Changing it would alter the registration attempt, which is not
permitted while registration is refused. It is recorded as a likely mismatch.

## Local test harness

`tests/test_account_generator.py` (32 tests) injects a `FakeSession` and
covers: URL/method/header/parameter shape for all three steps, the HMAC
signature, AES block alignment, timeouts on every request, success, and every
failure mode (non-200 at each stage, missing uid, missing token fields,
non-JSON bodies, connection errors, timeouts, detail truncation). It also proves
byte-for-byte equivalence with the original encoders, with the zero-varint
difference asserted explicitly as an intentional fix, and confirms the live
config is untouched by importing the module.
