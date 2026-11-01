# MajorLogin fix

## Confirmed defect

`get_major_login()` treated **every** non-200 response as `MajorLoginError`:

```python
if response.status_code != 200:
    raise MajorLoginError(...)
```

The login service answers HTTP **404** with

```json
{"type": "account_not_found", "msg": "account not found", "server_time": 1793547142694}
```

for an account that has an OAuth identity but no game profile. That is exactly
the state of a freshly created guest account, and it is the "404" observed in
testing.

### Reproduced before the fix

New guest uid `8389367013`, open_id `fb102cbdd505d6dfcfd5df107d4fa6aa`:

```
/MajorLogin     404  {"type": "account_not_found", ...}
/MajorRegister  400  BR_PLATFORM_INVALID_PLATFORM
/GetLoginData   401  token contains an invalid number of segments
```

`get_major_login` raised a generic `MajorLoginError`. The
`/get_player_personal_show` route did not catch it at all, so a new guest
produced a bare 500 with no explanation.

### APK support

The client keeps a dedicated outcome for this case. From the IL2CPP metadata ret
code table:

```
PropID_LoginRetOK   PropID_LoginRetNewUser   PropID_RegisterSuccess
PropID_MajorLoginSuccess   PropID_MajorRegisterResponed
```

`PropID_LoginRetNewUser` exists as its own state, and `PropID_RegisterSuccess`
follows it. The client does not treat a new account as a hard login failure.

## Change

`Api/Account.py`

- Added `AccountNotFoundError(MajorLoginError)`, so existing callers that catch
  `MajorLoginError` keep working.
- `get_major_login()` raises it for `404` + `account_not_found`.
- Added `PLATFORM_ANDROID = "4"`, replacing the inline `"4"` literal. The value
  is confirmed by the OAuth grant (`platform:4`, `main_active_platform:4`) and
  matches `PlatformGuestBindReq.guest_platform_type`.

`app.py`

- `/get_player_personal_show` and `/get_player_stats` now catch
  `AccountNotFoundError` and return **404 `ACCOUNT_NOT_REGISTERED`** with a
  plain explanation, instead of a 500 or a misleading 401.
- Both also catch `MajorLoginError` and return 401 `MAJOR_LOGIN_FAILED`.

## Test results

New regression tests, `tests/test_account_not_found.py`:

```
test_404_account_not_found_raises_dedicated_error   PASS
test_account_not_found_is_a_major_login_error       PASS
test_plain_404_is_not_treated_as_account_not_found  PASS
test_platform_value_sent_is_four                    PASS
```

Full suite:

```
151 passed in 0.37s
```

(147 before this change, +4 new.)

## What is still not fixed, and why

`MajorRegister` and the JWT-gated routes are **not** fixed, and the reason is
evidential, not effort:

- `/GetLoginData`, `/MajorGuestBind`, `/ActivateAccount`, `/UpdateAuthInspect`
  require a **signed JWT** (`401 key is of invalid type` once the token parses).
- The APK does not mint one: `Jwt`/`JWT`/`SignToken`/`HS256`/`RS256` are absent
  from the metadata; the bundled JJWT is LINE-SDK only.
- The only candidate issuer route, `/oauth/token/exchange`, answers
  `invalid_grant` for a code minted by the guest grant, and `/oauth/token/refresh`
  returns another opaque token, not a JWT.

So there is no evidence-backed way to produce that credential from the supplied
artifacts. Reporting MajorRegister as fixed would not be reproducible.

## Rejected changes

- **Unity version.** The APK says `2018.4.12f1`; the API sends `2022.3.47f1`.
  A/B tested on `/MajorLogin`: identical 200 for both values and for no header.
  Changed nothing, because there is no evidence it affects any response.
- **AES key/IV.** The APK's `VodkaConst` pair differs from the API's. The API's
  pair produces a 200 on `/MajorLogin`, so it is correct for the game path; the
  APK pair belongs to the Vodka voice protocol. Left unchanged.
