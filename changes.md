# Changed files

## `Api/Account.py`

- Added `AccountNotFoundError(MajorLoginError)`. Subclassing keeps every
  existing `except MajorLoginError` working.
- `get_major_login()` now raises `AccountNotFoundError` when the service answers
  HTTP 404 with `account_not_found`, instead of a generic `MajorLoginError`.
- Added `PLATFORM_ANDROID = "4"` and used it in the request builder, replacing
  the inline `"4"`.

## `app.py`

- Imported `MajorLoginError` and `AccountNotFoundError`.
- `/get_player_personal_show`: wrapped the `get_major_login` call. Returns
  `404 ACCOUNT_NOT_REGISTERED` for a new account and `401 MAJOR_LOGIN_FAILED`
  for other login errors, instead of an unhandled 500.
- `/get_player_stats`: same handling; the generic `except Exception` no longer
  swallows a login failure into a 502.

## `tests/test_account_not_found.py` (new)

Four regression tests covering the 404 path, the subclass relationship, a
non-`account_not_found` 404, and the platform constant.

## Documentation (new)

- `apk-evidence.md` — APK evidence with artifact references.
- `majorlogin-comparison.md` — APK vs Python comparison table.
- `majorlogin-fix.md` — defect, change, test results, rejected changes.
- `uid-lookup-results.md` — live results for UID `11111111` IND.
- `discovered-endpoints.md` — endpoint catalogue with evidence levels.
- `guest-flow-capture.md` — end-to-end live capture of the new-guest flow.
- `progress.md` — this phase's status.

## Not changed, and why

- `Configuration/APIConfiguration.py`: `UNITY_VERSION` diverges from the APK but
  a live A/B test shows the header is not validated. Left as-is.
- `Configuration/AESConfiguration.py`: the API's key/IV produce a 200 on
  MajorLogin, so they are correct for the game path. The APK's differing pair
  belongs to the Vodka voice SDK.
- No new Flask routes: every remaining candidate needs the signed JWT, so
  adding them would ship endpoints that cannot work.
