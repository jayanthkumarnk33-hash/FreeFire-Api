# Progress

## Current phase

Phase 4-5: APK-grounded comparison done, evidence-supported MajorLogin fix
implemented and tested. Register/JWT blocker documented.

## Completed

- Traced the full Python authentication chain (guest token → MajorLogin →
  session).
- Reverse engineered the APK login surface: dex SDK classes, IL2CPP metadata
  type tables, native libs, Vodka `.proto` files.
- Compared APK evidence against the Python API (see `majorlogin-comparison.md`).
- Reproduced the HTTP 404 `account_not_found` defect and fixed it
  (`majorlogin-fix.md`).
- Ran the live UID lookup attempt for `11111111` IND
  (`uid-lookup-results.md`).
- Catalogue of additional endpoints with evidence levels
  (`discovered-endpoints.md`).
- 151 tests pass.

## Key findings

1. The login host is **not** in the APK. `MajorLoginRes.server_url` delivers it
   at runtime. The API's hardcoded host cannot be confirmed or contradicted by
   static analysis.
2. The "404" is `/MajorLogin` answering `account_not_found` for a guest with no
   game profile. The client has a dedicated ret code for it
   (`PropID_LoginRetNewUser`) and follows it with registration. Now handled.
3. Six login-family routes (`GetLoginData`, `MajorGuestBind`,
   `ActivateAccount`, `UpdateAuthInspect`, …) require a **signed JWT**, not the
   OAuth access token. Proven by moving the failure from
   `token contains an invalid number of segments` to `key is of invalid type`
   with a well-formed token.
4. The APK does not mint that JWT, and the OAuth exchange refuses a guest-grant
   code. This is the register/lookup blocker.
5. Unity version diverges (`2018.4.12f1` in the APK vs `2022.3.47f1` in the
   API) but is not validated by the server.
6. `MajorRegister` is platform registration (`PlatformRegisterReq`); guests use
   `PlatformGuestBindReq`. Different RPCs.

## Next steps

- None that are evidence-backed. Obtaining a signed JWT requires a credential
  the supplied artifacts do not produce.

## Blockers

- Signed JWT for the game login host: no source in either repository.
- The configured profiled account is server-restricted; a fresh guest has no
  game profile and cannot create one without the JWT.
