# UID lookup results

Target: UID `11111111`, region `IND`.

## Method

Ran the real API in-process against the live service, no mocks:

```python
from Api.Account import get_garena_token, get_major_login
from Api.InGame import get_player_personal_show
```

## Result: the lookup cannot run, and the reason is upstream of the UID

The lookup is a two-step chain: authenticate, then query the game server with
the session the login step returns. Step 2 never returns a session.

### Account currently configured (`4700657236`, IND)

```
STEP 1  guest token         ok    open_id 52fed4978cb6b49b187b67688ee3720d, token 64 chars
STEP 2  MajorLogin          HTTP 200
        decoded fields      queueInfo{allow:true, needWaitSecs:..., reason:"Exploiting loopholes"}
                            appServerId{serverId:1}
        token present       NO
        serverUrl present   NO
        _restricted         True ("Exploiting loopholes")
STEP 3  player query        SKIPPED - no token and no serverUrl exist to query with
```

### Fresh guest (`8389367013`, IND)

```
/MajorLogin      404  {"type": "account_not_found", ...}
/MajorRegister   400  BR_PLATFORM_INVALID_PLATFORM
/GetLoginData    401  token contains an invalid number of segments
/MajorGuestBind  401  token contains an invalid number of segments
```

### API route behaviour (in-process, `app.test_client()`)

```
401  /get_player_personal_show?server=IND&uid=11111111
       code MAJOR_LOGIN_FAILED, message "Account is restricted by the server: Exploiting loopholes"
401  /get_player_stats?server=IND&uid=11111111&mode=BR
       error "Major login failed", restricted true
401  /get_search_account_by_keyword?server=IND&keyword=test
       error "Major login failed"
```

So the API reports **401 restricted**, not 404, for the configured account. The
404 in this project comes from `/MajorLogin` answering `account_not_found` for a
new guest, which is now handled explicitly (see `majorlogin-fix.md`).

## Why this is not about UID 11111111

`get_player_personal_show` is never reached. `get_major_login` yields neither
`token` nor `serverUrl`, and both are required arguments. Nothing about the
target UID is evaluated. There is no evidence that UID `11111111` is banned or
nonexistent, and no such claim is made here.

## What is verified

- The guest authentication chain works end to end: token grant returns a real
  `access_token` and `open_id`.
- `MajorLogin` reaches the service and gets a well-formed 200 for a profiled
  account; the response decodes with the API's schema.
- That 200 carries a **restriction notice**, not a session. The server's own
  reason string is `Exploiting loopholes`.
- For a new guest, `MajorLogin` returns 404 `account_not_found`.
- `GenerateNickname` returns a genuine server-issued nickname, so the service
  does answer this account on some routes.

## What is not verified

- Whether UID `11111111` exists, is banned, or is reachable. No request that
  would reveal this ever completed.
- Any player profile data. No lookup response body was obtained.

## Blocker

Two independent blockers, both on the account side rather than the UID side:

1. The configured profiled account is restricted by the server.
2. A fresh guest has no game profile, so `MajorLogin` returns
   `account_not_found`, and the route that would create one (`MajorRegister`)
   needs a credential this API cannot obtain.

Neither is fixable by changing the UID or the request for UID `11111111`.
