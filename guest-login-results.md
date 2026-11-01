# Guest login results

Date: 2026-11-01. Flow: Guest credentials -> GuestLogin -> Garena token.

## Stage result

| Stage | Endpoint | Result |
|---|---|---|
| Guest registration | `/oauth/guest/register` | **HTTP 404** `error_not_found` (server-side refusal, see `account-registration-test.md`) |
| Garena token grant | `/oauth/guest/token/grant` | **HTTP 200** for all 13 configured accounts |

Because registration is refused, there is no fresh guest account. The token
grant was therefore exercised with the existing configured accounts, which is
the GuestLogin equivalent for this API: `Api/Account.get_garena_token()`.

## Token grant: confirmed working

```
get_garena_token(uid, password)
  -> HTTP 200
  -> {"access_token": <present>, "open_id": <present>, ...}
```

All 13 regions return HTTP 200 with an `access_token` and an `open_id`. This
proves:

1. The credentials in `Configuration/AccountConfiguration.json` are **valid**.
2. The request construction (parameters, headers, `client_secret`, `client_id`)
   is **correct**.
3. The Garena authentication layer accepts this client.

## Distinguishing the two credential layers

| Layer | Result | Meaning |
|---|---|---|
| Garena OAuth (`ffmconnect...garenanow.com`) | HTTP 200, token issued | credentials valid, client accepted |
| Game session (`loginbp.ggpolarbear.com`) | HTTP 200, **no session token**, enforcement reason | account restricted |

The failure is therefore **not** at GuestLogin. It is at the game-session layer.

## Error handling verified

`get_garena_token` distinguishes and classifies:

| Condition | Behaviour |
|---|---|
| HTTP non-200 | `raise_for_status()` -> `RequestException` caught, returns `None` |
| Network failure / timeout | `RequestException` caught, returns `None` |
| Non-JSON body | `json.JSONDecodeError` caught, returns `None` |
| Success | parsed JSON returned |

The debug print was deliberately changed to log only the status code and body
length, never the body, because this response carries `access_token` and
`refresh_token`.

## Local tests

Covered by `tests/test_majorlogin.py` (token-request configuration, timeout,
failure modes) and `tests/test_account_generator.py` (step 2 request shape).
The live token grant is confirmed above.

## Blocked at

Guest **registration** (404, server-side). Guest **login** for existing accounts
succeeds, but the resulting session cannot be upgraded to a game session because
of the account-level restriction recorded in `account-diagnostics.md`.
