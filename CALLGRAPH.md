# Auth call graph

Line numbers as of commit `3aea094` + working-tree changes.

| Step | File:Func (line) | Endpoint | Protobuf Msg | Encrypt | Headers | Parse | Err codes |
|---|---|---|---|---|---|---|---|
| guest_register | `Additional/GenerateAccounts.py:register` (223) | POST `ffmconnect.live.gop.garenanow.com/oauth/guest/register` | none (form-encoded) | none; `Authorization: Signature <HMAC-SHA256(body)>` | `User-Agent` | `r1.json()["uid"]` | 404 `error_not_found`, 400 `error_params` |
| guest_login | `Api/Account.py:get_garena_token` (279) | POST `ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant` | none (form) | none | `User-Agent`, `Connection`, `Accept-Encoding` | `response.json()` | `RequestException`, `JSONDecodeError` -> `None` |
| major_login | `Api/Account.py:get_major_login` (322) | POST `loginbp.ggpolarbear.com/MajorLogin` | `MajorLogin.request` (3 fields: openid, logintoken, platform) | AES-CBC `MAIN_KEY`/`MAIN_IV` | `X-GA`, `X-GA-RV`, `X-GA-SV`, `ReleaseVersion`, `X-Unity-Version`, `Content-Type: application/octet-stream` | `decode_major_login_response` (94) -> `_parse_framed_message` (56) | HTTP 400 `SignError1`, `BR_PLATFORM_INVALID_PLATFORM`, `BR_GOP_TOKEN_AUTH_FAILED`, `BR_PLATFORM_INVALID_OPENID`; else `MajorLoginError` |
| response framing | `Api/Account.py:_parse_framed_message` (56) | - | `MajorLogin.response` | none (plaintext tail) | - | 16-byte-aligned offsets scored against `_EXPECTED_RESPONSE_FIELDS` (53) | `ValueError` -> `MajorLoginError` |
| restriction detect | `Api/Account.py:extract_queue_info` (216) / `describe_major_login_failure` (253) | - | `LoginQueueInfo` field 4 | - | - | wire walk `_iter_wire_fields` (148) | - |
| uid_lookup | `Api/InGame.py:get_player_personal_show` (119) | POST `{serverUrl}/GetPlayerPersonalShow` | `PlayerPersonalShow.request` | AES-CBC `MAIN_KEY`/`MAIN_IV` | `Authorization: Bearer <session>`, `X-GA*`, `ReleaseVersion`, `X-Unity-Version` | `decode_protobuf(response.content)` | `RequestException`/`Exception` -> `None` |
| route | `app.py:get_account_info` (228) | GET `/get_player_personal_show?server=IND&uid=11111111` | - | - | - | `jsonify` | 400 `MISSING_UID`/`INVALID_UID_FORMAT`/`INVALID_UID_RANGE`/`SERVER_NOT_FOUND`; 401 `MAJOR_LOGIN_FAILED`; 404 `PLAYER_DATA_NOT_FOUND` |

## First failing step

**Step 3 (major_login) is the first step that fails**, and it fails at the
*interpretation* stage rather than the transport stage:

```
Step 1 guest_register : 404 error_not_found      (route present, contract refused)
Step 2 guest_login    : HTTP 200, token issued   OK
Step 3 major_login    : HTTP 200, 100 bytes, NO token, reason="Exploiting loopholes"
Step 4 game_session   : never reached
Step 5 uid_lookup     : never reached
```

Evidence: `EVIDENCE/step_2_majorlogin_20261101.txt`.

Note the distinction that matters: step 3 does **not** fail with an error. It
returns HTTP 200 and a well-formed protobuf. It simply carries no session token —
the server is notifying the client that the account is restricted. The Python
code handles this correctly (`_authenticated=False`, `_restricted=True`); the
chain stops because there is genuinely no token to continue with.

## Why this is not a request-construction defect

Four distinct valid payloads (baseline 3 fields; + clientversion/region;
+ platformsdkid/devicemodel/releasechannel) all returned an **identical** 100-byte
response. Only genuinely invalid input (`platform=1`) produced a different result
(HTTP 400). If the contract were wrong, the responses would differ. See
`EVIDENCE/step_2_majorlogin_20261101.txt`.
