# Why guest registration returns HTTP 404

Date: 2026-11-01. Evidence-based analysis of the `POST /oauth/guest/register`
refusal. Nothing here is inferred from external repositories or bug reports.

## 1. The observation, reproduced

One authorized attempt with the repository's own flow, region IND:

```
POST https://ffmconnect.live.gop.garenanow.com/oauth/guest/register
  -> HTTP 404  {"code":1005,"error":"error_not_found"}
```

## 2. Classifying the 404

Four controlled probes separate "no such route" from "route refuses this request".
`GET /oauth/guest/token/grant` is included as a control, because it is a route we
know works.

| Probe | Result | What it proves |
|---|---|---|
| `GET /oauth/guest/register` | **405** `error_method_not_allowed` | the **path exists**; only the method is wrong |
| `GET /oauth/guest/token/grant` (control) | **405** `error_method_not_allowed` | control behaves identically, so 405 reliably means "route exists" |
| `POST` empty body | **400** `error_params` | the route is **reached** and validates parameters |
| `POST` `app_id` only | **404** `error_not_found` | parameters accepted, then refused |
| `POST` full valid params + `Signature` header | **404** `error_not_found` | identical refusal |

A path that answers 405 on GET, 400 `error_params` on an empty POST, and 404 on a
populated POST is **present, routable and actively validating**. The 404 is an
**application-level response from the register handler**, not an HTTP routing
miss. That distinction is the whole point of the probe set: a genuinely missing
route would return 404 for every method, including GET.

## 3. What the APK says about how guest accounts are obtained

This is the decisive client-side evidence, and it points away from a direct HTTP
register call.

| String | Present in APK artifacts? |
|---|---|
| `/oauth/guest/register` | **No** (0 occurrences) |
| `/oauth/guest/token/grant` | **No** |
| `ffmconnect` (the host the generator calls) | **No** |
| `gop.garenanow` | **No** |
| `/oauth/token/checkbind` | **Yes** |
| `sbt-auth.garenanow.com`, `testconnect.garena.com` | **Yes** |
| `PlatformGuestBindReq` / `PlatformGuestBindRes` | **Yes** |
| `guest_open_id`, `guest_access_token`, `client_type` | **Yes** |
| `SDKManager`, `UIModelLogin.LoginSDK_Garena()`, `guest restore` | **Yes** |

Two conclusions follow, and only two:

1. **The generator's guest-registration host and path do not exist anywhere in
   the supplied APK.** The client does not call
   `ffmconnect.live.gop.garenanow.com/oauth/guest/register`. So the exact request
   contract of that endpoint **cannot be verified or corrected from the APK**.
   This is a genuine evidence gap, not a solved problem.
2. **The client obtains guest credentials through the Garena MSDK / PGS SDK**
   (`SDKManager`, `LoginSDK_Garena()`, "reset guest before login", "guest
   restore"), and binds them through `PlatformGuestBindReq`, which carries
   `guest_open_id`, `guest_access_token` and `client_type`. The `client_type`
   field the generator sends belongs to that protobuf, not to a form-encoded
   register call.

So the repository's direct-HTTP registration is a **legacy/community-reconstructed
flow** that the current client does not use. That is a plausible reason the
service refuses it, and it is the most likely explanation consistent with the
evidence.

## 4. What can and cannot be concluded

**Established:**
- The 404 is an application-level refusal, not a missing route (probe set above).
- The endpoint validates parameters (400 on empty body) and then refuses valid ones.
- The APK contains no counterpart to the generator's register URL, so the
  generator's contract cannot be cross-checked against client behaviour.
- The client uses an SDK-mediated guest flow instead.

**Not established:**
- That the endpoint is **permanently** retired. A 404 on every well-formed attempt
  proves the endpoint does not accept *this* flow; it does not prove the path is
  gone forever, nor that a different contract would fail.
- What the APK-authentic contract would be. It is not in the artifacts, so it
  cannot be tested. Fabricating parameters to guess it would be inventing
  protocol values, which is out of scope.

The honest position: the 404 is **reproducible and application-level**, the
generator's contract is **unverifiable against the APK**, and the client's actual
guest flow is **SDK-mediated**. Which of those two facts causes the refusal
cannot be separated with the evidence available.

## 5. Consequence for the task

Guest self-registration cannot be repaired from this evidence. The remaining
options all fall outside the permitted scope:

| Option | Why it is not taken |
|---|---|
| Guess new parameters until one is accepted | Invents protocol values; would also be repeated unauthorized registration |
| Reverse the SDK's native guest flow | Requires runtime evidence the APK does not contain; also a bypass |
| Create accounts another way | Attempts to work around an upstream control |

Per instruction, no further registration attempts were made after the single
authorized try, and no parameters were guessed.

## 6. Reproducing the classification locally

`tests/test_account_generator.py::FailureClassificationTests` pins the mapping so
this diagnosis stays reproducible without network access:

```
HTTP 404            -> category "endpoint_not_found"
HTTP 400            -> category "bad_request"
HTTP 401 / 403      -> category "auth_rejected"
HTTP 5xx            -> category "server_error"
Timeout             -> category "network_timeout"
Connection error    -> category "network_error"
Bad local input     -> category "invalid_input"
Malformed payload   -> category "serialization_error"
```
