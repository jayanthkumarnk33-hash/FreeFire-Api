"""Guest account registration for the Free Fire Garena MSDK flow.

Registration is a three step flow:

    1. POST /api/v2/oauth/guest:register    -> allocates a UID
    2. POST /api/v2/oauth/guest/token:grant -> exchanges uid + password for a token
    3. POST /MajorRegister                  -> finalises the game account

Steps 1 and 2 are APK-verified: the endpoints, the compact-JSON bodies, the
HMAC "Signature" header on step 1 and the `data.uid` / `data.access_token`
response nesting all come from com.beetalk.sdk.A0 and service/j.java in the
shipped APK.

Step 3 is NOT APK-verified. The APK references MajorRegister only as an RPC
name (no host is hardcoded; the client resolves it from remote config), and the
host below is inherited from the original generator. Against the live service it
returns HTTP 500 for every payload variant tried, so a fresh MSDK account is
left without an in-game profile and MajorLogin then reports
`account_not_found`.

Usage (writes to a separate file, so the live config is safe):

    python Additional/GenerateAccounts.py --region IND --out /tmp/new.json

Writing over Configuration/AccountConfiguration.json requires --force.
"""

import argparse
import hashlib
import hmac
import json
import os
import random
import sys

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- Garena MSDK client identity (public constants, also in the shipped APK) ---
# The app_id / source values are the ones the shipped client reads from its own
# AndroidManifest (com.garena.sdk.applicationId, com.garena.sdk.ApplicationSourceId).
CLIENT_ID = "100067"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
USER_AGENT = "GarenaMSDK/4.0.44(A063;Android 13;en;IN)"

# Endpoints taken from com.beetalk.sdk.A0 in the shipped APK:
#   A0.P() -> R() + "/api/v2/oauth/guest:register"
#   A0.C() -> R() + "/api/v2/oauth/guest/token:grant"
#   A0.R() -> "https://connect.garena.com"
GARENA_CONNECT_URL = "https://connect.garena.com"
REGISTER_URL = GARENA_CONNECT_URL + "/api/v2/oauth/guest:register"
TOKEN_URL = GARENA_CONNECT_URL + "/api/v2/oauth/guest/token:grant"

# MajorRegister finalises the in-game profile.
#
# The host below is NOT APK-derived. The supplied APK never hardcodes a login
# host: N2/c.java builds requests from VodkaConfig.getServerUrl(), and the host
# is fetched from remote config at runtime. This value is inherited from the
# upstream repository (Api/Account.py). The route is confirmed to exist live --
# a genuinely absent path returns "404 page not found", while /MajorRegister
# returns the service's own BR_PLATFORM_INVALID_PLATFORM -- but the request
# schema is unknown, so step 3 cannot currently complete.
MAJOR_REGISTER_URL = "https://loginbp.ggpolarbear.com/MajorRegister"

# Password alphabet from com.beetalk.sdk.helper.F: digits, lowercase, then the
# ten symbols "!@#$%^&*()". A 64-character string is drawn from it and hashed
# with SHA-256; helper.u.a renders the digest as UPPERCASE hex.
PASSWORD_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()"
PASSWORD_LENGTH = 64

# The MajorRegister payload is AES-CBC encrypted with the same key/IV the API
# uses for its game requests.
AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"

REQUEST_TIMEOUT = (10, 20)

REGIONS = ["IND", "SG", "RU", "ID", "TW", "US", "VN", "TH", "ME", "PK", "CIS", "BR", "BD"]

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "Configuration",
    "AccountConfiguration.generated.json",
)


def _new_guest_password():
    """
    Build a guest password the way the shipped client does.

    com.beetalk.sdk.helper.F.c() draws 64 characters from
    PASSWORD_ALPHABET, SHA-256s the result, and renders it as uppercase hex
    (helper.u.a). The plaintext is never stored: the digest *is* the credential
    the server hashes again, so it is what gets sent to the register and token
    endpoints.
    """
    raw = "".join(random.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH))
    return hashlib.sha256(raw.encode()).hexdigest().upper()


def _device_id():
    """A random 32-hex device id, the shape com.beetalk.sdk.deviceId.g.f() yields."""
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def _obfuscate_openid(openid):
    """
    Obfuscate the openid for the MajorRegister `others` field.

    A fixed 32-byte mask is XORed with the ASCII of the openid and 0x30. This is
    reproduced from the original generator. No equivalent routine exists in the
    supplied APK, so it is treated as an implementation detail of this client
    rather than a verified protocol step.
    """
    mask = [0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0, 1, 7,
            0, 0, 0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0]
    return bytes(b ^ mask[i % len(mask)] ^ 48 for i, b in enumerate(openid.encode()))


def _aes_encrypt_hex(hex_payload):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(bytes.fromhex(hex_payload), AES.block_size)).hex()


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _encode_field(field, value):
    if isinstance(value, int):
        return _varint((field << 3) | 0) + _varint(value)
    raw = value.encode() if isinstance(value, str) else value
    return _varint((field << 3) | 2) + _varint(len(raw)) + raw


def _encode_message(fields):
    out = bytearray()
    for field in sorted(fields):
        out.extend(_encode_field(field, fields[field]))
    return bytes(out)


def _read_varint(buf, index):
    """Read one varint. Returns (value, next_index). Raises ValueError if truncated."""
    value = 0
    shift = 0
    while True:
        if index >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _validate_wire_message(buf):
    """
    Walk a protobuf message and raise ValueError if it is malformed.

    This is a pre-flight check on the hand-built MajorRegister payload. It
    catches the class of defect where a field is emitted as a bare tag with no
    value (which the server would reject as corrupt), before anything is sent.
    """
    index = 0
    while index < len(buf):
        tag, index = _read_varint(buf, index)
        field_number, wire_type = tag >> 3, tag & 7
        if field_number == 0:
            raise ValueError("field number 0 is not valid")
        if wire_type == 0:
            _, index = _read_varint(buf, index)
        elif wire_type == 2:
            length, index = _read_varint(buf, index)
            if index + length > len(buf):
                raise ValueError("length-delimited field runs past the end")
            index += length
        elif wire_type == 5:
            index += 4
        elif wire_type == 1:
            index += 8
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
    return True


def classify_failure(stage, status, detail):
    """
    Map a failure to a stable category.

    Categories are deliberately distinct so a caller can tell a local defect
    from an upstream policy refusal:

        invalid_input        rejected before any request was sent
        serialization_error  the request payload could not be built
        platform_rejected    MajorRegister refused the request with the
                             service's own BR_PLATFORM_INVALID_PLATFORM code,
                             i.e. the payload was understood but rejected
        network_timeout      the request timed out
        network_error        the request could not be completed
        auth_rejected        upstream refused authorization (401/403)
        bad_request          upstream rejected the parameters (400)
        endpoint_not_found   upstream has no such route/workflow (404)
        server_error         upstream fault (5xx)
        upstream_error       any other upstream status
    """
    if stage == "validate":
        return "invalid_input"
    if stage == "serialize":
        return "serialization_error"
    if detail and "BR_PLATFORM_INVALID_PLATFORM" in detail:
        return "platform_rejected"
    if status == 404:
        return "endpoint_not_found"
    if status in (401, 403):
        return "auth_rejected"
    if status == 400:
        return "bad_request"
    if isinstance(status, int) and status >= 500:
        return "server_error"
    if status is not None:
        return "upstream_error"
    return "network_error"


def _fail(stage, detail, status=None, uid=None, password=None, category=None):
    """Build a classified failure result."""
    return {"ok": False, "uid": uid, "password": password, "stage": stage,
            "status": status, "detail": detail,
            "category": category or classify_failure(stage, status, detail)}


def _post(session, url, data, headers, timeout, stage, uid=None, password=None):
    """
    Perform one POST. Returns (response, failure); exactly one is None.

    A timeout is reported separately from other network errors so a caller can
    tell "too slow" from "unreachable".
    """
    try:
        return session.post(url, data=data, headers=headers, timeout=timeout), None
    except requests.exceptions.Timeout as e:
        return None, _fail(stage, f"{type(e).__name__}: {e}", uid=uid,
                           password=password, category="network_timeout")
    except requests.RequestException as e:
        return None, _fail(stage, f"{type(e).__name__}: {e}", uid=uid,
                           password=password, category="network_error")


def _orig_bare_tag(field):
    """Reproduce the original encoder's output for a zero-valued field (a bare tag).

    Retained so a test can prove the pre-fix behaviour was malformed.
    """
    return _varint((field << 3) | 0)


def _safe_detail(response, limit=200):
    """Short, non-sensitive description of a response body."""
    try:
        text = response.text.strip()
    except Exception:
        return "<unreadable body>"
    if not text:
        return "<empty body>"
    return text[:limit]


def register(region, session=None, timeout=REQUEST_TIMEOUT):
    """
    Register one guest account in `region`.

    Returns:
        dict: {"ok", "uid", "password", "stage", "status", "detail", "category"}
        where "stage" names the step that stopped the flow (or "done") and
        "category" is a stable classification (see classify_failure).

    The password is returned to the caller but never logged.
    """
    if region not in REGIONS:
        return _fail("validate", f"unknown region {region!r}")

    session = session or requests.Session()
    password_plain = _new_guest_password()

    # --- Step 1: guest register ---
    # The APK posts compact JSON (t.networking.n(..., t.c.JSON)) and signs the
    # exact request body with HMAC-SHA256 over the client secret, sent as
    # "Authorization: Signature <hex>" (com.beetalk.sdk.networking.interceptor.a).
    body = json.dumps({"password": password_plain, "client_type": 2,
                       "app_id": int(CLIENT_ID), "source": 2},
                      separators=(",", ":"))
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": "Signature " + hmac.new(
            CLIENT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest(),
    }
    r1, failure = _post(session, REGISTER_URL, body.encode(), headers, timeout, "register")
    if failure:
        return failure
    if r1.status_code != 200:
        return _fail("register", _safe_detail(r1), status=r1.status_code)
    # RegisterGuestResponse nests the uid under "data".
    try:
        uid = (r1.json().get("data") or {}).get("uid")
    except ValueError:
        uid = None
    if not uid:
        return _fail("register", "response contained no uid", status=r1.status_code)

    # --- Step 2: token grant ---
    # The APK sends this as compact JSON too, but with no Authorization header
    # (j.c passes an empty signature key), and reads the token out of "data".
    token_data = json.dumps({
        "uid": int(uid), "password": password_plain, "response_type": "token",
        "client_type": 2, "client_id": int(CLIENT_ID), "client_secret": CLIENT_SECRET,
        "device_id": _device_id(),
    }, separators=(",", ":"))
    token_headers = {"User-Agent": USER_AGENT,
                     "Content-Type": "application/json; charset=utf-8"}
    r2, failure = _post(session, TOKEN_URL, token_data.encode(), token_headers, timeout,
                        "token", uid=uid, password=password_plain)
    if failure:
        return failure
    if r2.status_code != 200:
        return _fail("token", _safe_detail(r2), status=r2.status_code,
                     uid=uid, password=password_plain)
    try:
        grant = r2.json().get("data") or {}
    except ValueError:
        grant = {}
    access_token = grant.get("access_token")
    open_id = grant.get("open_id") or grant.get("openId") or grant.get("openid")
    if not access_token or not open_id:
        return _fail("token", "response contained no access_token/open_id",
                     status=r2.status_code, uid=uid, password=password_plain)

    # --- Step 3: MajorRegister ---
    fields = {
        1: f"0xMe{''.join('⁰¹²³⁴⁵⁶⁷⁸⁹'[int(d)] for d in str(random.randint(1, 9999)))}",
        2: access_token,
        3: open_id,
        5: 102000007,
        6: 4,
        13: 1,
        14: _obfuscate_openid(open_id),
        15: region,
        16: 1,
    }
    try:
        raw_payload = _encode_message(fields)
        _validate_wire_message(raw_payload)
    except ValueError as e:
        return _fail("serialize", f"MajorRegister payload is malformed: {e}",
                     uid=uid, password=password_plain)
    encrypted = bytes.fromhex(_aes_encrypt_hex(raw_payload.hex()))
    headers3 = {
        "Authorization": f"Bearer {access_token}",
        "X-Unity-Version": "2022.3.47f1",
        "X-GA": "v1 1",
        "X-GA-RV": "OB55",
        "X-GA-SV": "1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/octet-stream",
        "User-Agent": USER_AGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    r3, failure = _post(session, MAJOR_REGISTER_URL, encrypted, headers3, timeout,
                        "major_register", uid=uid, password=password_plain)
    if failure:
        return failure
    if r3.status_code != 200:
        return _fail("major_register", _safe_detail(r3), status=r3.status_code,
                     uid=uid, password=password_plain)

    return {"ok": True, "uid": uid, "password": password_plain, "stage": "done",
            "status": r3.status_code, "detail": "", "category": "ok"}


def register_many(regions, session=None):
    """Register several regions, returning {region: result}."""
    session = session or requests.Session()
    return {r: register(r, session=session) for r in regions}


def _write_accounts(path, results, force=False):
    """
    Write successful registrations to `path`.

    Refuses to overwrite an existing file unless `force` is set, so a stray run
    cannot destroy the live account configuration.
    """
    if os.path.exists(path) and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    accounts = {
        region: {"uid": res["uid"], "password": res["password"]}
        for region, res in results.items() if res["ok"]
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(accounts, handle, indent=4)
    return accounts


def _write_credentials(path, results, force=False):
    """
    Write every credential that steps 1-2 produced, even if step 3 failed.

    A result counts as a usable credential once guest register returned a uid and
    token grant accepted it. Step 3 (MajorRegister) finalises the in-game
    profile; when it fails the credential can still authenticate at the Garena
    layer, so it is worth keeping rather than discarding. Each entry records the
    stage the flow stopped at so a partial credential is never mistaken for a
    complete one.

    Refuses to overwrite an existing file unless `force` is set.
    """
    if os.path.exists(path) and not force:
        raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    accounts = {}
    for region, res in results.items():
        if res.get("uid") and res.get("password"):
            accounts[region] = {"uid": res["uid"], "password": res["password"],
                                "stage": res.get("stage")}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(accounts, handle, indent=4)
    return accounts


def main(argv=None):
    parser = argparse.ArgumentParser(description="Register Free Fire guest accounts.")
    parser.add_argument("--region", action="append", choices=REGIONS,
                        help="region to register; repeatable. Default: all regions.")
    parser.add_argument("--out", default=DEFAULT_OUTPUT,
                        help="output JSON path (default: a .generated.json file).")
    parser.add_argument("--force", action="store_true",
                        help="allow overwriting an existing output file.")
    args = parser.parse_args(argv)

    regions = args.region or REGIONS
    results = register_many(regions)

    for region, res in results.items():
        if res["ok"]:
            print(f"{region}: OK uid={res['uid']}")
        elif res.get("uid"):
            print(f"{region}: PARTIAL uid={res['uid']} stage={res['stage']} "
                  f"status={res['status']} detail={res['detail']!r}")
        else:
            print(f"{region}: FAILED stage={res['stage']} status={res['status']} "
                  f"detail={res['detail']!r}")

    written = _write_credentials(args.out, results, force=args.force)
    complete = sum(1 for r in results.values() if r["ok"])
    print(f"wrote {len(written)} credential(s) to {args.out} "
          f"({complete} fully registered)")
    return 0 if complete else 1


if __name__ == "__main__":
    sys.exit(main())
