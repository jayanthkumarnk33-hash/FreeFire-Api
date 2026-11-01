import requests
import Proto.compiled.MajorLogin_pb2
from Utilities.until import encode_protobuf, decode_protobuf
import json
from Configuration.APIConfiguration import (
    RELEASEVERSION,
    DEBUG,
    GARENA_TOKEN_URL,
    MAJOR_LOGIN_URL,
    GENERATE_NICKNAME_URL,
    GARENA_CLIENT_ID,
    GARENA_CLIENT_SECRET,
    X_GA,
    X_GA_RV,
    X_GA_SV,
    UNITY_VERSION,
    REQUEST_TIMEOUT,
)


class MajorLoginError(Exception):
    """Raised when MajorLogin is rejected or its response is unusable."""


USER_AGENT = "GarenaMSDK/4.0.44(A063;Android 13;en;IN)"


class AccountNotFoundError(MajorLoginError):
    """
    Raised when the login service answers HTTP 404 "account_not_found".

    A freshly created guest account has an OAuth identity but no game profile
    yet, so MajorLogin cannot resolve it. This is a distinct, expected state and
    must not be reported as a transport or credential failure.

    APK evidence: the client keeps a dedicated ret code for this case
    (PropID_LoginRetNewUser / PropID_RegisterSuccess) and calls MajorRegister
    after it, rather than treating the response as a hard login error.
    """


# Value the client sends in MajorLogin request field 99 ("platform") and in
# PlatformGuestBindReq.guest_platform_type. Confirmed live: the OAuth token
# grant returns "platform": 4 and "main_active_platform": 4 for these accounts.
PLATFORM_ANDROID = "4"


def _safe_error_text(response):
    """Return a short, non-sensitive description of a failed response body."""
    try:
        text = response.text.strip()
    except Exception:
        return "<unreadable body>"
    if not text:
        return "<empty body>"
    return text[:200] + "..." if len(text) > 200 else text


# The live MajorLogin endpoint frames its response as a fixed-length opaque
# prefix followed by a plaintext protobuf message. Parsing the whole body fails
# with a protobuf DecodeError, so the message must be parsed from the correct
# offset. Observed live on 2026-11-01: 100-byte body, plaintext protobuf begins
# at offset 64 (see response-format-investigation.md).
MAJOR_LOGIN_PREFIX_LEN = 64

# Maximum offset scanned when locating the protobuf message. The prefix length
# is not advertised anywhere in the response, so the parser locates the message
# by trying candidate offsets and accepting the first one that parses cleanly.
_MAJOR_LOGIN_MAX_PREFIX = 256


# Field numbers a genuine MajorLoginRes can carry, per the APK-derived schema
# (metadata offset 2885333). Used to reject spurious parses that start inside
# the opaque prefix: a partial parse can land on a byte sequence that happens to
# decode as an unrelated field, e.g. "ipRegion" (field 4), which is not part of
# the client's MajorLoginRes at all.
_EXPECTED_RESPONSE_FIELDS = frozenset({1, 8, 10, 12, 13, 15, 18, 19, 20, 21})


def _parse_framed_message(body, message_cls):
    """
    Parse a framed protobuf body, tolerating a leading opaque prefix.

    The message offset is not advertised in the response, so every 16-byte
    aligned candidate is tried and the most plausible parse wins. A candidate is
    preferred when it yields a field the client's MajorLoginRes can actually
    contain; ties are broken by field count, then by the larger offset (the
    message begins after the prefix, not inside it).

    Returns:
        (offset, message): the offset the message was parsed from and the
        parsed message.

    Raises:
        ValueError: If no offset yields a parseable message.
    """
    best = None
    for offset in range(0, min(len(body), _MAJOR_LOGIN_MAX_PREFIX) + 1, 16):
        if offset >= len(body):
            break
        message = message_cls()
        try:
            message.ParseFromString(body[offset:])
        except Exception:
            continue
        fields = message.ListFields()
        if not fields:
            continue
        has_expected = any(f.number in _EXPECTED_RESPONSE_FIELDS for f, _ in fields)
        score = (has_expected, len(fields), offset)
        if best is None or score > best[0]:
            best = (score, offset, message)
    if best is None:
        raise ValueError("no protobuf message found in framed response")
    return best[1], best[2]


def decode_major_login_response(body):
    """
    Decode a MajorLogin response body into a dict.

    Handles the observed framing (opaque prefix + plaintext protobuf) and
    reports whether the response actually carries a game session token.

    Args:
        body (bytes): Raw response body.

    Returns:
        dict: Decoded fields, plus:
            "_framed": True when a leading prefix was present.
            "_prefixLen": Length of the leading prefix.
            "_authenticated": True when a non-empty "token" was returned.

    Raises:
        MajorLoginError: If the body cannot be decoded at all.
    """
    if not body:
        raise MajorLoginError("MajorLogin returned an empty response")

    try:
        offset, message = _parse_framed_message(body, Proto.compiled.MajorLogin_pb2.response)
    except ValueError as e:
        raise MajorLoginError(f"MajorLogin response could not be decoded: {e}")

    decoded = decode_protobuf(body[offset:], Proto.compiled.MajorLogin_pb2.response)

    # queueInfo.reason is a string in the schema, so it decodes natively. Fall
    # back to a direct wire read only if the schema regresses to the client's
    # bool declaration and the reason is discarded again.
    queue_info = decoded.get("queueInfo") or {}
    reason = queue_info.get("reason")
    if not reason:
        wire_info = extract_queue_info(body[offset:])
        if wire_info:
            queue_info = wire_info
            decoded["queueInfo"] = queue_info
            reason = wire_info.get("reason")

    decoded["_framed"] = offset > 0
    decoded["_prefixLen"] = offset
    decoded["_authenticated"] = bool(decoded.get("token"))
    decoded["_restricted"] = bool(reason)
    if decoded["_restricted"]:
        decoded["_restrictionReason"] = reason
    return decoded


# Field number of the queueInfo message inside MajorLogin.response.
MAJOR_LOGIN_QUEUE_INFO_FIELD = 13


def _iter_wire_fields(buf):
    """
    Iterate (field_number, wire_type, payload) over a protobuf byte buffer.

    payload is an int for varint fields and bytes for length-delimited and
    fixed-width fields.

    Raises:
        ValueError: If the buffer is not well-formed.
    """
    i, n = 0, len(buf)
    while i < n:
        key = shift = 0
        while True:
            if i >= n:
                raise ValueError("truncated key varint")
            b = buf[i]; i += 1
            key |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift > 63:
                raise ValueError("key varint too long")
        field_number, wire_type = key >> 3, key & 7
        if field_number == 0:
            raise ValueError("invalid field number 0")

        if wire_type == 0:
            val = shift = 0
            while True:
                if i >= n:
                    raise ValueError("truncated varint")
                b = buf[i]; i += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
                if shift > 63:
                    raise ValueError("varint too long")
            yield field_number, wire_type, val
        elif wire_type == 2:
            ln = shift = 0
            while True:
                if i >= n:
                    raise ValueError("truncated length varint")
                b = buf[i]; i += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
                if shift > 63:
                    raise ValueError("length varint too long")
            if i + ln > n:
                raise ValueError("truncated payload")
            yield field_number, wire_type, buf[i:i + ln]
            i += ln
        elif wire_type == 5:
            if i + 4 > n:
                raise ValueError("truncated fixed32")
            yield field_number, wire_type, buf[i:i + 4]; i += 4
        elif wire_type == 1:
            if i + 8 > n:
                raise ValueError("truncated fixed64")
            yield field_number, wire_type, buf[i:i + 8]; i += 8
        else:
            raise ValueError(f"unsupported wire type {wire_type}")


def extract_queue_info(message_bytes):
    """
    Read the queueInfo field directly off the wire.

    This is a fallback: the schema declares queueInfo field 4 as a string, so
    decode_protobuf already returns the reason. The client's own metadata names
    that field `queue_is_full` (a bool), and a bool declaration silently drops
    the server's string. This reader exists so the reason survives even if the
    schema is ever regenerated from the client metadata.

    Args:
        message_bytes (bytes): The unframed MajorLogin.response bytes.

    Returns:
        dict | None: {allow, queuePosition, needWaitSecs, reason} or None if the
        field is absent or unparseable.
    """
    try:
        for field_number, wire_type, payload in _iter_wire_fields(message_bytes):
            if field_number != MAJOR_LOGIN_QUEUE_INFO_FIELD or wire_type != 2:
                continue
            info = {}
            for fnum, wtype, val in _iter_wire_fields(payload):
                if fnum == 1 and wtype == 0:
                    info["allow"] = bool(val)
                elif fnum == 2 and wtype == 0:
                    info["queuePosition"] = val
                elif fnum == 3 and wtype == 0:
                    info["needWaitSecs"] = val
                elif fnum == 4 and wtype == 2:
                    info["reason"] = val.decode("utf-8", "replace")
            return info or None
    except ValueError:
        return None
    return None


def get_account_state(access_token, app_id=None):
    """
    Probe the two Garena MSDK routes that describe an account's state.

    Both paths come from the shipped APK's endpoint table
    (com.beetalk.sdk.A0 lines 222 and 256). Neither is a game route, so neither
    needs the game session token that a restricted account never receives.

    Why this exists: when MajorLogin returns only a restriction notice, the
    reason the account cannot be used is invisible from the login response
    alone. These two calls separate the cases:

        user_info reachable + platform bound   -> the account is provisioned
        user_info reachable + no platform bound -> never finished registering
        user_info rejected                      -> the credential itself is dead

    Args:
        access_token (str): Garena access token from get_garena_token().
        app_id (str | int | None): MSDK application id. Defaults to
            GARENA_CLIENT_ID.

    Returns:
        dict: {
            "userInfo": {...} | None,
            "bindInfo": {...} | None,
            "credentialValid": bool,
            "platformBound": bool,
            "errors": [...],
        }
    """
    from Configuration.APIConfiguration import (
        GARENA_USER_INFO_URL,
        GARENA_BIND_INFO_URL,
        GARENA_CLIENT_ID,
    )

    app_id = GARENA_CLIENT_ID if app_id is None else app_id
    headers = {'User-Agent': USER_AGENT, 'Accept': 'application/json'}

    result = {"userInfo": None, "bindInfo": None,
              "credentialValid": False, "platformBound": False, "errors": []}

    try:
        response = requests.get(GARENA_USER_INFO_URL,
                                params={"access_token": access_token},
                                headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            try:
                info = response.json()
            except ValueError:
                info = None
            if isinstance(info, dict) and info.get("uid"):
                result["userInfo"] = info
                result["credentialValid"] = True
        else:
            result["errors"].append(
                f"user/info/get HTTP {response.status_code}: {_safe_error_text(response)}")
    except requests.exceptions.RequestException as e:
        result["errors"].append(f"user/info/get transport error: {type(e).__name__}")

    try:
        response = requests.get(GARENA_BIND_INFO_URL,
                                params={"access_token": access_token, "app_id": app_id},
                                headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            try:
                info = response.json()
            except ValueError:
                info = None
            if isinstance(info, dict):
                result["bindInfo"] = info
                result["platformBound"] = bool(info.get("bounded_accounts"))
        else:
            result["errors"].append(
                f"bind/platform/info/get HTTP {response.status_code}: {_safe_error_text(response)}")
    except requests.exceptions.RequestException as e:
        result["errors"].append(f"bind/platform/info/get transport error: {type(e).__name__}")

    return result


def describe_major_login_failure(result):
    """
    Build a human-readable explanation for a MajorLogin result that did not
    yield a session token.

    Args:
        result (dict | None): Value returned by get_major_login().

    Returns:
        str: Explanation, including the server-supplied reason when present.
    """
    if not result:
        return "MajorLogin returned no result"
    reason = result.get("_restrictionReason")
    if reason:
        return f"Account is restricted by the server: {reason}"
    if result.get("_framed") and not result.get("_authenticated"):
        return ("MajorLogin returned a queue response without a session token "
                f"(prefix {result.get('_prefixLen')} bytes)")
    if not result.get("token"):
        return "MajorLogin response contained no session token"
    if not result.get("serverUrl"):
        return "MajorLogin response contained no server URL"
    return "MajorLogin did not yield a usable session"


def get_garena_token(uid, password):
    """
    Exchange guest credentials for a Garena access token.

    LEG 1 (Garena OAuth / MSDK). app_id, client_id, client_secret, client_type
    and device_id belong to this leg only. The result is an opaque 64-character
    access_token, not a JWT. See login-legs.md before adding a parameter here:
    leg-1 parameters have no effect on any game route.

    Args:
        uid (str): User ID
        password (str): Password

    Returns:
        dict | None: Parsed token response, or None if authentication failed.
    """
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': GARENA_CLIENT_SECRET,
        'client_id': GARENA_CLIENT_ID
    }

    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    try:
        response = requests.post(GARENA_TOKEN_URL, data=payload, headers=headers,
                                 timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        if DEBUG:
            # Never log this response body: it carries access_token/refresh_token.
            print(f"[oauth/guest/token/grant] HTTP {response.status_code}, "
                  f"{len(response.content)} bytes")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")
        return None


def get_major_login(logintoken, openid):
    """
    Perform MajorLogin and return the in-game session token.

    LEG 3 (game login, IL2CPP side). Do not send leg-1 parameters here: adding
    anything to the body breaks the X-GA signature and yields HTTP 400
    "SignError1". The endpoint is protected by an edge signature check. Three headers are
    required and were confirmed live against the running service: 'X-GA',
    'X-GA-RV' (release version) and 'X-GA-SV' (scheme version). Sending 'X-GA'
    alone is rejected with HTTP 400 "SignError1".

    Args:
        logintoken (str): Garena access token from get_garena_token().
        openid (str): Garena open_id for the same account.

    Returns:
        dict: Decoded MajorLogin response (token, serverUrl, ttl, ...).

    Raises:
        MajorLoginError: If the server rejects the request or the response
            cannot be decoded.
    """
    encrypted_payload = encode_protobuf({
        "openid": openid,
        "logintoken": logintoken,
        "platform": PLATFORM_ANDROID,
    }, Proto.compiled.MajorLogin_pb2.request())

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; A063 Build/TKQ1.221220.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'X-Unity-Version': UNITY_VERSION,
        'X-GA': X_GA,
        'X-GA-RV': X_GA_RV,
        'X-GA-SV': X_GA_SV,
        'ReleaseVersion': RELEASEVERSION,
    }

    try:
        response = requests.post(MAJOR_LOGIN_URL, data=encrypted_payload,
                                 headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as e:
        raise MajorLoginError(f"MajorLogin transport error: {e}")

    if response.status_code == 404 and "account_not_found" in response.text:
        raise AccountNotFoundError(
            "MajorLogin: no game profile exists for this OAuth account yet "
            "(HTTP 404 account_not_found)"
        )

    if response.status_code != 200:
        raise MajorLoginError(
            f"MajorLogin rejected with HTTP {response.status_code}: "
            f"{_safe_error_text(response)}"
        )

    if not response.content:
        raise MajorLoginError("MajorLogin returned an empty response")

    return decode_major_login_response(response.content)


def decode_generate_nickname_response(body):
    """
    Decode a /GenerateNickname response.

    The server answers with a plain (unencrypted) protobuf message:
    field 1 is the generated nickname as a length-delimited string, e.g.
    b'\\n\\x0cOmega5w4e0V4'. Confirmed live on 2026-11-01.
    """
    if not body:
        raise MajorLoginError("GenerateNickname returned an empty response")
    for field_no, wire_type, value in _iter_wire_fields(body):
        if field_no == 1 and wire_type == 2 and isinstance(value, bytes):
            return {"nickname": value.decode("utf-8", "replace")}
    raise MajorLoginError("GenerateNickname response had no nickname field")


def get_generated_nickname(logintoken, openid, timeout=REQUEST_TIMEOUT):
    """
    Ask the server for a generated nickname (RPC 'GenerateNickname').

    The APK registers this RPC in its method table and ships
    CSGenerateNicknameReq/Res. It is part of the first-login flow: the client
    requests a name before completing registration.

    Args:
        logintoken (str): Garena access token from get_garena_token().
        openid (str): Garena open_id for the same account.
        timeout (int): Request timeout in seconds.

    Returns:
        dict: {"nickname": str}

    Raises:
        MajorLoginError: If the request fails or the response cannot be decoded.
    """
    encrypted_payload = encode_protobuf({
        "openid": openid,
        "logintoken": logintoken,
        "platform": "4",
    }, Proto.compiled.MajorLogin_pb2.request())

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; A063 Build/TKQ1.221220.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'X-Unity-Version': UNITY_VERSION,
        'X-GA': X_GA,
        'X-GA-RV': X_GA_RV,
        'X-GA-SV': X_GA_SV,
        'ReleaseVersion': RELEASEVERSION,
    }

    try:
        response = requests.post(GENERATE_NICKNAME_URL, data=encrypted_payload,
                                 headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise MajorLoginError(f"GenerateNickname transport error: {e}")

    if response.status_code != 200:
        raise MajorLoginError(
            f"GenerateNickname rejected with HTTP {response.status_code}: "
            f"{_safe_error_text(response)}"
        )

    return decode_generate_nickname_response(response.content)
