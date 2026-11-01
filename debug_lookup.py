#!/usr/bin/env python3
"""Run the full auth chain and attempt the player UID lookup, printing everything.

    python debug_lookup.py [uid] [region]

Defaults: uid=11111111 (the PLAYER to look up), region=IND.

Distinct identifiers, never conflated:
    auth account uid  -> the guest account that authenticates (from config)
    lookup target uid -> the player whose profile is requested (argument)

On failure the raw bytes are hexdumped so the next session can see exactly what
the server returned. No secrets are printed: token material is shown as length
plus a short fingerprint, never the value.
"""
import hashlib
import json
import sys

import requests

sys.path.insert(0, ".")

from Api.Account import (  # noqa: E402
    MajorLoginError,
    describe_major_login_failure,
    get_garena_token,
    get_major_login,
)
from Api.InGame import get_player_personal_show  # noqa: E402
from Utilities.until import load_accounts  # noqa: E402

DEFAULT_TARGET_UID = "11111111"
DEFAULT_REGION = "IND"


def fingerprint(value):
    """Short, non-reversible identifier for a secret. Never prints the value."""
    if not value:
        return "<absent>"
    return f"<len={len(value)} sha256={hashlib.sha256(value.encode()).hexdigest()[:12]}>"


def hexdump(data, limit=512):
    if not data:
        return "    <empty>"
    head = data[:limit]
    lines = []
    for i in range(0, len(head), 16):
        chunk = head[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {i:04x}  {hexpart}  {text}")
    if len(data) > limit:
        lines.append(f"    ... ({len(data) - limit} more bytes)")
    return "\n".join(lines)


def main(argv):
    target_uid = argv[1] if len(argv) > 1 else DEFAULT_TARGET_UID
    region = (argv[2] if len(argv) > 2 else DEFAULT_REGION).upper()

    print("=" * 70)
    print(f"lookup target uid (PLAYER) : {target_uid}")
    print(f"region                     : {region}")
    print("=" * 70)

    accounts = load_accounts()
    if region not in accounts:
        print(f"FAIL: region {region} not in config. Available: {sorted(accounts)}")
        return 2
    account = accounts[region]
    print(f"auth account uid (GUEST)   : {account['uid']}   <- distinct from target")
    print()

    # --- Step 1: Garena token grant ---
    print("[1] guest token grant ...")
    token_response = get_garena_token(account["uid"], account["password"])
    if not token_response or "access_token" not in token_response:
        print("    FAIL: no access_token. Raw response:")
        print(hexdump(json.dumps(token_response or {}, indent=2).encode()))
        return 1
    print(f"    OK  access_token {fingerprint(token_response['access_token'])}")
    print(f"        open_id      {fingerprint(token_response.get('open_id'))}")
    print()

    # --- Step 2: MajorLogin ---
    print("[2] major_login ...")
    try:
        login = get_major_login(token_response["access_token"],
                                token_response["open_id"])
    except MajorLoginError as exc:
        print(f"    FAIL (MajorLoginError): {exc}")
        return 1

    print(f"    HTTP 200, decoded keys: {sorted(k for k in login if not k.startswith('_'))}")
    print(f"    _framed={login.get('_framed')} _prefixLen={login.get('_prefixLen')}")
    print(f"    _authenticated={login.get('_authenticated')} "
          f"_restricted={login.get('_restricted')}")
    if login.get("queueInfo"):
        print(f"    queueInfo={login['queueInfo']}")

    if not login.get("_authenticated"):
        print()
        print(f"    BLOCKED: {describe_major_login_failure(login)}")
        print("    No session token was issued, so the lookup cannot proceed.")
        print("    Raw MajorLogin body:")
        try:
            with open("EVIDENCE/majorlogin_body.bin", "rb") as handle:
                print(hexdump(handle.read()))
        except OSError:
            print("    (no saved body; re-run the capture to store one)")
        return 1

    print(f"    OK  session token {fingerprint(login.get('token'))}")
    print(f"        serverUrl = {login.get('serverUrl')}")
    print()

    # --- Step 3: player lookup ---
    print(f"[3] uid lookup for PLAYER {target_uid} ...")
    result = get_player_personal_show(login["serverUrl"], login["token"], int(target_uid))
    if result is None:
        print("    FAIL: get_player_personal_show returned None (see stderr for the"
              " status code; body is only dumped when DEBUG=True)")
        return 1

    print("    OK  decoded response:")
    print(json.dumps(result, indent=2)[:2000])
    out = f"LOOKUP_{target_uid}_{region}.json"
    with open(out, "w") as handle:
        json.dump(result, handle, indent=2)
    print(f"\n    saved -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
