"""Offline verification of the MajorLogin response pipeline.

No network access and no credentials: it exercises the decoder against sanitized
fixtures captured live on 2026-11-01. Run with:

    python tests/verify_local.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Api import Account

IND = bytes.fromhex(
    "819269d3323b375288e7a62d442bb01b314f48040228c1b74fa978a4af65657e"
    "c4c2deeb851ccfff5a92c75d6ee9dad6f01dc5bc34dd9ed3c44cc1f7dbcc3c04"
    "6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801"
)
ID = bytes.fromhex(
    "18830a9d1d8496090fecd91a67cb5ac2b100c18f40c551b2bc59d973d4f09c0a"
    "a61e1f25cd2329b57612dbb8415487f6290628d06f8c8c484ea9ad7dfb288f04"
    "6a1e08011896cfb0cf0622144578706c6f6974696e67206c6f6f70686f6c65737a020801"
)
SG = bytes.fromhex(
    "9c890b0ace0dc6072c4472adce6d5392590fa150aef50e04514525af453581a5"
    "508cb6e1ce35a0e158ffaf36cb3893294a5e67727802da00a9bbafe93a9e2805"
    "6a1b080118b0f382d206221150726f74656374696f6e204279706173737a020801"
)

CASES = [
    ("IND", IND, 64, "Exploiting loopholes", 1781577563),
    ("ID", ID, 64, "Exploiting loopholes", 1777084310),
    ("SG", SG, 64, "Protection Bypass", 1782626736),
]

failures = 0
for label, body, want_prefix, want_reason, want_wait in CASES:
    decoded = Account.decode_major_login_response(body)
    checks = {
        "_prefixLen": decoded["_prefixLen"] == want_prefix,
        "_framed": decoded["_framed"] is True,
        "_authenticated": decoded["_authenticated"] is False,
        "_restricted": decoded["_restricted"] is True,
        "reason": decoded.get("_restrictionReason") == want_reason,
        "needWaitSecs": decoded["queueInfo"].get("needWaitSecs") == want_wait,
        "no token": "token" not in decoded,
        "no serverUrl": "serverUrl" not in decoded,
        "no spurious field": "ipRegion" not in decoded,
        "appServerId": decoded.get("appServerId", {}).get("serverId") == 1,
        "describe": want_reason in Account.describe_major_login_failure(decoded),
    }
    bad = [k for k, ok in checks.items() if not ok]
    status = "PASS" if not bad else f"FAIL {bad}"
    failures += len(bad)
    print(f"{label:4s} prefix={decoded['_prefixLen']:3d} reason={decoded.get('_restrictionReason')!r:24s} {status}")

# A synthetic genuine grant must still be recognised as authenticated.
import Proto.compiled.MajorLogin_pb2 as ML
grant = ML.response()
grant.token = "t" * 32
grant.serverUrl = "https://client.ind.freefiremobile.com"
grant.ttl = 3600
d = Account.decode_major_login_response(grant.SerializeToString())
ok = d["_authenticated"] and not d["_framed"] and not d["_restricted"]
print(f"{'GRANT':4s} authenticated={d['_authenticated']} framed={d['_framed']} -> {'PASS' if ok else 'FAIL'}")
failures += 0 if ok else 1

print("\nALL CHECKS PASSED" if failures == 0 else f"\n{failures} CHECK(S) FAILED")
sys.exit(1 if failures else 0)
