"""Defect: MajorLogin response raised protobuf DecodeError.

Root cause: the body is 64 opaque bytes followed by a plaintext protobuf tail.
Parsing the whole body fails. Fix: Api/Account.py:_parse_framed_message.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Api import Account
from Proto.compiled import MajorLogin_pb2

# Real live capture, 2026-11-01 (EVIDENCE/step_2_majorlogin_20261101.txt).
LIVE_BODY = bytes.fromhex(
    "819269d3323b375288e7a62d442bb01b314f48040228c1b74fa978a4af65657e"
    "c4c2deeb851ccfff5a92c75d6ee9dad6f01dc5bc34dd9ed3c44cc1f7dbcc3c04"
    "6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801"
)

class FramingTests(unittest.TestCase):
    def test_parsing_the_whole_body_fails(self):
        with self.assertRaises(Exception):
            MajorLogin_pb2.response().ParseFromString(LIVE_BODY)

    def test_message_is_located_at_offset_64(self):
        offset, _ = Account._parse_framed_message(LIVE_BODY, MajorLogin_pb2.response)
        self.assertEqual(offset, Account.MAJOR_LOGIN_PREFIX_LEN)
        self.assertEqual(offset, 64)

    def test_decoder_reports_framing(self):
        decoded = Account.decode_major_login_response(LIVE_BODY)
        self.assertTrue(decoded["_framed"])
        self.assertEqual(decoded["_prefixLen"], 64)

    def test_empty_body_is_rejected(self):
        with self.assertRaises(Account.MajorLoginError):
            Account.decode_major_login_response(b"")
