"""Defect: the server's restriction reason was silently discarded.

Root cause: LoginQueueInfo field 4 was declared bool (`queueIsFull`) but the
server sends a length-delimited string. Protobuf drops wire-type mismatches.
Fix: Proto/MajorLogin.proto declares `string reason = 4`, plus a wire-level
fallback Api/Account.py:extract_queue_info.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Api import Account
from Proto.compiled import MajorLogin_pb2

TAIL = bytes.fromhex(
    "6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801")


class ReasonDroppedTests(unittest.TestCase):
    def test_schema_declares_field_4_as_string(self):
        field = [f for f in MajorLogin_pb2.LoginQueueInfo.DESCRIPTOR.fields
                 if f.number == 4][0]
        self.assertEqual(field.type, field.TYPE_STRING)
        self.assertEqual(field.name, "reason")

    def test_reason_decodes_natively(self):
        msg = MajorLogin_pb2.response()
        msg.ParseFromString(TAIL)
        self.assertEqual(msg.queueInfo.reason, "Exploiting loopholes")

    def test_wire_fallback_recovers_the_reason(self):
        info = Account.extract_queue_info(TAIL)
        self.assertIsNotNone(info)
        self.assertEqual(info["reason"], "Exploiting loopholes")
        self.assertTrue(info["allow"])
        self.assertEqual(info["needWaitSecs"], 1781577563)

    def test_restriction_is_surfaced_by_the_decoder(self):
        decoded = Account.decode_major_login_response(TAIL)
        self.assertTrue(decoded["_restricted"])
        self.assertFalse(decoded["_authenticated"])
        self.assertEqual(decoded["_restrictionReason"], "Exploiting loopholes")

    def test_describe_names_the_reason(self):
        decoded = Account.decode_major_login_response(TAIL)
        self.assertIn("Exploiting loopholes",
                      Account.describe_major_login_failure(decoded))
