"""Defect: appServerId silently read as 0.

Root cause: field 15 was declared uint32, but the server sends wire type 2 (a
sub-message). A uint32 can never produce wire type 2, so the field was dropped
and the default 0 was reported. Fix: Proto/MajorLogin.proto declares
`AppServerInfo appServerId = 15`.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Proto.compiled import MajorLogin_pb2

TAIL = bytes.fromhex(
    "6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801")


class AppServerIdTypeTests(unittest.TestCase):
    def test_field_15_is_a_message_not_a_scalar(self):
        field = [f for f in MajorLogin_pb2.response.DESCRIPTOR.fields
                 if f.number == 15][0]
        self.assertEqual(field.type, field.TYPE_MESSAGE)
        self.assertEqual(field.message_type.name, "AppServerInfo")

    def test_field_15_decodes_with_its_real_value(self):
        msg = MajorLogin_pb2.response()
        msg.ParseFromString(TAIL)
        self.assertEqual(msg.appServerId.serverId, 1)

    def test_field_15_is_present_in_listfields(self):
        msg = MajorLogin_pb2.response()
        msg.ParseFromString(TAIL)
        self.assertIn("appServerId", [f.name for f, _ in msg.ListFields()])
