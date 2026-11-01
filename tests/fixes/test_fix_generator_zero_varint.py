"""Defect: the generator emitted malformed protobuf for zero-valued fields.

Root cause: the varint encoder returned b"" for 0, so a zero field became a bare
tag with no value byte (`30`), which is corrupt protobuf. Fix:
Additional/GenerateAccounts.py:_varint encodes 0 as b"\x00".
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Additional import GenerateAccounts as G
from Proto.compiled import MajorLogin_pb2


class ZeroVarintTests(unittest.TestCase):
    def test_varint_of_zero_is_a_single_zero_byte(self):
        self.assertEqual(G._varint(0), b"\x00")

    def test_original_bare_tag_was_malformed(self):
        # _orig_bare_tag reproduces the pre-fix output for a zero field.
        self.assertEqual(G._orig_bare_tag(6), b"\x30")
        with self.assertRaises(Exception):
            MajorLogin_pb2.request().ParseFromString(b"\x30")

    def test_zero_field_now_parses(self):
        msg = MajorLogin_pb2.request()
        msg.ParseFromString(G._encode_field(6, 0))
        self.assertEqual(msg.platid, 0)

    def test_wire_validator_rejects_the_old_output(self):
        with self.assertRaises(ValueError):
            G._validate_wire_message(b"\x30")
