"""Regression tests for MajorLogin response framing.

The live endpoint frames its response as a fixed-length opaque prefix followed
by a plaintext protobuf message. These tests pin the decoder behaviour using a
sanitized fixture captured on 2026-11-01 (a login-queue response; it carries no
credentials, no token and no server URL).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Proto.compiled.MajorLogin_pb2 as MajorLogin
from Api import Account

# 100-byte live body: 64-byte opaque prefix + plaintext MajorLoginRes protobuf.
LIVE_QUEUE_FIXTURE = bytes.fromhex(
    "819269d3323b375288e7a62d442bb01b314f48040228c1b74fa978a4af65657e"
    "c4c2deeb851ccfff5a92c75d6ee9dad6f01dc5bc34dd9ed3c44cc1f7dbcc3c04"
    "6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801"
)


class FramingDetectionTests(unittest.TestCase):
    def test_live_fixture_is_100_bytes_with_64_byte_prefix(self):
        self.assertEqual(len(LIVE_QUEUE_FIXTURE), 100)
        self.assertEqual(Account.MAJOR_LOGIN_PREFIX_LEN, 64)

    def test_whole_body_does_not_parse(self):
        with self.assertRaises(Exception):
            MajorLogin.response().ParseFromString(LIVE_QUEUE_FIXTURE)

    def test_tail_parses_as_majore_login_res(self):
        msg = MajorLogin.response()
        msg.ParseFromString(LIVE_QUEUE_FIXTURE[64:])
        self.assertTrue(msg.queueInfo.allow)
        self.assertEqual(msg.queueInfo.needWaitSecs, 1781577563)
        self.assertEqual(msg.queueInfo.reason, "Exploiting loopholes")
        self.assertEqual(msg.appServerId.serverId, 1)


class DecoderTests(unittest.TestCase):
    def test_decoder_locates_message_at_offset_64(self):
        decoded = Account.decode_major_login_response(LIVE_QUEUE_FIXTURE)
        self.assertTrue(decoded["_framed"])
        self.assertEqual(decoded["_prefixLen"], Account.MAJOR_LOGIN_PREFIX_LEN)

    def test_queue_response_is_not_authenticated(self):
        decoded = Account.decode_major_login_response(LIVE_QUEUE_FIXTURE)
        self.assertFalse(decoded["_authenticated"])
        self.assertNotIn("token", decoded)
        self.assertNotIn("serverUrl", decoded)

    def test_unframed_message_still_decodes(self):
        msg = MajorLogin.response()
        msg.token = "t" * 32
        msg.serverUrl = "https://client.ind.freefiremobile.com"
        decoded = Account.decode_major_login_response(msg.SerializeToString())
        self.assertFalse(decoded["_framed"])
        self.assertEqual(decoded["_prefixLen"], 0)
        self.assertTrue(decoded["_authenticated"])
        self.assertEqual(decoded["serverUrl"], "https://client.ind.freefiremobile.com")

    def test_empty_body_raises(self):
        with self.assertRaises(Account.MajorLoginError):
            Account.decode_major_login_response(b"")

    def test_undecodable_body_raises(self):
        with self.assertRaises(Account.MajorLoginError):
            Account.decode_major_login_response(b"\xff" * 128)


class MajorLoginIntegrationTests(unittest.TestCase):
    def test_get_major_login_returns_decoded_queue_response(self):
        from unittest import mock

        resp = mock.Mock(status_code=200, content=LIVE_QUEUE_FIXTURE, text="")
        with mock.patch.object(Account.requests, "post", return_value=resp):
            result = Account.get_major_login("logintoken", "openid")
        self.assertTrue(result["_framed"])
        self.assertEqual(result["_prefixLen"], 64)
        self.assertFalse(result["_authenticated"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class QueueInfoReasonTests(unittest.TestCase):
    """queueInfo field 4 is declared bool but the server sends a string reason."""

    # IND account, live 2026-11-01: 64-byte prefix + MajorLoginRes tail.
    IND_RESTRICTED = bytes.fromhex(
        "819269d3323b375288e7a62d442bb01b314f48040228c1b74fa978a4af65657e"
        "c4c2deeb851ccfff5a92c75d6ee9dad6f01dc5bc34dd9ed3c44cc1f7dbcc3c04"
        "6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801"
    )
    SG_RESTRICTED = bytes.fromhex(
        "9c890b0ace0dc6072c4472adce6d5392590fa150aef50e04514525af453581a5"
        "508cb6e1ce35a0e158ffaf36cb3893294a5e67727802da00a9bbafe93a9e2805"
        "6a1b080118b0f382d206221150726f74656374696f6e204279706173737a020801"
    )

    def test_reason_decodes_natively(self):
        # queueInfo field 4 is declared string, matching what the server sends.
        msg = MajorLogin.response()
        msg.ParseFromString(self.IND_RESTRICTED[64:])
        self.assertEqual(msg.queueInfo.reason, "Exploiting loopholes")

    def test_reason_recovered_from_the_wire(self):
        info = Account.extract_queue_info(self.IND_RESTRICTED[64:])
        self.assertEqual(info["reason"], "Exploiting loopholes")
        self.assertTrue(info["allow"])
        self.assertEqual(info["needWaitSecs"], 1781577563)

    def test_second_account_reason_differs(self):
        info = Account.extract_queue_info(self.SG_RESTRICTED[64:])
        self.assertEqual(info["reason"], "Protection Bypass")
        self.assertEqual(info["needWaitSecs"], 1782626736)

    def test_decoder_reports_restriction(self):
        decoded = Account.decode_major_login_response(self.IND_RESTRICTED)
        self.assertTrue(decoded["_restricted"])
        self.assertEqual(decoded["_restrictionReason"], "Exploiting loopholes")
        self.assertFalse(decoded["_authenticated"])

    def test_unrestricted_response_is_not_flagged(self):
        msg = MajorLogin.response()
        msg.queueInfo.allow = True
        msg.queueInfo.needWaitSecs = 5
        decoded = Account.decode_major_login_response(msg.SerializeToString())
        self.assertFalse(decoded["_restricted"])
        self.assertNotIn("_restrictionReason", decoded)

    def test_extract_queue_info_handles_garbage(self):
        self.assertIsNone(Account.extract_queue_info(b"\xff\xff\xff\xff"))
        self.assertIsNone(Account.extract_queue_info(b""))

    def test_describe_names_the_reason(self):
        decoded = Account.decode_major_login_response(self.IND_RESTRICTED)
        text = Account.describe_major_login_failure(decoded)
        self.assertIn("Exploiting loopholes", text)

    def test_describe_handles_no_result(self):
        self.assertIn("no result", Account.describe_major_login_failure(None))


class SpuriousParseTests(unittest.TestCase):
    """The decoder must not accept a partial parse that starts inside the prefix.

    For the ID account's response, offset 48 happens to decode as
    `ipRegion` (field 4), which the client's MajorLoginRes cannot contain. The
    decoder must prefer the real message at offset 64.
    """

    ID_RESTRICTED = bytes.fromhex(
        "18830a9d1d8496090fecd91a67cb5ac2b100c18f40c551b2bc59d973d4f09c0a"
        "a61e1f25cd2329b57612dbb8415487f6290628d06f8c8c484ea9ad7dfb288f04"
        "6a1e08011896cfb0cf0622144578706c6f6974696e67206c6f6f70686f6c65737a020801"
    )

    def test_offset_48_is_a_spurious_parse(self):
        msg = MajorLogin.response()
        msg.ParseFromString(self.ID_RESTRICTED[48:])
        # ipRegion is not part of the client's MajorLoginRes at all.
        self.assertIn("ipRegion", [f.name for f, _ in msg.ListFields()])

    def test_real_message_is_at_offset_64(self):
        msg = MajorLogin.response()
        msg.ParseFromString(self.ID_RESTRICTED[64:])
        self.assertEqual([f.name for f, _ in msg.ListFields()], ["queueInfo", "appServerId"])

    def test_decoder_prefers_the_real_message(self):
        decoded = Account.decode_major_login_response(self.ID_RESTRICTED)
        self.assertEqual(decoded["_prefixLen"], 64)
        self.assertEqual(decoded["queueInfo"]["reason"], "Exploiting loopholes")
        self.assertNotIn("ipRegion", decoded)

    def test_decoder_still_handles_an_unframed_message(self):
        msg = MajorLogin.response()
        msg.queueInfo.allow = True
        msg.appServerId.serverId = 1
        decoded = Account.decode_major_login_response(msg.SerializeToString())
        self.assertEqual(decoded["_prefixLen"], 0)
        self.assertFalse(decoded["_framed"])


class AppServerIdTypeTests(unittest.TestCase):
    """Field 15 is a sub-message on the wire, not a uint32.

    Declaring it uint32 silently discarded it and made the value look like a
    genuine appServerId = 0. These tests pin the corrected type.
    """

    TAIL = bytes.fromhex("6a1e080118dbeec2d10622144578706c6f6974696e67206c6f6f70686f6c65737a020801")

    def test_field_15_is_declared_as_a_message(self):
        field = [f for f in MajorLogin.response.DESCRIPTOR.fields if f.number == 15][0]
        self.assertEqual(field.type, field.TYPE_MESSAGE)
        self.assertEqual(field.message_type.name, "AppServerInfo")

    def test_field_15_decodes_with_its_nested_value(self):
        msg = MajorLogin.response()
        msg.ParseFromString(self.TAIL)
        self.assertEqual(msg.appServerId.serverId, 1)

    def test_field_15_is_present_in_listfields(self):
        msg = MajorLogin.response()
        msg.ParseFromString(self.TAIL)
        self.assertIn("appServerId", [f.name for f, _ in msg.ListFields()])
