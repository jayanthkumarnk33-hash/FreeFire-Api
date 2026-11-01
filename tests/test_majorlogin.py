"""Regression tests for the MajorLogin authentication chain.

These tests pin the request-side contract that was verified against the live
service: the X-GA / X-GA-RV / X-GA-SV header triple must be present, the payload
must be AES-CBC encrypted, and a non-200 response must surface as
MajorLoginError rather than a silent False.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES

from Api import Account
from Configuration.AESConfiguration import MAIN_KEY, MAIN_IV
from Configuration import APIConfiguration as cfg
from Utilities.until import encode_protobuf, decode_protobuf
import Proto.compiled.MajorLogin_pb2 as MajorLogin


def _ok_response():
    """A minimal, valid MajorLogin response body (serverUrl + token)."""
    msg = MajorLogin.response()
    msg.serverUrl = "https://client.ind.freefiremobile.com"
    msg.token = "x" * 32
    msg.ttl = 3600
    return mock.Mock(status_code=200, content=msg.SerializeToString(), text="")


class MajorLoginHeaderTests(unittest.TestCase):
    def test_required_signature_headers_present(self):
        with mock.patch.object(Account.requests, "post", return_value=_ok_response()) as post:
            Account.get_major_login("logintoken-value", "openid-value")

        headers = post.call_args.kwargs["headers"]
        self.assertEqual(headers["X-GA"], cfg.X_GA)
        self.assertEqual(headers["X-GA-RV"], cfg.RELEASEVERSION)
        self.assertEqual(headers["X-GA-SV"], cfg.X_GA_SV)
        self.assertEqual(headers["ReleaseVersion"], cfg.RELEASEVERSION)

    def test_request_has_timeout(self):
        with mock.patch.object(Account.requests, "post", return_value=_ok_response()) as post:
            Account.get_major_login("logintoken-value", "openid-value")
        self.assertEqual(post.call_args.kwargs["timeout"], cfg.REQUEST_TIMEOUT)

    def test_payload_is_aes_encrypted(self):
        with mock.patch.object(Account.requests, "post", return_value=_ok_response()) as post:
            Account.get_major_login("logintoken-value", "openid-value")

        body = post.call_args.kwargs["data"]
        self.assertEqual(len(body) % AES.block_size, 0)
        plain = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).decrypt(body)
        decoded = MajorLogin.request()
        decoded.ParseFromString(plain[:-plain[-1]])
        self.assertEqual(decoded.openid, "openid-value")
        self.assertEqual(decoded.logintoken, "logintoken-value")
        self.assertEqual(decoded.platform, "4")


class MajorLoginFailureTests(unittest.TestCase):
    def test_sig_error_surfaces_as_major_login_error(self):
        bad = mock.Mock(status_code=400, content=b"SignError1\n", text="SignError1\n")
        with mock.patch.object(Account.requests, "post", return_value=bad):
            with self.assertRaises(Account.MajorLoginError) as ctx:
                Account.get_major_login("t", "o")
        self.assertIn("400", str(ctx.exception))
        self.assertIn("SignError1", str(ctx.exception))

    def test_undecodable_body_surfaces_as_major_login_error(self):
        junk = mock.Mock(status_code=200, content=b"\xff\xfe\xfd", text="")
        with mock.patch.object(Account.requests, "post", return_value=junk):
            with self.assertRaises(Account.MajorLoginError):
                Account.get_major_login("t", "o")

    def test_empty_body_surfaces_as_major_login_error(self):
        empty = mock.Mock(status_code=200, content=b"", text="")
        with mock.patch.object(Account.requests, "post", return_value=empty):
            with self.assertRaises(Account.MajorLoginError):
                Account.get_major_login("t", "o")

    def test_transport_error_surfaces_as_major_login_error(self):
        with mock.patch.object(Account.requests, "post",
                               side_effect=Account.requests.exceptions.Timeout("boom")):
            with self.assertRaises(Account.MajorLoginError):
                Account.get_major_login("t", "o")


class GarenaTokenTests(unittest.TestCase):
    def test_token_request_uses_config_credentials_and_timeout(self):
        body = b'{"access_token": "a", "open_id": "b"}'
        resp = mock.Mock(status_code=200, content=body, text=body.decode())
        resp.json.return_value = {"access_token": "a", "open_id": "b"}
        with mock.patch.object(Account.requests, "post", return_value=resp) as post:
            result = Account.get_garena_token("uid-1", "pw-1")

        self.assertEqual(result["access_token"], "a")
        payload = post.call_args.kwargs["data"]
        self.assertEqual(payload["client_id"], cfg.GARENA_CLIENT_ID)
        self.assertEqual(payload["client_secret"], cfg.GARENA_CLIENT_SECRET)
        self.assertEqual(post.call_args.kwargs["timeout"], cfg.REQUEST_TIMEOUT)

    def test_token_failure_returns_none(self):
        with mock.patch.object(Account.requests, "post",
                               side_effect=Account.requests.exceptions.ConnectionError("down")):
            self.assertIsNone(Account.get_garena_token("uid-1", "pw-1"))


class ProtobufRoundTripTests(unittest.TestCase):
    def test_encode_then_decrypt_round_trip(self):
        data = {"openid": "oid", "logintoken": "tok", "platform": "4"}
        encoded = encode_protobuf(data, MajorLogin.request())
        # encode_protobuf AES-encrypts, so decrypt before parsing.
        plain = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).decrypt(encoded)
        decoded = MajorLogin.request()
        decoded.ParseFromString(plain[:-plain[-1]])
        self.assertEqual(decoded.openid, "oid")
        self.assertEqual(decoded.platform, "4")

    def test_decode_protobuf_parses_plaintext(self):
        msg = MajorLogin.response()
        msg.serverUrl = "https://client.ind.freefiremobile.com"
        msg.token = "tok"
        decoded = decode_protobuf(msg.SerializeToString(), MajorLogin.response)
        self.assertEqual(decoded["serverUrl"], "https://client.ind.freefiremobile.com")

    def test_response_prefix_is_not_plaintext(self):
        """The live service returns 64 encrypted bytes before the plaintext tail.

        This pins the currently-unsolved part of the protocol: a body shaped like
        the live response must NOT silently decode as a usable response.
        """
        msg = MajorLogin.response()
        msg.serverUrl = "https://client.ind.freefiremobile.com"
        msg.token = "x" * 32
        live_shaped = b"\x81\x92\x69\xd3" + b"\x00" * 60 + msg.SerializeToString()
        with self.assertRaises(Exception):
            decode_protobuf(live_shaped, MajorLogin.response)


if __name__ == "__main__":
    unittest.main(verbosity=2)
