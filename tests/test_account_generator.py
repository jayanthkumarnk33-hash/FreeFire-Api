"""Tests for Additional/GenerateAccounts.py.

All network access is replaced by an injected fake session, so these tests are
offline and deterministic. They pin:
  * the exact URLs, methods, headers and parameters of each step,
  * success and every failure mode,
  * timeout / connection-error handling,
  * that the output writer refuses to clobber an existing file,
  * byte-for-byte equivalence of the payload encoders with the original script.
"""
import hashlib
import hmac
import json
import os
import sys
import tempfile
import unittest
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Additional import GenerateAccounts as G
from Api import Account as A


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeSession:
    """Records requests and replays canned responses in order."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append({"url": url, "data": data, "headers": headers, "timeout": timeout})
        if not self.responses:
            raise AssertionError("unexpected extra request")
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def ok_responses():
    # Register and token responses nest their payload under "data" (the shipped
    # client parses RegisterGuestResponse / the token grant that way).
    return [
        FakeResponse(200, {"code": 0, "data": {"uid": 4700123456}}),
        FakeResponse(200, {"code": 0, "data": {"access_token": "at-" + "x" * 20,
                                              "open_id": "oid-123"}}),
        FakeResponse(200, {}),
    ]


class RequestConstructionTests(unittest.TestCase):
    def setUp(self):
        self.session = FakeSession(ok_responses())
        self.result = G.register("IND", session=self.session)

    def test_three_requests_in_order(self):
        self.assertEqual(len(self.session.calls), 3)
        self.assertEqual([c["url"] for c in self.session.calls],
                         [G.REGISTER_URL, G.TOKEN_URL, G.MAJOR_REGISTER_URL])

    def test_register_request_shape(self):
        call = self.session.calls[0]
        self.assertEqual(call["headers"]["Content-Type"], "application/json; charset=utf-8")
        body = json.loads(call["data"])
        self.assertEqual(body["client_type"], 2)
        self.assertEqual(body["source"], 2)
        self.assertEqual(body["app_id"], int(G.CLIENT_ID))
        self.assertEqual(len(body["password"]), 64)
        self.assertEqual(body["password"], body["password"].upper())

    def test_register_endpoint_is_the_apk_one(self):
        # com.beetalk.sdk.A0.P() -> connect.garena.com/api/v2/oauth/guest:register
        self.assertEqual(G.REGISTER_URL,
                         "https://connect.garena.com/api/v2/oauth/guest:register")

    def test_register_signature_header(self):
        call = self.session.calls[0]
        expected = "Signature " + hmac.new(
            G.CLIENT_SECRET.encode(), call["data"], hashlib.sha256).hexdigest()
        self.assertEqual(call["headers"]["Authorization"], expected)

    def test_register_body_is_compact_json(self):
        # The signature covers the exact bytes sent, so the encoding must match
        # what Gson produces: no spaces after the separators.
        raw = self.session.calls[0]["data"]
        self.assertIsInstance(raw, bytes)
        self.assertNotIn(b" ", raw)
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        json.loads(raw)

    def test_token_request_shape(self):
        call = self.session.calls[1]
        self.assertEqual(call["headers"]["Content-Type"], "application/json; charset=utf-8")
        body = json.loads(call["data"])
        self.assertEqual(body["response_type"], "token")
        self.assertEqual(body["client_id"], int(G.CLIENT_ID))
        self.assertEqual(body["client_secret"], G.CLIENT_SECRET)
        self.assertEqual(body["uid"], 4700123456)
        # The token grant carries no Authorization header in the shipped client.
        self.assertNotIn("Authorization", call["headers"])

    def test_password_matches_apk_derivation(self):
        # SHA-256 over 64 chars drawn from the APK alphabet, rendered upper hex.
        password = json.loads(self.session.calls[0]["data"])["password"]
        self.assertEqual(len(password), 64)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in password))
        for c in G.PASSWORD_ALPHABET:
            self.assertIn(c, "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()")

    def test_major_register_headers(self):
        call = self.session.calls[2]
        self.assertTrue(call["headers"]["Authorization"].startswith("Bearer "))
        self.assertEqual(call["headers"]["Content-Type"], "application/octet-stream")

    def test_major_register_body_is_aes_block_aligned(self):
        body = self.session.calls[2]["data"]
        self.assertIsInstance(body, bytes)
        self.assertEqual(len(body) % 16, 0)
        self.assertGreater(len(body), 0)

    def test_every_request_has_a_timeout(self):
        for call in self.session.calls:
            self.assertEqual(call["timeout"], G.REQUEST_TIMEOUT)

    def test_success_result(self):
        self.assertTrue(self.result["ok"])
        self.assertEqual(self.result["uid"], 4700123456)
        self.assertEqual(self.result["stage"], "done")
        self.assertIsNotNone(self.result["password"])


class FailureModeTests(unittest.TestCase):
    def _register(self, responses):
        return G.register("IND", session=FakeSession(responses))

    def test_unknown_region_rejected_before_any_request(self):
        session = FakeSession([])
        res = G.register("XX", session=session)
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "validate")
        self.assertEqual(session.calls, [])

    def test_register_non_200(self):
        res = self._register([FakeResponse(403, None, "forbidden")])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "register")
        self.assertEqual(res["status"], 403)

    def test_register_missing_uid(self):
        res = self._register([FakeResponse(200, {})])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "register")
        self.assertIn("no uid", res["detail"])

    def test_register_non_json_body(self):
        res = self._register([FakeResponse(200, None, "<html>")])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "register")

    def test_token_non_200(self):
        res = self._register([FakeResponse(200, {"data": {"uid": 1}}),
                              FakeResponse(400, None, "bad")])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "token")
        self.assertEqual(res["status"], 400)

    def test_token_missing_fields(self):
        res = self._register([FakeResponse(200, {"data": {"uid": 1}}),
                              FakeResponse(200, {"data": {"access_token": "a"}})])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "token")

    def test_uid_nested_under_data_is_required(self):
        # A top-level uid (the old shape) must NOT be accepted: the live service
        # nests it under "data".
        res = self._register([FakeResponse(200, {"uid": 1})])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "register")
        self.assertIn("no uid", res["detail"])

    def test_major_register_non_200(self):
        res = self._register(ok_responses()[:2] + [FakeResponse(500, None, "err")])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "major_register")
        self.assertEqual(res["status"], 500)

    def test_connection_error_is_caught(self):
        import requests
        res = self._register([requests.ConnectionError("boom")])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "register")
        self.assertIn("ConnectionError", res["detail"])

    def test_timeout_is_caught(self):
        import requests
        res = self._register(ok_responses()[:1] + [requests.Timeout("slow")])
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "token")

    def test_failure_detail_is_truncated(self):
        res = self._register([FakeResponse(500, None, "z" * 5000)])
        self.assertLessEqual(len(res["detail"]), 200)

    def test_password_never_appears_in_failure_detail(self):
        session = FakeSession(ok_responses())
        res = G.register("IND", session=session)
        # The password is the plain 10-digit value; ensure no failure string holds it.
        self.assertNotIn(res["password"], res["detail"])


class OutputWriterTests(unittest.TestCase):
    def test_writes_only_successful_accounts(self):
        results = {
            "IND": {"ok": True, "uid": 111, "password": "p1"},
            "SG": {"ok": False, "uid": None, "password": None},
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            written = G._write_accounts(path, results)
            self.assertEqual(set(written), {"IND"})
            with open(path) as handle:
                self.assertEqual(json.load(handle), {"IND": {"uid": 111, "password": "p1"}})

    def test_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            with open(path, "w") as handle:
                handle.write("{}")
            with self.assertRaises(FileExistsError):
                G._write_accounts(path, {"IND": {"ok": True, "uid": 1, "password": "p"}})

    def test_force_allows_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            with open(path, "w") as handle:
                handle.write("{}")
            G._write_accounts(path, {"IND": {"ok": True, "uid": 1, "password": "p"}}, force=True)
            with open(path) as handle:
                self.assertEqual(json.load(handle)["IND"]["uid"], 1)

    def test_default_output_is_not_the_live_config(self):
        self.assertNotIn("AccountConfiguration.json", os.path.basename(G.DEFAULT_OUTPUT))
        self.assertIn("generated", G.DEFAULT_OUTPUT)


class PartialCredentialWriterTests(unittest.TestCase):
    """
    Steps 1-2 produce a real credential even when step 3 fails, so the account
    JSON must be written rather than silently discarded.
    """

    def _partial(self):
        return {"IND": {"ok": False, "uid": 4700999888, "password": "AB" * 32,
                        "stage": "major_register", "status": 500, "detail": "boom"}}

    def test_writes_a_credential_that_stopped_at_major_register(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            written = G._write_credentials(path, self._partial())
            self.assertEqual(set(written), {"IND"})
            with open(path) as handle:
                saved = json.load(handle)["IND"]
            self.assertEqual(saved["uid"], 4700999888)
            self.assertEqual(saved["password"], "AB" * 32)
            # The stopping stage is recorded so a partial credential is visible.
            self.assertEqual(saved["stage"], "major_register")

    def test_skips_results_with_no_uid(self):
        results = {"IND": {"ok": False, "uid": None, "password": None,
                           "stage": "register", "status": 404, "detail": "nope"}}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            self.assertEqual(G._write_credentials(path, results), {})

    def test_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            with open(path, "w") as handle:
                handle.write("{}")
            with self.assertRaises(FileExistsError):
                G._write_credentials(path, self._partial())

    def test_force_allows_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            with open(path, "w") as handle:
                handle.write("{}")
            G._write_credentials(path, self._partial(), force=True)
            with open(path) as handle:
                self.assertEqual(json.load(handle)["IND"]["uid"], 4700999888)

    def test_complete_registration_also_records_stage(self):
        results = {"IND": {"ok": True, "uid": 1, "password": "p", "stage": "done"}}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            G._write_credentials(path, results)
            with open(path) as handle:
                self.assertEqual(json.load(handle)["IND"]["stage"], "done")


class ApkContractTests(unittest.TestCase):
    """The endpoints and shapes the shipped client actually uses."""

    def test_register_endpoint_matches_apk_a0_p(self):
        self.assertEqual(G.REGISTER_URL,
                         "https://connect.garena.com/api/v2/oauth/guest:register")

    def test_token_endpoint_matches_apk_a0_c(self):
        self.assertEqual(G.TOKEN_URL,
                         "https://connect.garena.com/api/v2/oauth/guest/token:grant")

    def test_password_alphabet_matches_helper_f(self):
        self.assertEqual(G.PASSWORD_ALPHABET,
                         "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()")
        self.assertEqual(G.PASSWORD_LENGTH, 64)

    def test_generated_password_is_sha256_upper_hex(self):
        for _ in range(5):
            pw = G._new_guest_password()
            self.assertEqual(len(pw), 64)
            self.assertTrue(all(c in "0123456789ABCDEF" for c in pw))

    def test_device_id_is_32_hex(self):
        for _ in range(5):
            self.assertRegex(G._device_id(), r"^[0-9a-f]{32}$")

    def test_user_agent_reports_the_current_msdk_build(self):
        self.assertIn("GarenaMSDK/4.0.44", G.USER_AGENT)


    def test_platform_rejection_is_its_own_category(self):
        # The register service answers with its own error code when it
        # understands the payload but refuses the platform. That is a distinct
        # outcome from a bad request or a missing route, so it must not be
        # flattened into "bad_request".
        self.assertEqual(
            G.classify_failure("major_register", 400, "BR_PLATFORM_INVALID_PLATFORM"),
            "platform_rejected")

    def test_plain_bad_request_is_still_bad_request(self):
        self.assertEqual(G.classify_failure("register", 400, "error_params"),
                         "bad_request")

    def test_missing_route_is_still_not_found(self):
        self.assertEqual(G.classify_failure("major_register", 404, "404 page not found"),
                         "endpoint_not_found")


class EncoderEquivalenceTests(unittest.TestCase):
    """The refactored encoders must match the original script byte for byte."""

    MASK = [0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0, 1, 7,
            0, 0, 0, 0, 0, 2, 0, 1, 7, 0, 0, 0, 0, 0, 2, 0]

    def _orig_obfuscate(self, x):
        return bytes(b ^ self.MASK[i % len(self.MASK)] ^ 48 for i, b in enumerate(x.encode()))

    def _orig_varint(self, n):
        r = bytearray()
        while n:
            b = n & 0x7F
            n >>= 7
            r.append(b | (0x80 if n else 0))
        return bytes(r)

    def _orig_field(self, f, v):
        if type(v) == int:
            return self._orig_varint((f << 3) | 0) + self._orig_varint(v)
        b = v.encode() if type(v) == str else v
        return self._orig_varint((f << 3) | 2) + self._orig_varint(len(b)) + b

    def _orig_message(self, d):
        p = bytearray()
        for k in sorted(d):
            p.extend(self._orig_field(k, d[k]))
        return bytes(p)

    def test_obfuscate_matches_original(self):
        for sample in ["oid-123", "a", "GOP" + "9" * 30]:
            self.assertEqual(G._obfuscate_openid(sample), self._orig_obfuscate(sample))

    def test_varint_matches_original_for_nonzero(self):
        for n in [1, 127, 128, 300, 16384, 2 ** 31 - 1]:
            self.assertEqual(G._varint(n), self._orig_varint(n))

    def test_varint_zero_is_a_deliberate_fix(self):
        # The original returns b"" for 0, which makes the encoded field a bare
        # tag with no value byte, i.e. corrupt protobuf.
        self.assertEqual(self._orig_varint(0), b"")
        self.assertEqual(G._varint(0), b"\x00")

    def test_original_zero_field_is_malformed_and_ours_is_not(self):
        from Proto.compiled import MajorLogin_pb2 as ML
        # field 6 is a uint32 in MajorLogin.request.
        broken = self._orig_field(6, 0)
        self.assertEqual(broken.hex(), "30")
        with self.assertRaises(Exception):
            ML.request().ParseFromString(broken)
        msg = ML.request()
        msg.ParseFromString(G._encode_field(6, 0))
        self.assertEqual(msg.platid, 0)

    def test_field_matches_original(self):
        self.assertEqual(G._encode_field(1, "hi"), self._orig_field(1, "hi"))
        self.assertEqual(G._encode_field(5, 102000007), self._orig_field(5, 102000007))
        self.assertEqual(G._encode_field(14, b"\x01\x02"),
                         self._orig_field(14, b"\x01\x02"))

    def test_message_matches_original(self):
        fields = {1: "nick", 2: "tok", 3: "oid", 5: 102000007, 6: 4, 7: 1,
                  13: 1, 14: b"\x05\x06\x07", 15: "IND", 16: 1}
        self.assertEqual(G._encode_message(fields), self._orig_message(fields))

    def test_aes_encrypt_matches_original(self):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        payload = G._encode_message({1: "n", 15: "IND", 16: 1})
        expected = AES.new(G.AES_KEY, AES.MODE_CBC, G.AES_IV).encrypt(
            pad(payload, 16)).hex()
        self.assertEqual(G._aes_encrypt_hex(payload.hex()), expected)


def _live_config_present():
    return os.path.exists(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "Configuration", "AccountConfiguration.json"))


class ConfigIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(_live_config_present(), "needs Configuration/AccountConfiguration.json")
    def test_load_accounts_reads_live_config(self):
        from Utilities.until import load_accounts
        accounts = load_accounts()
        self.assertIn("IND", accounts)
        self.assertIn("uid", accounts["IND"])
        self.assertIn("password", accounts["IND"])

    @unittest.skipUnless(_live_config_present(), "needs Configuration/AccountConfiguration.json")
    def test_live_config_was_not_modified_by_import(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "Configuration", "AccountConfiguration.json")
        with open(path) as handle:
            before = handle.read()
        import importlib
        importlib.reload(G)
        with open(path) as handle:
            self.assertEqual(handle.read(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class WireValidationTests(unittest.TestCase):
    """_validate_wire_message must reject malformed payloads before they are sent."""

    def test_accepts_a_well_formed_message(self):
        payload = G._encode_message({1: "nick", 5: 102000007, 15: "IND", 16: 1})
        self.assertTrue(G._validate_wire_message(payload))

    def test_rejects_a_bare_tag_with_no_value(self):
        # This is exactly what the original ev(0) produced for a zero field.
        self.assertEqual(G._orig_bare_tag(6), b"\x30")
        with self.assertRaises(ValueError):
            G._validate_wire_message(b"\x30")

    def test_rejects_truncated_varint(self):
        with self.assertRaises(ValueError):
            G._validate_wire_message(b"\x08\x80")

    def test_rejects_length_running_past_the_end(self):
        with self.assertRaises(ValueError):
            G._validate_wire_message(b"\x0a\x40abc")

    def test_rejects_field_number_zero(self):
        with self.assertRaises(ValueError):
            G._validate_wire_message(b"\x00\x01")

    def test_accepts_empty(self):
        self.assertTrue(G._validate_wire_message(b""))


class FailureClassificationTests(unittest.TestCase):
    """Every failure mode must map to a distinct, stable category."""

    def test_validate_stage_is_invalid_input(self):
        self.assertEqual(G.classify_failure("validate", None, ""), "invalid_input")

    def test_serialize_stage_is_serialization_error(self):
        self.assertEqual(G.classify_failure("serialize", None, ""), "serialization_error")

    def test_status_mapping(self):
        cases = {404: "endpoint_not_found", 400: "bad_request",
                 401: "auth_rejected", 403: "auth_rejected",
                 500: "server_error", 502: "server_error",
                 418: "upstream_error", 429: "upstream_error"}
        for status, expected in cases.items():
            self.assertEqual(G.classify_failure("register", status, ""), expected,
                             f"status {status}")

    def test_live_404_is_endpoint_not_found(self):
        res = G.register("IND", session=FakeSession(
            [FakeResponse(404, None, '{"code":1005,"error":"error_not_found"}')]))
        self.assertFalse(res["ok"])
        self.assertEqual(res["category"], "endpoint_not_found")
        self.assertEqual(res["status"], 404)

    def test_live_400_is_bad_request(self):
        res = G.register("IND", session=FakeSession(
            [FakeResponse(400, None, '{"code":1002,"error":"error_params"}')]))
        self.assertEqual(res["category"], "bad_request")

    def test_timeout_and_connection_error_are_distinguished(self):
        import requests
        t = G.register("IND", session=FakeSession([requests.Timeout("slow")]))
        c = G.register("IND", session=FakeSession([requests.ConnectionError("down")]))
        self.assertEqual(t["category"], "network_timeout")
        self.assertEqual(c["category"], "network_error")

    def test_every_result_carries_a_category(self):
        # success
        ok = G.register("IND", session=FakeSession(ok_responses()))
        self.assertEqual(ok["category"], "ok")
        # each failure path
        for responses in ([FakeResponse(403, None, "x")],
                          [FakeResponse(200, {})],
                          [FakeResponse(200, {"uid": 1}), FakeResponse(400, None, "x")],
                          ok_responses()[:2] + [FakeResponse(503, None, "x")]):
            self.assertIn("category", G.register("IND", session=FakeSession(responses)))

    def test_serialization_failure_is_classified(self):
        """If the hand-built payload were malformed, it must not be sent."""
        sent = []
        session = FakeSession(ok_responses())
        original = G._encode_message
        try:
            G._encode_message = lambda fields: b"\x30"   # bare tag: malformed
            res = G.register("IND", session=session)
        finally:
            G._encode_message = original
        self.assertFalse(res["ok"])
        self.assertEqual(res["stage"], "serialize")
        self.assertEqual(res["category"], "serialization_error")
        # only steps 1 and 2 went out; the bad payload was never posted
        self.assertEqual(len(session.calls), 2)


class GenerateNicknameTests(unittest.TestCase):
    """The /GenerateNickname response is plain protobuf: field 1 = nickname."""

    def test_decodes_the_live_response_shape(self):
        # Exact bytes captured live: b'\n\x0cOmega5w4e0V4'
        self.assertEqual(A.decode_generate_nickname_response(b"\x0a\x0cOmega5w4e0V4"),
                         {"nickname": "Omega5w4e0V4"})

    def test_rejects_empty_body(self):
        with self.assertRaises(A.MajorLoginError):
            A.decode_generate_nickname_response(b"")

    def test_rejects_body_without_nickname(self):
        with self.assertRaises(A.MajorLoginError):
            A.decode_generate_nickname_response(b"\x08\x01")

    def test_rejects_non_string_nickname(self):
        with self.assertRaises(A.MajorLoginError):
            A.decode_generate_nickname_response(b"\x08\x2a")

    def test_url_is_the_apk_rpc_name(self):
        self.assertTrue(A.GENERATE_NICKNAME_URL.endswith("/GenerateNickname"))
