"""Mocked integration tests for GET /get_player_personal_show.

Target is the PLAYER uid 11111111 (eight digits), which is distinct from the
guest-account uid used for authentication. No network is used: the account
lookup, token grant, major login and the player request are all patched.
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module
from Api import Account, InGame
from Proto.compiled import PlayerPersonalShow_pb2

PLAYER_UID = "11111111"
REGION = "IND"

# AccountConfiguration.json holds live credentials and is gitignored, so a
# fresh clone or zip extract does not have it. The tests below drive the real
# account through the routes, so they need a configured account. Skip rather
# than fail when it is absent: the tests are meaningful, the environment simply
# does not supply the credential.
_HAS_LIVE_ACCOUNT = bool(app_module.accounts)


def _grant():
    return {"access_token": "garena-token", "open_id": "open-id-1"}


def _session():
    return {"token": "game-session-token", "serverUrl": "https://client.ind.freefiremobile.com"}


def _restricted():
    return {"_framed": True, "_prefixLen": 64, "_authenticated": False,
            "_restricted": True, "_restrictionReason": "Exploiting loopholes",
            "queueInfo": {"allow": True, "needWaitSecs": 1781577563,
                          "reason": "Exploiting loopholes"}}


@unittest.skipUnless(_HAS_LIVE_ACCOUNT, "needs Configuration/AccountConfiguration.json")
class UidParameterTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def test_missing_uid_is_rejected(self):
        r = self.client.get("/get_player_personal_show?server=IND")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["code"], "MISSING_UID")

    def test_non_numeric_uid_is_rejected(self):
        r = self.client.get("/get_player_personal_show?server=IND&uid=abcdefgh")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["code"], "INVALID_UID_FORMAT")

    def test_zero_uid_is_rejected(self):
        r = self.client.get("/get_player_personal_show?server=IND&uid=0")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["code"], "INVALID_UID_RANGE")

    def test_unknown_server_is_rejected(self):
        r = self.client.get("/get_player_personal_show?server=NOPE&uid=11111111")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["code"], "SERVER_NOT_FOUND")

    def test_target_uid_is_accepted_as_a_player_uid(self):
        """11111111 must pass validation: it is a player uid, not an account uid."""
        self.assertEqual(int(PLAYER_UID), 11111111)
        self.assertEqual(len(PLAYER_UID), 8)
        self.assertIn(REGION, app_module.accounts)
        # It must not collide with any configured guest-account uid.
        account_uids = {str(a["uid"]) for a in app_module.accounts.values()}
        self.assertNotIn(PLAYER_UID, account_uids)


@unittest.skipUnless(_HAS_LIVE_ACCOUNT, "needs Configuration/AccountConfiguration.json")
class AuthStageTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        self.url = f"/get_player_personal_show?server={REGION}&uid={PLAYER_UID}"

    def test_token_grant_failure_returns_401(self):
        with mock.patch.object(app_module, "get_garena_token", return_value=None):
            r = self.client.get(self.url)
        self.assertEqual(r.status_code, 401)

    def test_major_login_restriction_is_surfaced(self):
        with mock.patch.object(app_module, "get_garena_token", return_value=_grant()), \
             mock.patch.object(app_module, "get_major_login", return_value=_restricted()):
            r = self.client.get(self.url)
        self.assertEqual(r.status_code, 401)
        body = r.get_json()
        self.assertEqual(body["code"], "MAJOR_LOGIN_FAILED")
        self.assertIn("Exploiting loopholes", body["message"])

    def test_major_login_without_token_is_401(self):
        with mock.patch.object(app_module, "get_garena_token", return_value=_grant()), \
             mock.patch.object(app_module, "get_major_login", return_value={"_authenticated": False}):
            r = self.client.get(self.url)
        self.assertEqual(r.status_code, 401)


@unittest.skipUnless(_HAS_LIVE_ACCOUNT, "needs Configuration/AccountConfiguration.json")
class SuccessPathTests(unittest.TestCase):
    """A successful lookup must return real decoded fields, not a fixture."""

    PLAYER = {"accountId": 11111111, "nickname": "TestPlayer",
              "level": 42, "region": "IND"}

    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        self.url = f"/get_player_personal_show?server={REGION}&uid={PLAYER_UID}"

    def test_successful_lookup_returns_player_data(self):
        with mock.patch.object(app_module, "get_garena_token", return_value=_grant()), \
             mock.patch.object(app_module, "get_major_login", return_value=_session()), \
             mock.patch.object(app_module, "get_player_personal_show", return_value=self.PLAYER) as p:
            r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["accountId"], 11111111)
        # the route must pass the session token and the player uid through
        args, _ = p.call_args
        self.assertIn("game-session-token", args)

    def test_upstream_failure_returns_error_not_success(self):
        with mock.patch.object(app_module, "get_garena_token", return_value=_grant()), \
             mock.patch.object(app_module, "get_major_login", return_value=_session()), \
             mock.patch.object(app_module, "get_player_personal_show", return_value=None):
            r = self.client.get(self.url)
        self.assertNotEqual(r.status_code, 200)
        self.assertIn("error", r.get_json())


class InGameFunctionTests(unittest.TestCase):
    """Exercise the real InGame.get_player_personal_show request construction."""

    def _fake_response(self, payload, status=200):
        resp = mock.Mock()
        resp.status_code = status
        resp.content = payload
        resp.text = ""
        resp.raise_for_status = mock.Mock()
        return resp

    def test_request_is_encrypted_and_targets_the_right_path(self):
        msg = PlayerPersonalShow_pb2.response()
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            return self._fake_response(msg.SerializeToString())

        with mock.patch.object(InGame.requests, "post", side_effect=fake_post):
            InGame.get_player_personal_show(
                "https://client.ind.freefiremobile.com", "tok", 11111111)

        self.assertTrue(captured["url"].endswith("/GetPlayerPersonalShow"))
        self.assertEqual(len(captured["data"]) % 16, 0)          # AES-CBC
        self.assertIn("Bearer tok", captured["headers"]["Authorization"])
        self.assertNotIn("Content-Length", captured["headers"])  # not hardcoded

    def test_upstream_500_returns_none(self):
        resp = mock.Mock()
        resp.status_code = 500
        resp.content = b"err"
        resp.text = "err"
        resp.raise_for_status = mock.Mock(side_effect=Exception("500"))
        with mock.patch.object(InGame.requests, "post", return_value=resp):
            self.assertIsNone(InGame.get_player_personal_show(
                "https://x", "tok", 11111111))

    def test_unparseable_body_returns_none(self):
        with mock.patch.object(InGame.requests, "post",
                               return_value=self._fake_response(b"\xff" * 64)):
            self.assertIsNone(InGame.get_player_personal_show(
                "https://x", "tok", 11111111))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ErrorSanitizationTests(unittest.TestCase):
    """Upstream error bodies can echo session tokens; they must not be printed raw."""

    def test_safe_error_text_truncates(self):
        resp = mock.Mock()
        resp.text = "x" * 5000
        out = InGame._safe_error_text(resp)
        self.assertLessEqual(len(out), 203)
        self.assertTrue(out.endswith("..."))

    def test_safe_error_text_handles_empty(self):
        resp = mock.Mock()
        resp.text = ""
        self.assertEqual(InGame._safe_error_text(resp), "<empty body>")

    def test_error_path_does_not_print_raw_body(self):
        token = "SECRET-SESSION-TOKEN-abcdef123456"
        resp = mock.Mock()
        resp.status_code = 403
        resp.content = b""
        resp.text = f'{{"error":"denied","token":"{token}"}}'
        resp.raise_for_status = mock.Mock(side_effect=Exception("403"))

        printed = []
        with mock.patch.object(InGame.requests, "post", return_value=resp), \
             mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(str(x) for x in a))):
            InGame.get_player_personal_show("https://x", "tok", 11111111)

        joined = " ".join(printed)
        self.assertNotIn(token, joined, "raw upstream body leaked a token to stdout")


@unittest.skipUnless(_HAS_LIVE_ACCOUNT, "needs Configuration/AccountConfiguration.json")
class EndToEndDecodingTests(unittest.TestCase):
    """End-to-end: real AES response bytes -> real protobuf decode -> route JSON.

    Nothing is stubbed inside InGame here. Only the HTTP transport is faked, so
    the encryption, protobuf and JSON paths are all the production ones. The
    response is built by the real schema, not a literal, so it is not a
    hand-written fixture.
    """

    def _response_payload(self, account_id, nickname, level):
        """Plaintext protobuf, matching how the API decodes this response.

        get_player_personal_show passes response.content straight to
        decode_protobuf with no decryption step, which is consistent with the
        plaintext protobuf tail observed in MajorLogin responses.
        """
        msg = PlayerPersonalShow_pb2.response()
        msg.basicinfo.accountid = account_id
        msg.basicinfo.nickname = nickname
        msg.basicinfo.level = level
        msg.basicinfo.region = "IND"
        msg.rankingleaderboardpos = 7
        return msg.SerializeToString()

    def _transport(self, payload, status=200):
        resp = mock.Mock()
        resp.status_code = status
        resp.content = payload
        resp.text = ""
        resp.raise_for_status = mock.Mock()
        return resp

    def test_real_response_decodes_to_player_fields(self):
        payload = self._response_payload(11111111, "PlayerOne", 42)
        with mock.patch.object(InGame.requests, "post",
                               return_value=self._transport(payload)):
            out = InGame.get_player_personal_show(
                "https://client.ind.freefiremobile.com", "tok", 11111111)
        self.assertIsNotNone(out)
        self.assertEqual(out["basicinfo"]["accountid"], "11111111")
        self.assertEqual(out["basicinfo"]["nickname"], "PlayerOne")
        self.assertEqual(out["basicinfo"]["level"], 42)
        self.assertEqual(out["basicinfo"]["region"], "IND")

    def test_full_route_returns_real_decoded_data(self):
        """Route -> InGame -> real decode, with only the transport faked."""
        payload = self._response_payload(11111111, "PlayerOne", 42)
        app_module.app.config["TESTING"] = True
        client = app_module.app.test_client()
        with mock.patch.object(app_module, "get_garena_token", return_value=_grant()), \
             mock.patch.object(app_module, "get_major_login", return_value=_session()), \
             mock.patch.object(InGame.requests, "post",
                               return_value=self._transport(payload)):
            r = client.get("/get_player_personal_show?server=IND&uid=11111111")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["basicinfo"]["accountid"], "11111111")
        self.assertEqual(body["basicinfo"]["nickname"], "PlayerOne")

    def test_the_request_uid_reaches_the_payload(self):
        """The uid under test must be the uid serialized into the request."""
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured["data"] = data
            return self._transport(self._response_payload(11111111, "P", 1))

        with mock.patch.object(InGame.requests, "post", side_effect=fake_post):
            InGame.get_player_personal_show("https://x", "tok", 11111111)

        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        from Configuration.AESConfiguration import MAIN_KEY, MAIN_IV
        raw = unpad(AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).decrypt(captured["data"]), 16)
        req = PlayerPersonalShow_pb2.request()
        req.ParseFromString(raw)
        self.assertEqual(req.accountId, 11111111)
        self.assertEqual(req.callSignSrc, 7)
