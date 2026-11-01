"""Defect: MajorLogin rejected with HTTP 400 "SignError1".

Root cause: only X-GA was sent. The edge signature check requires all three of
X-GA, X-GA-RV and X-GA-SV. Fix: Api/Account.py:get_major_login (header dict).
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Api import Account


class MajorLoginHeaderTests(unittest.TestCase):
    def _capture(self):
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured["headers"] = headers
            resp = mock.Mock()
            resp.status_code = 400
            resp.content = b"SignError1"
            resp.text = "SignError1"
            return resp

        with mock.patch.object(Account.requests, "post", side_effect=fake_post):
            try:
                Account.get_major_login("tok", "openid")
            except Account.MajorLoginError:
                pass
        return captured["headers"]

    def test_all_three_x_ga_headers_are_sent(self):
        headers = self._capture()
        for name in ("X-GA", "X-GA-RV", "X-GA-SV"):
            self.assertIn(name, headers, f"{name} missing -> HTTP 400 SignError1")
            self.assertTrue(headers[name], f"{name} is empty")

    def test_release_version_and_unity_version_are_sent(self):
        headers = self._capture()
        self.assertIn("ReleaseVersion", headers)
        self.assertIn("X-Unity-Version", headers)

    def test_body_is_binary_not_form_encoded(self):
        headers = self._capture()
        self.assertEqual(headers["Content-Type"], "application/octet-stream")
