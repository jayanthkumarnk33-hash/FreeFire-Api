"""Regression tests for the MajorLogin HTTP 404 "account_not_found" path.

A freshly created guest account holds a valid OAuth identity but has no game
profile yet. The login service answers MajorLogin with HTTP 404 and the JSON
body {"type": "account_not_found", ...}. The API must surface that as a
dedicated AccountNotFoundError / ACCOUNT_NOT_REGISTERED response rather than
reporting a transport failure or a generic 500.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Api import Account
from Api.Account import AccountNotFoundError, MajorLoginError, get_major_login


def _not_found():
    return mock.Mock(
        status_code=404,
        content=b'{"type": "account_not_found", "msg": "account not found", '
                b'"server_time":1793547142694}',
        text='{"type": "account_not_found", "msg": "account not found", '
             '"server_time":1793547142694}',
    )


def _other_404():
    return mock.Mock(status_code=404, content=b"nope", text="nope")


class AccountNotFoundTests(unittest.TestCase):
    def test_404_account_not_found_raises_dedicated_error(self):
        with mock.patch.object(Account.requests, "post", return_value=_not_found()):
            with self.assertRaises(AccountNotFoundError):
                get_major_login("logintoken", "openid")

    def test_account_not_found_is_a_major_login_error(self):
        # Callers that only catch MajorLoginError must still catch it.
        self.assertTrue(issubclass(AccountNotFoundError, MajorLoginError))

    def test_plain_404_is_not_treated_as_account_not_found(self):
        with mock.patch.object(Account.requests, "post", return_value=_other_404()):
            with self.assertRaises(MajorLoginError) as ctx:
                get_major_login("logintoken", "openid")
        self.assertNotIsInstance(ctx.exception, AccountNotFoundError)
        self.assertIn("404", str(ctx.exception))


class PlatformConstantTests(unittest.TestCase):
    def test_platform_value_sent_is_four(self):
        # APK evidence: MajorLogin request field 99 and
        # PlatformGuestBindReq.guest_platform_type both carry the platform id;
        # the OAuth token grant reports platform 4 for these accounts.
        self.assertEqual(Account.PLATFORM_ANDROID, "4")


if __name__ == "__main__":
    unittest.main()
