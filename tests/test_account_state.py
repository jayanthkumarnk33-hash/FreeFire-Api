"""Regression tests for the account-state diagnostics.

get_account_state() calls the two Garena MSDK routes recovered from the shipped
APK (com.beetalk.sdk.A0 lines 222 and 256). These tests pin the interpretation
of their responses, which is what the /diagnose_account route reports.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Api import Account
from Api.Account import get_account_state


def _json_response(payload, status=200):
    return mock.Mock(status_code=status, json=mock.Mock(return_value=payload),
                     text=str(payload))


class AccountStateTests(unittest.TestCase):
    def test_valid_credential_without_platform_bound(self):
        # Exactly what a freshly registered guest returns: real account data,
        # and an empty bound-account list.
        responses = [
            _json_response({"uid": 8390089713, "open_id": "abc", "platform": 4,
                            "main_active_platform": 4}),
            _json_response({"bounded_accounts": [], "available_platforms": []}),
        ]
        with mock.patch.object(Account.requests, "get", side_effect=responses):
            state = get_account_state("token")

        self.assertTrue(state["credentialValid"])
        self.assertFalse(state["platformBound"])
        self.assertEqual(state["userInfo"]["uid"], 8390089713)
        self.assertEqual(state["errors"], [])

    def test_platform_bound_when_accounts_present(self):
        responses = [
            _json_response({"uid": 1, "open_id": "abc"}),
            _json_response({"bounded_accounts": [{"platform": 4}]}),
        ]
        with mock.patch.object(Account.requests, "get", side_effect=responses):
            state = get_account_state("token")

        self.assertTrue(state["platformBound"])

    def test_rejected_credential_is_not_valid(self):
        responses = [
            _json_response({"error": "invalid_token"}, status=401),
            _json_response({"error": "invalid_token"}, status=401),
        ]
        with mock.patch.object(Account.requests, "get", side_effect=responses):
            state = get_account_state("token")

        self.assertFalse(state["credentialValid"])
        self.assertFalse(state["platformBound"])
        self.assertEqual(len(state["errors"]), 2)

    def test_transport_error_is_recorded_not_raised(self):
        with mock.patch.object(Account.requests, "get",
                               side_effect=Account.requests.exceptions.ConnectionError()):
            state = get_account_state("token")

        self.assertFalse(state["credentialValid"])
        self.assertEqual(len(state["errors"]), 2)

    def test_sends_app_id_to_bind_route(self):
        responses = [
            _json_response({"uid": 1, "open_id": "a"}),
            _json_response({"bounded_accounts": []}),
        ]
        with mock.patch.object(Account.requests, "get", side_effect=responses) as get:
            get_account_state("token")

        bind_params = get.call_args_list[1].kwargs["params"]
        self.assertIn("app_id", bind_params)
        self.assertIn("access_token", bind_params)


if __name__ == "__main__":
    unittest.main()
