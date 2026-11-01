"""Defect: importing the generator ran 13 live registrations and overwrote the
live account config.

Root cause: the registration loop and the file write were at module level.
Fix: Additional/GenerateAccounts.py:register/_write_accounts/main, with the
write guarded by `if __name__ == "__main__"`.
"""
import hashlib
import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Additional import GenerateAccounts as G

CONFIG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "Configuration", "AccountConfiguration.json")


class NoMainGuardTests(unittest.TestCase):
    def test_module_has_a_main_guard(self):
        with open(os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "Additional", "GenerateAccounts.py")) as handle:
            source = handle.read()
        self.assertIn('if __name__ == "__main__":', source)

    def test_no_module_level_registration_loop(self):
        with open(os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "Additional", "GenerateAccounts.py")) as handle:
            source = handle.read()
        # The old code called register(r) in a module-level comprehension.
        for line in source.splitlines():
            if line.startswith(" ") or line.startswith("\t") or line.startswith("#"):
                continue
            self.assertNotIn("register(r)", line)

    @unittest.skipUnless(os.path.exists(CONFIG), "needs Configuration/AccountConfiguration.json")
    def test_reimport_does_not_modify_the_live_config(self):
        with open(CONFIG, "rb") as handle:
            before = hashlib.sha256(handle.read()).hexdigest()
        importlib.reload(G)
        with open(CONFIG, "rb") as handle:
            after = hashlib.sha256(handle.read()).hexdigest()
        self.assertEqual(before, after)

    def test_default_output_is_not_the_live_config(self):
        self.assertNotEqual(os.path.basename(G.DEFAULT_OUTPUT),
                            "AccountConfiguration.json")
