import unittest

from recursive_json_search import json_search
from test_data import data, key1, key2


class json_search_test(unittest.TestCase):

    # ---------- Baseline functional tests ----------

    def test_search_found(self):
        """FR-01: an authorized role gets every value stored under an existing key."""
        self.assertEqual(
            json_search(key1, data, role="admin"),
            ["Network Device 10.10.20.82 Is Unreachable From Controller"],
        )

    def test_search_not_found(self):
        """FR-02: a key that does not exist in the data returns an empty list."""
        self.assertEqual(json_search(key2, data, role="admin"), [])

    def test_is_a_list(self):
        """The function always returns a list, whether the key is found or not."""
        self.assertIsInstance(json_search(key1, data, role="admin"), list)
        self.assertIsInstance(json_search(key2, data, role="admin"), list)

    # ---------- Security tests (policy.py role permissions) ----------

    def test_sr01_allowed_roles_get_values(self):
        """SR-01: roles listed in POLICY[key] receive the field's value."""
        self.assertEqual(json_search("apiKey", data, role="admin"),
                         ["SNMP-COMMUNITY-STRING-7f3a9c"])
        self.assertEqual(json_search("managementIpAddress", data, role="operator"),
                         ["10.10.20.21"])
        self.assertEqual(json_search("issueSummary", data, role="viewer"),
                         ["Network Device 10.10.20.82 Is Unreachable From Controller"])

    def test_sr01_unauthorized_roles_denied(self):
        """SR-01 (T1, T2): roles not listed in POLICY[key] get [] for that key."""
        self.assertEqual(json_search("apiKey", data, role="operator"), [])
        self.assertEqual(json_search("apiKey", data, role="viewer"), [])
        self.assertEqual(json_search("managementIpAddress", data, role="viewer"), [])

    def test_sr02_keys_outside_policy_denied(self):
        """SR-02 (T3): keys not defined in POLICY are denied for every role."""
        self.assertEqual(json_search("serialNumber", data, role="viewer"), [])
        self.assertEqual(json_search("macAddress", data, role="operator"), [])
        self.assertEqual(json_search("XY&^$#*@!1234%^&", data, role="admin"), [])

    def test_sr03_invalid_roles_denied(self):
        """SR-03 (T4, T5): missing, malformed or wrong-type roles cannot read apiKey."""

        class AlwaysEqual:
            def __eq__(self, other):
                return True

            def __hash__(self):
                return hash("admin")

        self.assertEqual(json_search("apiKey", data), [])
        for role in (None, "", "Admin", "ADMIN", " admin", "admin ", "admin\x00",
                     "superuser", "root", ["admin"], {"admin"}, AlwaysEqual()):
            with self.subTest(role=role):
                self.assertEqual(json_search("apiKey", data, role=role), [])


if __name__ == "__main__":
    unittest.main()
