# Fill the Python code in this file
import unittest
from recursive_json_search import *
from test_data import *


class json_search_test(unittest.TestCase):

    def test_search_found(self):
        self.assertTrue([] != json_search(key1, data))

    def test_search_not_found(self):
        self.assertTrue([] == json_search(key2, data))

    def test_is_a_list(self):
        self.assertIsInstance(json_search(key1, data), list)
    # Security tests
    def test_viewer_cannot_read_api_key(self):
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_operator_cannot_read_api_key(self):
        result = json_search("apiKey", data, role="operator")
        self.assertEqual([], result)

    def test_viewer_cannot_read_management_ip(self):
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual([], result)

    def test_admin_can_read_api_key(self):
        result = json_search("apiKey", data, role="admin")
        self.assertNotEqual([], result)




if __name__ == '__main__':
    unittest.main()
