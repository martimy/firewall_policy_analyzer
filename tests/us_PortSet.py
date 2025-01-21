# -*- coding: utf-8 -*-

"""
Copyright 2025 Maen Artimy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import unittest

# from parsing import parse_ports_string, protocols_to_numbers
from policyanalyzer import PortSet


class TestPortSet(unittest.TestCase):
    def setUp(self):
        self.port_http = PortSet({80})
        self.port_https = PortSet({443})
        self.port_http_https = PortSet({80, 443})
        self.port_any = PortSet({0})

    def test_initialization(self):
        self.assertEqual(self.port_http.port_set, {80})
        self.assertEqual(self.port_https.port_set, {443})
        self.assertEqual(self.port_any.port_set, {0})

    def test_equality(self):
        self.assertEqual(self.port_http, PortSet({80}))
        self.assertNotEqual(self.port_http, self.port_https)
        self.assertNotEqual(self.port_any, self.port_http)

    def test_repr(self):
        self.assertEqual(repr(self.port_http), "80")
        self.assertEqual(repr(self.port_https), "443")
        self.assertEqual(repr(self.port_http_https), "{80, 443}")
        self.assertEqual(repr(self.port_any), "ANY")

    def test_superset_of(self):
        self.assertTrue(self.port_http_https.superset_of(self.port_http))
        self.assertFalse(self.port_http.superset_of(self.port_http_https))
        self.assertTrue(self.port_any.superset_of(self.port_http))
        self.assertFalse(self.port_http.superset_of(self.port_any))

    # def test_strict_superset_of(self):
    #     self.assertTrue(self.port_http_https.strict_superset_of(self.port_http))
    #     self.assertTrue(self.port_any.strict_superset_of(self.port_http_https))
    #     self.assertFalse(self.port_http.strict_superset_of(self.port_http))
    #     self.assertFalse(self.port_any.strict_superset_of(self.port_any))

    def test_subset_of(self):
        self.assertTrue(self.port_http.subset_of(self.port_http_https))
        self.assertFalse(self.port_http_https.subset_of(self.port_http))
        self.assertFalse(self.port_any.subset_of(self.port_http))
        self.assertTrue(self.port_http.subset_of(self.port_any))

    # def test_strict_subset_of(self):
    #     self.assertTrue(self.port_http.strict_subset_of(self.port_http_https))
    #     self.assertTrue(self.port_http_https.strict_subset_of(self.port_any))
    #     self.assertFalse(self.port_http.strict_subset_of(self.port_http))
    #     self.assertFalse(self.port_any.strict_subset_of(self.port_any))

    def test_get_port_any(self):
        port_set = PortSet.get_port("ANY")
        self.assertEqual(port_set, self.port_any)

    def test_get_port_single(self):
        port_set = PortSet.get_port("HTTP")
        self.assertEqual(port_set, self.port_http)

    def test_get_port_multiple(self):
        port_set = PortSet.get_port("HTTP, HTTPS")
        self.assertEqual(port_set, self.port_http_https)

    def test_get_port_invalid(self):
        with self.assertRaises(ValueError):
            # Assume ValueError is raised for invalid input
            PortSet.get_port("-2, 50, 70")


# Run the tests
if __name__ == "__main__":
    unittest.main()
