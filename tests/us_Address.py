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
import ipaddress
from policyanalyzer import Address


# Assuming the ANY constant is defined somewhere
# the_globals = globals()
# ANY = "ANY"
# the_globals["ANY"] = ANY


# Unit tests
class TestAddress(unittest.TestCase):
    def test_valid_address(self):
        # Test a valid IPv4 address with a subnet mask
        result = Address.get_address("192.168.1.1/24")
        self.assertEqual(result, ipaddress.ip_network("192.168.1.0/24"))

    def test_any_address(self):
        # Test the 'ANY' constant
        result = Address.get_address("ANY")
        self.assertEqual(result, ipaddress.ip_network("0.0.0.0/0"))

        # Test 'any' in lowercase (case insensitive check)
        result = Address.get_address("any")
        self.assertEqual(result, ipaddress.ip_network("0.0.0.0/0"))

    def test_invalid_address(self):
        # Test an invalid address and check if it raises a ValueError
        with self.assertRaises(ValueError):
            Address.get_address("45.2.3.1.3")

    def test_ip_without_mask(self):
        # Test IP address without subnet mask (assumes default /32)
        result = Address.get_address("192.168.1.1")
        self.assertEqual(result, ipaddress.ip_network("192.168.1.1/32"))

    def test_address_in_subnet(self):
        # Test if an address is within a subnet
        subnet = ipaddress.ip_network("192.168.1.0/24")
        address = ipaddress.ip_address("192.168.1.10")
        self.assertTrue(address in subnet)

    def test_address_not_in_subnet(self):
        # Test if an address is not within a subnet
        subnet = ipaddress.ip_network("192.168.1.0/24")
        address = ipaddress.ip_address("192.168.2.10")
        self.assertFalse(address in subnet)


if __name__ == "__main__":
    unittest.main()
