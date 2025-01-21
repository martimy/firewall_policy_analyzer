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
from policyanalyzer import Interface


class TestInterface(unittest.TestCase):
    def test_get_interface(self):
        # Test creating an interface using the class method
        interface = Interface.get_interface("eth0")
        self.assertEqual(interface.interface, "ETH0")

    def test_equality(self):
        # Test equality between interfaces
        interface1 = Interface.get_interface("eth0")
        interface2 = Interface.get_interface("ETH0")
        self.assertEqual(interface1, interface2)

    def test_repr(self):
        # Test string representation of an interface
        interface = Interface.get_interface("eth0")
        self.assertEqual(repr(interface), "ETH0")

    def test_superset_of(self):
        # Test superset_of method
        any_interface = Interface.get_interface("ANY")
        specific_interface = Interface.get_interface("eth0")
        self.assertTrue(any_interface.superset_of(specific_interface))
        self.assertFalse(specific_interface.superset_of(any_interface))

    def test_subset_of(self):
        # Test subset_of method
        any_interface = Interface.get_interface("ANY")
        specific_interface = Interface.get_interface("eth0")
        self.assertTrue(specific_interface.subset_of(any_interface))
        self.assertFalse(any_interface.subset_of(specific_interface))

    def test_invalid_interface(self):
        # Positive tests
        self.assertEqual(Interface.get_interface("eth0").interface, "ETH0")
        self.assertEqual(Interface.get_interface("eth-1").interface, "ETH-1")
        self.assertEqual(Interface.get_interface("eth_2").interface, "ETH_2")

        # Negative tests
        with self.assertRaises(ValueError):
            Interface.get_interface(45)
        with self.assertRaises(ValueError):
            Interface.get_interface("1eth")  # Starts with a digit
        with self.assertRaises(ValueError):
            Interface.get_interface("eth$3")  # Contains special character $
        with self.assertRaises(ValueError):
            Interface.get_interface("eth 3")  # Contains a space
        with self.assertRaises(ValueError):
            Interface.get_interface("")  # Empty string
        with self.assertRaises(ValueError):
            Interface.get_interface(None)  # None type
        with self.assertRaises(ValueError):
            Interface.get_interface("eth@name")  # Contains invalid special character @


if __name__ == "__main__":
    unittest.main()
