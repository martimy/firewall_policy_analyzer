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
from policyanalyzer import Protocol
from definitions import PROTOCOLS


class TestProtocol(unittest.TestCase):
    def test_get_protocol_valid(self):
        """Test if get_protocol correctly identifies valid protocols."""
        for proto in PROTOCOLS:
            protocol = Protocol.get_protocol(proto)
            self.assertEqual(repr(protocol), proto.upper())

    def test_get_protocol_invalid(self):
        """Test if get_protocol raises ValueError for invalid protocols."""
        with self.assertRaises(ValueError):
            Protocol.get_protocol("INVALID")

        with self.assertRaises(ValueError):
            Protocol.get_protocol(123)

        with self.assertRaises(ValueError):
            Protocol.get_protocol(None)

    def test_get_protocol_case_insensitivity(self):
        """Test if get_protocol is case-insensitive."""
        protocol = Protocol.get_protocol("tcp")
        self.assertEqual(repr(protocol), "TCP")

    def test_superset_of(self):
        """Test if superset_of identifies IP as a superset of other protocols."""
        ip_protocol = Protocol.get_protocol("IP")
        tcp_protocol = Protocol.get_protocol("TCP")
        self.assertTrue(ip_protocol.superset_of(tcp_protocol))

        icmp_protocol = Protocol.get_protocol("ICMP")
        self.assertTrue(ip_protocol.superset_of(icmp_protocol))

        other_ip_protocol = Protocol.get_protocol("IP")
        self.assertTrue(ip_protocol.superset_of(other_ip_protocol))

    def test_not_superset_of(self):
        """Test if superset_of correctly identifies non-IP protocols as not supersets."""
        tcp_protocol = Protocol.get_protocol("TCP")
        icmp_protocol = Protocol.get_protocol("ICMP")
        self.assertFalse(tcp_protocol.superset_of(icmp_protocol))

    def test_subset_of(self):
        """Test if subset_of identifies protocols as subsets of IP."""
        ip_protocol = Protocol.get_protocol("IP")
        tcp_protocol = Protocol.get_protocol("TCP")
        self.assertTrue(tcp_protocol.subset_of(ip_protocol))

        icmp_protocol = Protocol.get_protocol("ICMP")
        self.assertTrue(icmp_protocol.subset_of(ip_protocol))

        any_protocol = Protocol.get_protocol("ANY")
        tcp_protocol = Protocol.get_protocol("TCP")
        self.assertTrue(tcp_protocol.subset_of(any_protocol))

        icmp_protocol = Protocol.get_protocol("ICMP")
        self.assertTrue(icmp_protocol.subset_of(any_protocol))

    def test_not_subset_of(self):
        """Test if subset_of correctly identifies IP as not a subset of other protocols."""
        ip_protocol = Protocol.get_protocol("IP")
        tcp_protocol = Protocol.get_protocol("TCP")
        self.assertFalse(ip_protocol.subset_of(tcp_protocol))

    def test_equality(self):
        """Test if equality operator works correctly."""
        proto1 = Protocol.get_protocol("TCP")
        proto2 = Protocol.get_protocol("tcp")
        proto3 = Protocol.get_protocol("UDP")

        self.assertEqual(proto1, proto2)
        self.assertNotEqual(proto1, proto3)


if __name__ == "__main__":
    unittest.main()
