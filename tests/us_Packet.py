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
from policyanalyzer import Packet, Policy
from policyanalyzer import Interface, Protocol, Address
from policyanalyzer import PortSet, Action

# from definitions import RField #, RRule
from unittest.mock import MagicMock

# Mock the dependencies
# Interface = MagicMock()
# Protocol = MagicMock()
# Address = MagicMock()
# PortSet = MagicMock()
# Action = MagicMock()
# RField = MagicMock()
# RRule = MagicMock()

compare_two_fields = MagicMock()
compare_two_addresses = MagicMock()


class TestPacket(unittest.TestCase):
    def setUp(self):
        self.interface = Interface.get_interface("eth0")
        self.protocol = Protocol.get_protocol("TCP")
        self.saddress = Address.get_address("192.168.1.1")
        self.sport = PortSet.get_port("12345")
        self.daddress = Address.get_address("192.168.1.2")
        self.dport = PortSet.get_port("80")

    def test_packet_initialization(self):
        packet = Packet(
            "TCP", "192.168.1.1", "12345", "192.168.1.2", "80", interface="eth0"
        )
        self.assertEqual(packet.fields["interface"], self.interface)
        self.assertEqual(packet.fields["protocol"], self.protocol)
        self.assertEqual(packet.fields["src"], self.saddress)
        self.assertEqual(packet.fields["sport"], self.sport)
        self.assertEqual(packet.fields["dst"], self.daddress)
        self.assertEqual(packet.fields["dport"], self.dport)

    def test_packet_repr(self):
        packet = Packet(
            "TCP", "192.168.1.1", "12345", "192.168.1.2", "80", interface="eth0"
        )
        expected_repr = "ETH0,TCP,192.168.1.1/32,12345,192.168.1.2/32,80"
        self.assertEqual(repr(packet), expected_repr)


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.interface = Interface.get_interface("eth0")
        self.protocol = Protocol.get_protocol("TCP")
        self.saddress = Address.get_address("192.168.1.1")
        self.sport = PortSet.get_port("12345")
        self.daddress = Address.get_address("192.168.1.2")
        self.dport = PortSet.get_port("80")
        self.action = Action.get_action("Allow")

        self.policy = Policy(
            interface="eth0",
            protocol="TCP",
            src="192.168.1.1",
            s_port="12345",
            dst="192.168.1.2",
            d_port="80",
            action="ALLOW",
        )

    def test_policy_initialization(self):
        self.assertEqual(self.policy.fields["interface"], self.interface)
        self.assertEqual(self.policy.fields["protocol"], self.protocol)
        self.assertEqual(self.policy.fields["src"], self.saddress)
        self.assertEqual(self.policy.fields["sport"], self.sport)
        self.assertEqual(self.policy.fields["dst"], self.daddress)
        self.assertEqual(self.policy.fields["dport"], self.dport)
        self.assertEqual(self.policy.action, self.action)

    def test_policy_repr(self):
        expected_repr = "ETH0,TCP,192.168.1.1/32,12345,192.168.1.2/32,80,ACCEPT"
        self.assertEqual(repr(self.policy), expected_repr)

    def test_compare_fields(self):
        other_policy = Policy(
            interface="eth0",
            protocol="TCP",
            src="192.168.1.1",
            s_port="12345",
            dst="192.168.1.2",
            d_port="80",
            action="ALLOW",
        )

        # compare_two_fields.side_effect = lambda x, y: RField.EQUAL if x == y else RField.UNEQUAL
        # compare_two_addresses.side_effect = lambda x, y: RField.EQUAL if x == y else RField.UNEQUAL

        # relations = self.policy.compare_fields(other_policy)
        # self.assertTrue(all(r is RField.EQUAL for r in relations))

    def test_is_match(self):
        packet = Packet(
            "TCP", "192.168.1.1", "12345", "192.168.1.2", "80", interface="eth0"
        )
        # compare_two_fields.side_effect = lambda x, y: RField.EQUAL if x == y else RField.UNEQUAL
        # compare_two_addresses.side_effect = lambda x, y: RField.EQUAL if x == y else RField.UNEQUAL

        self.assertTrue(self.policy.is_match(packet))


if __name__ == "__main__":
    unittest.main()
