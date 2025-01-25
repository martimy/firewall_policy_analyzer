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
from definitions import RField  # , RRule


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.interface = Interface.get_interface("eth0")
        self.protocol = Protocol.get_protocol("TCP")
        self.saddress = Address.get_address("192.168.1.0/24")
        self.sport = PortSet.get_port("12345")
        self.daddress = Address.get_address("192.168.2.2")
        self.dport = PortSet.get_port("80")
        self.action = Action.get_action("Allow")

        self.policy = Policy(
            interface="eth0",
            protocol="TCP",
            src="192.168.1.0/24",
            s_port="12345",
            dst="192.168.2.2",
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
        expected_repr = "ETH0,TCP,192.168.1.0/24,12345,192.168.2.2/32,80,ACCEPT"
        self.assertEqual(repr(self.policy), expected_repr)

    def test_is_match(self):
        packet = Packet(
            "TCP", "192.168.1.0/24", "12345", "192.168.2.2/32", "80", interface="eth0"
        )
        # compare_two_fields.side_effect = lambda x, y: RField.EQUAL if x == y else RField.UNEQUAL
        # compare_two_addresses.side_effect = lambda x, y: RField.EQUAL if x == y else RField.UNEQUAL

        self.assertTrue(self.policy.is_match(packet))

    def test_relations(self):
        def create_policy(interface, protocol, src, s_port, dst, d_port, action):
            return Policy(
                interface=interface,
                protocol=protocol,
                src=src,
                s_port=s_port,
                dst=dst,
                d_port=d_port,
                action=action,
            )

        # Compare the fields of the two rules
        test_cases = [
            {
                "policy": create_policy(
                    "eth0",
                    "TCP",
                    "192.168.1.0/24",
                    "12345",
                    "192.168.2.2",
                    "80",
                    "ALLOW",
                ),
                "expected": [RField.EQUAL] * 6,
            },
            {
                "policy": create_policy(
                    "eth1", "UDP", "192.168.2.2", "123", "192.168.1.3", "8000", "ALLOW"
                ),
                "expected": [RField.UNEQUAL] * 6,
            },
            {
                "policy": create_policy(
                    "eth0",
                    "IP",
                    "192.168.1.2",
                    "ANY",
                    "192.168.2.0/24",
                    "80, 8000",
                    "ALLOW",
                ),
                "expected": [
                    RField.EQUAL,
                    RField.STRICT_SUBSET,
                    RField.STRICT_SUPERSET,
                    RField.STRICT_SUBSET,
                    RField.STRICT_SUBSET,
                    RField.STRICT_SUBSET,
                ],
            },
        ]

        for test in test_cases:
            other = test["policy"]
            expected = test["expected"]
            relations = self.policy.compare_fields(other)
            self.assertTrue(relations == expected)


if __name__ == "__main__":
    unittest.main()
