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
from policyanalyzer import Packet
from policyanalyzer import Interface, Protocol, Address
from policyanalyzer import PortSet


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


if __name__ == "__main__":
    unittest.main()
