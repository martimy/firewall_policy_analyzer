# -*- coding: utf-8 -*-

"""
Copyright 2021-2022 Maen Artimy

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


import ipaddress
from definitions import RRule, RField, Anomaly


class Port():
    """
    A TCP/UDP Port
    """

    def __init__(self, port):
        # Do not use this construtor directly, use get_port() instead
        self.port = port

    def __eq__(self, other):
        return self.port == other.port

    def __repr__(self):
        return str(self.port)

    def superset_of(self, other):
        return self.port == 0 and other.port != 0

    def subset_of(self, other):
        return self.port != 0 and other.port == 0

    @classmethod
    def get_port(cls, port):
        if isinstance(port, str) and port.strip().upper() == "ANY":
            return cls(0)
        return cls(int(port))


class Protocol():
    """
    A Protcol
    """

    _protocols = ["IP", "ICMP", "TCP", "UDP"]

    def __init__(self, protocol):
        # Do not use this construtor directly, use get_protocol() instead
        self.protocol = protocol.upper()

    def __eq__(self, other):
        return self.protocol == other.protocol

    def __repr__(self):
        return self.protocol

    def superset_of(self, other):
        return self.protocol == "IP" and other.protocol in Protocol._protocols[1:]

    def subset_of(self, other):
        return self.protocol in Protocol._protocols[1:] and other.protocol == "IP"

    @classmethod
    def get_protocol(cls, protocol):
        if protocol.upper() not in Protocol._protocols:
            raise ValueError("not a recognized protocol")
        return cls(protocol)


class Address():
    """
    An IPv4 Address
    """

    @classmethod
    def get_address(cls, address):
        if address == 'any':
            address = '0.0.0.0/0'
        return ipaddress.ip_interface(address).network


def compare_fields(a, b):
    """
    get relation between two policy fields
    """
    relation = RField.UNEQUAL
    if a == b:
        relation = RField.EQUAL
    elif a.subset_of(b):
        relation = RField.SUBSET
    elif a.superset_of(b):
        relation = RField.SUPERSET
    return relation


def compare_addresses(a, b):
    """
    Get relation between two policy fields representing IP addresses
    """

    relation = RField.UNEQUAL
    if a == b:
        relation = RField.EQUAL
    elif a.subnet_of(b):
        relation = RField.SUBSET
    elif a.supernet_of(b):
        relation = RField.SUPERSET
    return relation


class Packet():
    """
    Packet header information
    """

    def __init__(self, protocol, src, s_port, dst, d_port):
        self.fields = {
            'protocol': Protocol.get_protocol(protocol.strip()),
            'src': Address.get_address(src.strip()),
            'sport': Port.get_port(s_port.strip()),
            'dst': Address.get_address(dst.strip()),
            'dport': Port.get_port(d_port),
        }

    def __repr__(self):
        return ','.join(map(str, self.fields.values()))


class Policy(Packet):
    """
    Firewall Policy
    """

    def __init__(self, protocol, src, s_port, dst, d_port, action):
        super().__init__(protocol, src, s_port, dst, d_port)
        self.action = action

    def compare_fields(self, other):
        # compare fields with another policy or packet
        return [
            compare_fields(self.fields['protocol'], other.fields['protocol']),
            compare_addresses(self.fields['src'], other.fields['src']),
            compare_fields(self.fields['sport'], other.fields['sport']),
            compare_addresses(self.fields['dst'], other.fields['dst']),
            compare_fields(self.fields['dport'], other.fields['dport'])
        ]

    def compare_actions(self, other):
        return self.action == other.action

    def get_rule_relation(self, other):
        """
        The fields list include comparsions between corrosponding fields
        in two rules.
        The method returns the resulting relationship between two rule.
        """

        fields = self.compare_fields(other)
        relation = None
        if all(f is RField.UNEQUAL for f in fields):
            relation = RRule.CD
        elif all(f is RField.EQUAL for f in fields):
            relation = RRule.EM
        elif all(f in [RField.SUPERSET, RField.EQUAL] for f in fields):
            relation = RRule.IMP
        elif all(f in [RField.SUBSET, RField.EQUAL] for f in fields):
            relation = RRule.IMB
        elif any(f is RField.UNEQUAL for f in fields) \
                and any(f is not RField.UNEQUAL for f in fields):
            relation = RRule.PD
        else:
            relation = RRule.CC
        return relation

    def is_match(self, packet):
        # the packet matches this policy if all fields in policy are
        # equal or supersets of the packet fields
        return all(f in [RField.SUPERSET, RField.EQUAL]
                   for f in self.compare_fields(packet))

    def __repr__(self):
        return ','.join(map(str, self.fields.values())) + ',' + self.action


class PolicyAnalyzer():
    """
    Firewall Policy Analyzer
    """

    anamoly = {
        (RRule.IMB, False): Anomaly.GEN,
        (RRule.IMP, False): Anomaly.SHD,
        (RRule.CC, False): Anomaly.COR,
        (RRule.IMP, True): Anomaly.RXD,
        (RRule.EM, True): Anomaly.RXD,
        (RRule.IMB, True): Anomaly.RUD
    }

    def __init__(self, policies):
        self.policies = policies

    def _get_anamoly(self, rule_relation, same_action):
        return self.anamoly.get((rule_relation, same_action), Anomaly.AOK)

    def get_relations(self):
        # compare each policy with the previous ones
        rule_relations = {}
        for y, y_policy in enumerate(self.policies):
            rule_relations[y] = [(x, x_policy.get_rule_relation(y_policy))
                                 for x, x_policy in enumerate(self.policies[0:y])]
        return rule_relations

    def get_a_relations(self):
        # compare each policy action with the previous ones
        rule_a_relations = {}
        for y, y_policy in enumerate(self.policies):
            rule_a_relations[y] = [x_policy.compare_actions(y_policy)
                                   for x_policy in self.policies[0:y]]
        return rule_a_relations

    def get_anomalies(self):
        anomalies = {}
        rule_relations = self.get_relations()
        a_relations = self.get_a_relations()

        for ry, ry_relations in rule_relations.items():
            for rx, relation in ry_relations:
                anamoly = self._get_anamoly(relation, a_relations[ry][rx])
                if anamoly is Anomaly.RUD:
                    # check the rules in between for additional conditions
                    for rz in range(rx+1, ry):
                        if any(a == rx and not a_relations[rz][rx]
                               and b in [RRule.CC, RRule.IMB]
                                   for a, b in rule_relations[rz]):
                            anamoly = Anomaly.AOK
                            break
                if anamoly is not Anomaly.AOK:
                    anomalies.setdefault(ry, []).append((rx, anamoly))
        return anomalies

    def get_first_match(self, packet):

        for i, policy in enumerate(self.policies):
            if policy.is_match(packet):
                return i, policy
        return None
