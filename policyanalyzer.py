# -*- coding: utf-8 -*-

"""
Copyright 2021-2025 Maen Artimy

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


import re
import ipaddress
from definitions import PORTS, PROTOCOLS, RRule, RField, Anomaly
from parsing import parse_ports_string, protocols_to_numbers

UniversalSet = {0}
ANY = "ANY"


class Action:
    """
    A Rule's action
    """

    _permit = ["PERMIT", "ALLOW", "ACCEPT", "PASS"]
    _deny = ["DENY", "REJECT", "DROP"]

    def __init__(self, action: bool):
        # Do not use this constructor directly, use get_port() instead
        self.action = action

    def __eq__(self, other):
        if isinstance(other, Action):
            return self.action == other.action
        return False

    def __repr__(self):
        return "ACCEPT" if self.action else "DENY"

    @classmethod
    def get_action(cls, action):
        if isinstance(action, str):
            if action.upper() in Action._permit:
                return cls(True)
            if action.upper() in Action._deny:
                return cls(False)
        raise ValueError(f"Invalid action '{action}'.")


class PortSet:
    """
    A TCP/UDP Port
    """

    def __init__(self, ports):
        # Do not use this constructor directly, use get_port() instead
        self.port_set = ports

    def __eq__(self, other):
        return self.port_set == other.port_set

    def __repr__(self):
        if self.port_set == UniversalSet:
            return ANY
        elif len(self.port_set) == 1:
            return str(next(iter(self.port_set)))
        return str(self.port_set)

    def superset_of(self, other):
        if self.port_set == UniversalSet:  # a Universal Set is a superset of any set
            return True
        if other.port_set == UniversalSet:
            return False
        return self.port_set.issuperset(other.port_set)

    def subset_of(self, other):
        if other.port_set == UniversalSet:
            return True
        if self.port_set == UniversalSet:
            return False
        return self.port_set.issubset(other.port_set)

    @classmethod
    def get_port(cls, ports_string):
        if isinstance(ports_string, str) and ports_string.strip().upper() == ANY:
            return cls(UniversalSet)  # represents a Universal Set
        else:
            a_set = parse_ports_string(ports_string)
            ports = protocols_to_numbers(a_set, PORTS)
        return cls(ports)


class Protocol:
    """
    A Protcol
    """

    def __init__(self, protocol):
        # Do not use this constructor directly, use get_protocol() instead
        self.protocol = protocol.upper()

    def __eq__(self, other):
        return self.protocol == other.protocol

    def __repr__(self):
        return self.protocol

    def superset_of(self, other):
        return self.protocol == "IP" and other.protocol in PROTOCOLS

    def subset_of(self, other):
        return self.protocol in PROTOCOLS and other.protocol == "IP"

    @classmethod
    def get_protocol(cls, protocol):
        if not isinstance(protocol, str):
            raise ValueError(f"Not a recognized protocol '{protocol}'")
        protocol = "IP" if protocol.upper() == ANY else protocol.upper()
        if protocol not in PROTOCOLS:
            raise ValueError(f"Not a recognized protocol '{protocol}'")
        return cls(protocol)


class Address:
    """
    An IPv4 Address
    """

    @classmethod
    def get_address(cls, address):
        if address.upper() == ANY:
            address = "0.0.0.0/0"
        return ipaddress.ip_interface(address).network


class Interface:
    """
    An Interface
    """

    def __init__(self, interface):
        # Do not use this constructor directly, use get_port() instead
        self.interface = interface

    def __eq__(self, other):
        return self.interface == other.interface

    def __repr__(self):
        return self.interface

    def superset_of(self, other):
        return self.interface == ANY

    def subset_of(self, other):
        return other.interface == ANY

    @classmethod
    def get_interface(cls, interface):
        if not isinstance(interface, str):
            raise ValueError(f"Not a valid interface '{interface}'")

        # Validate the address
        if not re.match(r"^[A-Za-z][A-Za-z0-9_-]*$", interface):
            raise ValueError(
                f"Interface '{interface}' must start with a letter and can only include letters, digits, '_' or '-'"
            )

        return cls(interface.upper())


class Packet:
    """
    Packet header information
    """

    def __init__(self, protocol, src, s_port, dst, d_port, *, interface=ANY):
        self.fields = {
            "interface": Interface.get_interface(interface.strip()),
            "protocol": Protocol.get_protocol(protocol.strip()),
            "src": Address.get_address(src.strip()),
            "sport": PortSet.get_port(s_port.strip()),
            "dst": Address.get_address(dst.strip()),
            "dport": PortSet.get_port(d_port.strip()),
        }

    def __repr__(self):
        return ",".join(map(str, self.fields.values()))


class Policy(Packet):
    """
    Firewall Policy
    """

    def __init__(self, **policy_fields):
        interface = policy_fields.get("interface", ANY)
        protocol = policy_fields.get("protocol", ANY)
        src = policy_fields.get("src", ANY)
        s_port = policy_fields.get("s_port", ANY)
        dst = policy_fields.get("dst", ANY)
        d_port = policy_fields.get("d_port", ANY)

        super().__init__(protocol, src, s_port, dst, d_port, interface=interface)
        self.action = Action.get_action(policy_fields.get("action"))

    def compare_two_fields(self, a, b):
        """
        Get the relation between two policy fields.
        """
        if a == b:
            return RField.EQUAL
        if a.subset_of(b):
            return RField.STRICT_SUBSET if a != b else RField.SUBSET
        if a.superset_of(b):
            return RField.STRICT_SUPERSET if a != b else RField.SUPERSET
        return RField.UNEQUAL

    def compare_two_addresses(self, a, b):
        """
        Get the relation between two policy fields representing IP addresses.
        """
        if a == b:
            return RField.EQUAL
        if a.subnet_of(b):
            return RField.STRICT_SUBSET if a != b else RField.SUBSET
        if a.supernet_of(b):
            return RField.STRICT_SUPERSET if a != b else RField.SUPERSET
        return RField.UNEQUAL

    def compare_fields(self, other):
        # compare fields with another policy or packet
        return [
            self.compare_two_fields(
                self.fields["interface"], other.fields["interface"]
            ),
            self.compare_two_fields(self.fields["protocol"], other.fields["protocol"]),
            self.compare_two_addresses(self.fields["src"], other.fields["src"]),
            self.compare_two_fields(self.fields["sport"], other.fields["sport"]),
            self.compare_two_addresses(self.fields["dst"], other.fields["dst"]),
            self.compare_two_fields(self.fields["dport"], other.fields["dport"]),
        ]

    def compare_actions(self, other):
        return self.action == other.action

    def is_exact_match(self, relations):
        return all(f is RField.EQUAL for f in relations)

    def is_inclusive_match_superset(self, relations):
        condition1 = all(
            relation in {RField.EQUAL, RField.SUPERSET, RField.STRICT_SUPERSET}
            for relation in relations
        )
        condition2 = any(relation in {RField.STRICT_SUPERSET} for relation in relations)
        return condition1 and condition2

    def is_inclusive_match_subset(self, relations):
        condition1 = all(
            relation in {RField.EQUAL, RField.SUBSET, RField.STRICT_SUBSET}
            for relation in relations
        )
        condition2 = any(relation in {RField.STRICT_SUBSET} for relation in relations)
        return condition1 and condition2

    def is_corrlated_relation(self, relations):
        condition1 = all(
            relation
            in {
                RField.EQUAL,
                RField.SUBSET,
                RField.SUPERSET,
                RField.STRICT_SUBSET,
                RField.STRICT_SUPERSET,
            }
            for relation in relations
        )
        condition2 = any(relation in {RField.STRICT_SUBSET} for relation in relations)
        condition3 = any(relation in {RField.STRICT_SUPERSET} for relation in relations)
        return condition1 and condition2 and condition3

    def is_partial_disjoint(self, relations):
        condition1 = any(relation in {RField.EQUAL} for relation in relations)
        condition2 = any(relation not in {RField.EQUAL} for relation in relations)
        return condition1 and condition2

    def is_disjoint(self, relations):
        return all(f is RField.UNEQUAL for f in relations)

    def get_rule_relation(self, other):
        """
        Determines the relationship between two rules based on field comparisons.
        Returns the resulting relationship between the two rules.
        """

        # Compare the fields of the two rules
        relations = self.compare_fields(other)

        # Map condition checks to rule relations
        relation_checks = [
            (self.is_exact_match, RRule.EM),  # Exact match
            (self.is_inclusive_match_superset, RRule.IMP),  # Inclusive match (superset)
            (self.is_inclusive_match_subset, RRule.IMB),  # Inclusive match (subset)
            (self.is_corrlated_relation, RRule.CC),  # Correlated relation
            (self.is_partial_disjoint, RRule.PD),  # Partial disjoint
            (self.is_disjoint, RRule.CD),  # Completely disjoint
        ]

        # Iterate through checks and return the first match
        for check, rule_relation in relation_checks:
            # call the check function
            if check(relations):
                return rule_relation

        # Unknwon if no condition matches (fallback)
        return RRule.UN

    def is_match(self, packet):
        # the packet matches this policy if all fields in policy are
        # equal or supersets of the packet fields
        return all(
            f in [RField.SUPERSET, RField.EQUAL] for f in self.compare_fields(packet)
        )

    def get_action(self):
        return self.action

    def __repr__(self):
        return ",".join(map(str, self.fields.values())) + "," + str(self.action)


class PolicyAnalyzer:
    """
    Firewall Policy Analyzer
    """

    anamoly = {
        (RRule.IMB, False): Anomaly.GEN,
        (RRule.IMP, False): Anomaly.SHD,
        (RRule.CC, False): Anomaly.COR,
        (RRule.IMP, True): Anomaly.RYD,
        (RRule.EM, True): Anomaly.RYD,
        (RRule.IMB, True): Anomaly.RXD,
    }

    def __init__(self, policies):
        self.policies = policies

    def _get_anamoly(self, rule_relation, same_action):
        return PolicyAnalyzer.anamoly.get((rule_relation, same_action), Anomaly.AOK)

    def get_relations(self):
        # compare each policy with the previous ones
        rule_relations = {}
        for y, y_policy in enumerate(self.policies):
            rule_relations[y] = [
                (x, x_policy.get_rule_relation(y_policy))
                for x, x_policy in enumerate(self.policies[0:y])
            ]
        return rule_relations

    def get_action_relations(self):
        # compare each policy action with the previous ones
        rule_action_relations = {}
        for y, y_policy in enumerate(self.policies):
            rule_action_relations[y] = [
                x_policy.compare_actions(y_policy) for x_policy in self.policies[0:y]
            ]
        return rule_action_relations

    # def get_anomalies(self):
    #     anomalies = {}
    #     rule_relations = self.get_relations()
    #     action_relations = self.get_action_relations()

    #     for ry, ry_relations in rule_relations.items():
    #         for rx, relation in ry_relations:
    #             anamoly = self._get_anamoly(relation, action_relations[ry][rx])
    #             if anamoly is Anomaly.RXD:
    #                 # check the rules in between for additional conditions
    #                 for rz in range(rx + 1, ry):
    #                     if any(
    #                         a == rx
    #                         and not action_relations[rz][rx]
    #                         and b in [RRule.CC, RRule.IMB]
    #                         for a, b in rule_relations[rz]
    #                     ):
    #                         anamoly = Anomaly.AOK
    #                         break
    #             if anamoly is not Anomaly.AOK:
    #                 anomalies.setdefault(ry, []).append((rx, anamoly))
    #     return anomalies

    def get_anomalies(self):
        anomalies = {}
        rule_relations = self.get_relations()
        action_relations = self.get_action_relations()

        for y_rule, y_relations in rule_relations.items():
            for x_rule, relation in y_relations:
                anomaly = self._get_anamoly(relation, action_relations[y_rule][x_rule])

                if anomaly is Anomaly.RXD:
                    # Check intermediate rules for additional conditions
                    for intermediate_rule in range(x_rule + 1, y_rule):
                        if any(
                            src == x_rule
                            and not action_relations[intermediate_rule][x_rule]
                            and rel in [RRule.CC, RRule.IMB]
                            for src, rel in rule_relations[intermediate_rule]
                        ):
                            anomaly = Anomaly.AOK
                            break

                if anomaly is not Anomaly.AOK:
                    anomalies.setdefault(y_rule, []).append((x_rule, anomaly))

        return anomalies

    def get_first_match(self, packet):

        for i, policy in enumerate(self.policies):
            if policy.is_match(packet):
                return i, policy
        return None
