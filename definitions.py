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

from enum import Enum


class RRule(Enum):
    """
    Define rule relations
    """
    IMB = 5  # "IMB"  # Inclusive match (subset)
    IMP = 4  # "IMP"  # Inclusive match (superset)
    CC = 3  # "CC"  # corrolation
    EM = 2  # "EM"  # exact match
    PD = 1  # "PD"  # partial disjoint
    CD = 0  # "CD"  # complete disjoint

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class RField(Enum):
    """
    Define field relations
    """
    UNEQUAL = 0
    EQUAL = 1
    SUBSET = 2
    SUPERSET = 3

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class Anomaly(Enum):
    """
    Define anomaly types
    """
    AOK = 0  # no anomaly
    SHD = 1  # shadowing
    COR = 2  # corrolation
    RXD = 3  # redundancy: x is a superset of y
    RUD = 4  # redundancy: x is a supset of y
    GEN = 5  # generalization

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name
