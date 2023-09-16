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

"""
Command line example of using the policy analyzer
"""

import csv
import sys
import os
from policyanalyzer import Policy, PolicyAnalyzer, Packet


def policies_st(policies):
    print("=" * 50)
    print("Policies:")
    for n, p in enumerate(policies):
        print(f"{n:3}: {p}")


def anomalies_st(anomalies):
    print("=" * 50)
    print("Anomalies:")
    for i in anomalies:
        print(f"{i:3}: {anom[i]}")


# Read csv file conatining policies but remove header

# Read command line arguments
if len(sys.argv) > 2:
    outfilename = sys.argv[2].split(".")[0] + ".csv"
if len(sys.argv) > 1:
    with open(sys.argv[1], "r") as csvfile:
        reader = list(csv.reader(csvfile))[1:]
else:
    print(f"Usage: python3 {os.path.basename(__file__)} <file>")
    sys.exit("Input file name is required!")


policies = [Policy(*r) for r in reader]
analyzer = PolicyAnalyzer(policies)
rule_relations = analyzer.get_relations()
anom = analyzer.get_anomalies()

policies_st(policies)
anomalies_st(anom)


print("=" * 50)
print("Matches:")
packet = Packet("tcp", "140.192.37.0/24", "any", "0.0.0.0/0", "80")
packet = Packet("tcp", "0.0.0.0/0", "any", "161.120.33.40", "80")
packet = Packet("tcp", "140.192.37.0/24", "any", "161.120.33.40", "80")
result = analyzer.get_first_match(packet)
print(result)


####
num = len(reader)
print(num)
relations = {}  # cols
for y_rule in anom:
    # create a col of None
    col = [None] * num
    anom_list = anom[y_rule]
    for t in anom_list:
        # anom tuple
        x_rule, relation = t
        col[x_rule] = relation
    relations[y_rule] = col

print(relations)
