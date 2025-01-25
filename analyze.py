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

"""
Command line example of using the policy analyzer
"""

import csv
import sys
import os
from policyanalyzer import Policy, PolicyAnalyzer, Packet


def display_rules(policies):
    print("=" * 70)
    print("Rules:")
    print("=" * 70)

    for n, p in enumerate(policies):
        print(f"{n:3}: {p}")

    print()


def display_patterns(anomalies):
    print("=" * 70)
    print("Patterns:")
    print("=" * 70)

    for i in anomalies:
        print(f"{i:3}: {anom[i]}")

    print()


def read_csv_to_dict(file_path):
    """
    Reads a CSV file and returns a list of dictionaries where keys are the CSV
    header items.

    :param file_path: Path to the CSV file
    :return: List of dictionaries
    """
    with open(file_path, mode="r") as file:
        csv_reader = csv.DictReader(file)
        return [row for row in csv_reader]


# Read csv file conatining policies but remove header

# Read command line arguments
if len(sys.argv) > 2:
    outfilename = sys.argv[2].split(".")[0] + ".csv"

if len(sys.argv) > 1:
    csvfile = sys.argv[1]
    reader = read_csv_to_dict(csvfile)
else:
    print(f"Usage: python3 {os.path.basename(__file__)} <file>")
    sys.exit("Input file name is required!")


policies = [Policy(**r) for r in reader]
analyzer = PolicyAnalyzer(policies)
rule_relations = analyzer.get_relations()
anom = analyzer.get_anomalies()

display_rules(policies)
display_patterns(anom)


print("=" * 70)
print("Matches:")
print("=" * 70)

for packet in [
    Packet("tcp", "192.168.1.4", "ANY", "172.16.16.1", "80"),
    Packet("tcp", "0.0.0.0/0", "any", "161.120.33.40", "80"),
    Packet("tcp", "140.192.37.0/24", "any", "161.120.33.40", "80"),
]:

    result = analyzer.get_first_match(packet)
    if result:
        print(packet)
        print("has a match:")
        print(result)

print()

####
print("=" * 70)
print("Relations")
print("=" * 70)
num = len(reader)
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

for r in relations:
    print(relations[r])
