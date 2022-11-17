# -*- coding: utf-8 -*-
"""
Created on Thu Nov 17 08:07:34 2022

Copyright Maen Artimy
"""

import csv
import sys
import os
from policyanalyzer import Policy, PolicyAnalyzer, Packet
import pandas as pd
import influxdb
import streamlit as st


# def policies_st(policies):
#     print("=" * 50)
#     print("Policies:")
#     for n, p in enumerate(policies):
#         print(f"{n:3}: {p}")

# def anomalies_st(anomalies):
#     print("=" * 50)
#     print("Anomalies:")
#     for i in anomalies:
#         print(f"{i:3}: {anom[i]}")

# # Read csv file conatining policies but remove header
# # HEADER = "protocol,src,s_port,dest,d_port,action"

# # Read command line arguments
# if len(sys.argv) > 2:
#     outfilename = sys.argv[2].split('.')[0] + ".csv"
# if len(sys.argv) > 1:
#     with open(sys.argv[1], 'r') as csvfile:
#         reader = list(csv.reader(csvfile))[1:]
# else:
#     print(f"Usage: python3 {os.path.basename(__file__)} <file>")
#     sys.exit("Input file name is required!")


# policies = [Policy(*r) for r in reader]
# analyzer = PolicyAnalyzer(policies)
# rule_relations = analyzer.get_relations()
# anom = analyzer.get_anomalies()

# policies_st(policies)
# anomalies_st(anom)


# =================


st.title('Firewall Policy Analyzer')
st.write('Analyze a set of firewall policies and shows any relationship among rules.')


with st.sidebar:
    uploaded_file = st.file_uploader('Upload a policies')

if uploaded_file is not None:
    # Create a DataFrame from a csv file
    st.header('Rules:')
    reader = pd.read_csv(uploaded_file)
    st.write(reader)

    # Convert DataFrame to list to perfrom analysis
    rules = reader.values.tolist()
    policies = [Policy(*r) for r in rules]
    analyzer = PolicyAnalyzer(policies)
    # st.write(policies)
    
    # Display relations
    anom = analyzer.get_anomalies()

    num = len(rules)
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

    pdr = pd.DataFrame\
    .from_dict(relations)\
    .transpose().dropna(axis=1, how='all').fillna('')
    st.write(pdr)
    
else:
    st.error("upload file")
