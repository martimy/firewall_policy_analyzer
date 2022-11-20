# -*- coding: utf-8 -*-

"""
Copyright 2022 Maen Artimy

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

# A treamlit app that demonstrates the use of firewall policy analyzer

from io import StringIO
import pandas as pd
import streamlit as st
from policyanalyzer import Policy, PolicyAnalyzer

example_rules = """protocol,src,s_port,dst,d_port,action
tcp,140.192.37.20,any,0.0.0.0/0,80,deny
tcp,140.192.37.0/24,any,0.0.0.0/0,80,accept
tcp,0.0.0.0/0,any,161.120.33.40,80,accept
tcp,140.192.37.0/24,any,161.120.33.40,80,deny
tcp,140.192.37.30,any,0.0.0.0/0,21,deny
tcp,140.192.37.0/24,any,0.0.0.0/0,21,accept
tcp,140.192.37.0/24,any,161.120.33.40,21,accept
tcp,0.0.0.0/0,any,0.0.0.0/0,any,deny
udp,140.192.37.0/24,any,161.120.33.40,53,accept
udp,0.0.0.0/0,any,161.120.33.40,53,accept
udp,140.192.38.0/24,any,161.120.35.0/24,any,accept
udp,0.0.0.0/0,any,0.0.0.0/0,any,deny"""


desc = {
    "GEN": "Generalization",
    "SHD": "Shadowing",
    "COR": "Corrolation",
    "RUD": "Redundancy (1)",
    "RXD": "Redundancy (2)"}

rel = {
    "GEN": "generalizes",
    "SHD": "is shadowed by",
    "COR": "corrolates with",
    "RUD": "is a superset of",
    "RXD": "is a subset of"}

rec = {
    "GEN": "No changes is required.",
    "SHD": "Move rule Y before X.",
    "COR": "Verify correctness.",
    "RUD": "Remove rule X.",
    "RXD": "Remove rule Y"}

errors = ['SHD', 'RXD', 'RUD']
warn = ['COR']
LEGEND = '-' + '-'.join([f' {k}: {v}  \n'for k, v in desc.items()])


def color_erros(val):
    """Return style color for errors and warnnings"""

    fcolor = 'white' if val in errors else None
    bcolor = 'red' if val in errors else 'orange' if val in warn else None

    style = f'background-color: {bcolor};' if bcolor else ''
    style += f'color: {fcolor};' if fcolor else ''
    return style


def to_dict(rel_dict):
    """Convert anomalies to dictionary"""

    my_dict = {}
    for r_item in rel_dict:
        sub_dict = {}
        for i in rel_dict[r_item]:
            sub_dict[i[0]] = str(i[1])
        my_dict[r_item] = sub_dict
    return my_dict


st.title('Firewall Policy Analyzer')
with st.expander("About", expanded=True):
    st.write('Analyze a set of firewall policies and detect any anomalies.')

uploaded_file = st.file_uploader('Upload rules file')
use_example = st.checkbox('Use example file', value=False, 
                          help="Use built-in example file to demo the app.")
if use_example:
    uploaded_file = StringIO(example_rules)

if uploaded_file is not None:
    # Create a DataFrame from a csv file
    reader = pd.read_csv(uploaded_file)
   
    with st.expander("See Rules"):
        st.dataframe(reader, use_container_width=True)

    # Convert DataFrame to list to perfrom analysis
    rules = reader.values.tolist()
    policies = [Policy(*r) for r in rules]
    analyzer = PolicyAnalyzer(policies)
    # st.write(policies)

    # Find relations
    anom = analyzer.get_anomalies()
    anom_dict = to_dict(anom)

    # Display relations
    relations = {}  # cols
    for y_rule, y_dict in anom_dict.items():
        col = [None] * len(rules)
        for x_rule in y_dict:
            col[x_rule] = y_dict[x_rule]
        relations[y_rule] = col

    pdr = pd.DataFrame.from_dict(relations)\
        .transpose().dropna(axis=1, how='all').fillna('')

## Summary Section 

    st.header('Summary')
    if not pdr.empty:
        st.write('Relationship count:')
        
        count = {k: pdr[pdr == k].count().sum() for k in desc}
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric('SHD', count['SHD'], help=desc['SHD'])
        with c2:
            st.metric('RUD', count['RUD'], help=desc['RUD'])
        with c3:
            st.metric('RXD', count['RXD'], help=desc['RXD'])
        with c4:
            st.metric('COR', count['COR'], help=desc['COR'])
        with c5:
            st.metric('GEN', count['GEN'], help=desc['GEN'])

        st.write('Relationship table:')

        use_colors = st.checkbox('Highlight Errors', value=False)
        if use_colors:
            st.dataframe(pdr.style.applymap(color_erros),
                         use_container_width=True)
        else:
            st.dataframe(pdr, use_container_width=True)
    else:
        st.write(
            "There are no relationships. This usually means the rule set has anomalies.")

## Analysis Section 

    # If relations are detected
    st.header("Analysis")        
    if len(anom_dict) > 0:
        st.write('Select rules to review relationships.')
        col1, col2 = st.columns(2)
        with col1:
            # Select one of the Y rules
            y_rule = st.selectbox("Select Y Rule:", list(anom_dict.keys()))

        with col2:
            # Get the long description of relation between rules X and Y.
            x_list = list(anom_dict[y_rule].keys())

            # Select one of the X rules
            x_rule = st.selectbox("Select X Rule", x_list)

        if y_rule:  # note that 0 === False

            st.dataframe(reader.iloc[[x_rule, y_rule]].
                         rename(index={x_rule: f'X ({x_rule})',
                                y_rule: f'Y ({y_rule})'}),
                         use_container_width=True)

            xy_rel = rel.get(anom_dict[y_rule][x_rule], '??')
            xy_desc = f'Rule **Y** ({y_rule}) {xy_rel} rule **X** ({x_rule}).'
            xy_recom = rec.get(anom_dict[y_rule][x_rule], 'No recommondation.')
            xy_short = desc.get(anom_dict[y_rule][x_rule], 'No Description.')
            st.markdown(
                f"### {xy_short}\n- **Description:** {xy_desc}\
                    \n- **Recommendation:** {xy_recom}")

    else:
        st.write("No relations are found.")
else:
    st.error("Upload a file")
