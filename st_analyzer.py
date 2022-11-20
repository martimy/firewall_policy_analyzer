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

EXAMPE_RULES = """protocol,src,s_port,dst,d_port,action
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


DEF_GEN = """A rule (Y) is a generalization of a preceding rule (X) if they 
have different actions, and if rule (Y) can match all the packets that 
match rule (X)."""

DEF_RXD = """A rule (X) is redundant if it performs the same action on the 
same packets as a following rule (Y), and if rule (Y) can match all the packets 
that match rule (X), except when there is an intermidate rule (Z) 
that relates to (X) but with different action."""

DEF_RYD = """A rule (Y) is redundant if it performs the same action on the 
same packets as a preceding rule (X), and if rule (X) can match all the packets 
that match rule (Y)."""

DEF_SHD = """A rule (Y) is shadowed by a previous rule (X) if the they have 
different actions, and if rule (X) matches all the packets that match rule (Y), 
such that the rule (Y) will never be reached."""

DEF_COR = """Two rules (X) and (Y) are correlated if they have different 
actions, and rule (X) matches some packets that match rule (Y) and 
rule (Y) matches some packets that match rule (X)."""

desc = {
    "GEN": {"short": "Generalization",
            "long": "generalizes",
            "rec": "No change is required.",
            "def": DEF_GEN},
    "SHD": {"short": "Shadowing",
            "long": "is shadowed by",
            "rec": "Move rule Y before X.",
            "def": DEF_SHD},
    "COR": {"short": "Corrolation",
            "long": "corrolates with",
            "rec": "Verify correctness.",
            "def": DEF_COR},
    "RXD": {"short": "Redundancy X",
            "long": "is a superset of",
            "rec": "Remove rule X.",
            "def": DEF_RXD},
    "RYD": {"short": "Redundancy Y",
            "long": "is a subset of",
            "rec": "Remove rule Y",
            "def": DEF_RYD}
}

TITLE = "Firewall Policy Analyzer"
ABOUT = """This app analyzes a set of firewall policies and detects any anomalies.

:warning: Use at your own risk."""
NO_RELATION = ":heavy_check_mark: No anomalies detected."
EXAMPLE_HELP = "Use built-in example file to demo the app."
SELECT_RULES = "Select rules to review relationships."
UPLOAD_FILE = "Upload a file"

errors = ['SHD', 'RYD', 'RXD']
warn = ['COR']


def color_erros(val):
    """Return style color for errors and warnnings"""

    fcolor = 'red' if val in errors else 'orange' if val in warn else None
    # bcolor = 'red' if val in errors else 'orange' if val in warn else None

    # style = f'background-color: {bcolor};' if bcolor else ''
    style = f'color: {fcolor};' if fcolor else ''
    return style


def to_dict(rel_dict):
    """Convert anomalies lists to dictionary"""

    my_dict = {}
    for r_item in rel_dict:
        sub_dict = {}
        for i in rel_dict[r_item]:
            sub_dict[i[0]] = str(i[1])
        my_dict[r_item] = sub_dict
    return my_dict


st.title(TITLE)
with st.expander("About", expanded=True):
    st.markdown(ABOUT)

uploaded_file = st.file_uploader('Upload rules file')
use_example = st.checkbox('Use example file', value=False, help=EXAMPLE_HELP)
if use_example:
    uploaded_file = StringIO(EXAMPE_RULES)

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

# Summary Section

    st.header('Summary')
    if not pdr.empty:
        st.write('Relationship count:')

        count = {k: pdr[pdr == k].count().sum() for k in desc}
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric('SHD', count['SHD'], help=desc['SHD']['short'])
        with c2:
            st.metric('RXD', count['RXD'], help=desc['RXD']['short'])
        with c3:
            st.metric('RYD', count['RYD'], help=desc['RYD']['short'])
        with c4:
            st.metric('COR', count['COR'], help=desc['COR']['short'])
        with c5:
            st.metric('GEN', count['GEN'], help=desc['GEN']['short'])

        st.write('Relationship table:')

        use_colors = st.checkbox('Highlight Errors', value=False)
        if use_colors:
            st.dataframe(pdr.style.applymap(color_erros),
                         use_container_width=True)
        else:
            st.dataframe(pdr, use_container_width=True)
    else:
        st.markdown(NO_RELATION)

# Analysis Section

    # If relations are detected
    st.header("Analysis")
    if len(anom_dict) > 0:
        st.write(SELECT_RULES)
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

            acode = anom_dict[y_rule][x_rule]
            xy_rel = desc[acode]['long']
            xy_short = desc[acode]['short']
            xy_def = desc[acode]['def']
            xy_desc = f'Rule **Y** ({y_rule}) {xy_rel} rule **X** ({x_rule}).'
            xy_recom = desc[acode]['rec']

            st.markdown(f"#### {xy_short}")
            st.markdown(xy_desc)
            with st.expander('Definition', expanded=False):
                st.markdown(xy_def)
            st.markdown('#### Recommendation')
            st.markdown(xy_recom)

    else:
        st.markdown(NO_RELATION)
else:
    st.error(UPLOAD_FILE)
