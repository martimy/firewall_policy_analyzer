# -*- coding: utf-8 -*-
"""
Created on Thu Nov 17 08:07:34 2022

Copyright Maen Artimy 2022
"""

import pandas as pd
import streamlit as st
from policyanalyzer import Policy, PolicyAnalyzer  # , Packet

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

legend = '-' + '-'.join([f' {k}: {v}  \n'for k, v in desc.items()])

def color_erros(val):
    fcolor = 'white' if val in errors else None
    bcolor = 'red' if val in errors else 'orange' if val in warn else None

    style = f'background-color: {bcolor};' if bcolor else ''
    style += f'color: {fcolor};' if fcolor else ''
    return style


def highlight_shadow(val):
    color = 'red' if val == 'SHD' else 'black'
    return f'color: {color}'

def to_dict(rel):
    """Convert anomalies to dictionary"""
    
    my_dict = {}
    for a in rel:
        sub_dict = {}
        for i in rel[a]:
            sub_dict[i[0]] = str(i[1])
        my_dict[a] = sub_dict
    return my_dict            


st.title('Firewall Policy Analyzer')
st.write('Analyze a set of firewall policies and detect any anomalies.')

with st.sidebar:
    uploaded_file = st.file_uploader('Upload a policies')
    check_legend = st.checkbox("Show realtionships legend", value=False)
    if check_legend:
        st.markdown(legend)
        
if uploaded_file is not None:
    # Create a DataFrame from a csv file
    reader = pd.read_csv(uploaded_file)
    
    show_original = st.checkbox('Show Rules', value=True)
    if show_original:
        st.header('Rules')
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
    for y_rule in anom_dict:
        col = [None] * len(rules)
        for x_rule in anom_dict[y_rule]:
            col[x_rule] = anom_dict[y_rule][x_rule]
        relations[y_rule] = col

    pdr = pd.DataFrame.from_dict(relations)\
        .transpose().dropna(axis=1, how='all').fillna('')

    st.header('Summary')
    if not pdr.empty:
        st.write('The following table shows a summary of relationships among the rules.')
        use_colors = st.checkbox('Highlight Errors', value=False)
        if use_colors:
            st.dataframe(pdr.style.applymap(color_erros), use_container_width=True)
        else:
            st.dataframe(pdr, use_container_width=True)
    else:
        st.write("There are no relationships. This usually means the rule set has anomalies.")
        
    # Filter
    # df2 = pdr.where(pdr == "SHD", None)\
    #     .dropna(axis=0, how='all').dropna(axis=1, how='all')\
    #     .fillna('')
    # st.write(df2)


    # If relations are detected
    st.header("Details")
    
    if len(anom_dict) > 0:
        col1, col2 = st.columns(2)
        with col1:
            # Select one of the Y rules
            y_rule = st.selectbox("Select Y Rule:", list(anom_dict.keys()))
    
        with col2:
            # Get the long description of relation between rules X and Y.
            x_list = list(anom_dict[y_rule].keys())
            
            # Select one of the X rules                  
            x_rule = st.selectbox("Select X Rule", x_list)
    
            
        if y_rule: # note that 0 === False

            st.dataframe(reader.iloc[[x_rule, y_rule]].\
                rename(index={x_rule: f'X ({x_rule})', y_rule:f'Y ({y_rule})'}),\
                    use_container_width=True)
                
            xy_rel = rel.get(anom_dict[y_rule][x_rule], '??')
            xy_desc = f'Rule **Y** ({y_rule}) {xy_rel} rule **X** ({x_rule}).'
            xy_recom = rec.get(anom_dict[y_rule][x_rule], 'No recommondation.')
            xy_short = desc.get(anom_dict[y_rule][x_rule], 'No Description.')
            st.markdown(f"### {xy_short}\n- {xy_desc}\n- {xy_recom}")


    else:
        st.write("No relations are found.")            
else:
    st.error("upload file")
