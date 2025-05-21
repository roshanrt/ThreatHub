import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import os
import random
import requests
from ml_prediction import predict_ttps_in_mitre_attack
import logging

logger = logging.getLogger(__name__)

def load_mitre_attack_data():
    """Load MITRE ATT&CK data from JSON file"""
    data_file = "data_resources/mitre_attack_techniques.json"
    
    try:
        if os.path.exists(data_file):
            with open(data_file, "r") as f:
                data = json.load(f)
            return data
        else:
            logger.error(f"MITRE ATT&CK data file not found at {data_file}")
            raise FileNotFoundError(f"Required data file {data_file} not found")
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Error loading MITRE ATT&CK data: {str(e)}")
        raise

def fetch_live_mitre_data(api_url):
    """Fetch live MITRE ATT&CK data from an API."""
    response = requests.get(api_url)
    response.raise_for_status()
    return response.json()

def load_mitre_attack_data_with_live_update():
    try:
        live_data = fetch_live_mitre_data("https://api.mitre.org/attack")
        return live_data
    except Exception as e:
        print("Failed to fetch live data, falling back to local data.", e)
        return load_mitre_attack_data()

def generate_mitre_matrix(techniques_data, highlight_techniques=None, coverage_data=None):
    """
    Generate a MITRE ATT&CK matrix with optional highlighting for specific techniques
    and coverage visualization.
    
    Args:
        techniques_data: Dictionary containing tactics and techniques data
        highlight_techniques: List of technique IDs to highlight (optional)
        coverage_data: Dictionary with technique IDs as keys and coverage values as values (optional)
    
    Returns:
        Plotly figure object
    """
    tactics = techniques_data["tactics"]
    techniques = techniques_data["techniques"]
    
    # Create a dataframe for the heatmap
    tactic_ids = [tactic["tactic_id"] for tactic in tactics]
    tactic_names = [tactic["tactic_name"] for tactic in tactics]
    
    # Create a mapping from tactic_id to column index
    tactic_to_col = {tactic_id: i for i, tactic_id in enumerate(tactic_ids)}
    
    # Initialize the matrix with zeros
    matrix = np.zeros((len(techniques), len(tactics)))

    
    # Prepare technique labels and coverage information
    technique_labels = []
    technique_ids = []
    coverage_values = []
    
    for i, technique in enumerate(techniques):
        technique_ids.append(technique["technique_id"])
        technique_labels.append(f"{technique['technique_id']}: {technique['technique_name']}")
        
        # Set default coverage value
        if coverage_data and technique["technique_id"] in coverage_data:
            coverage_values.append(coverage_data[technique["technique_id"]])
        else:
            coverage_values.append(0.5)  # Default value if no coverage data
        
        # Fill the matrix
        tactic_id = technique["tactic_id"]
        if tactic_id in tactic_to_col:
            col_idx = tactic_to_col[tactic_id]
            
            # If we have highlighted techniques, use different values
            if highlight_techniques and technique["technique_id"] in highlight_techniques:
                matrix[i, col_idx] = 2  # Highlighted technique
            else:
                matrix[i, col_idx] = 1  # Normal technique
    
    # Create color scale based on whether we have highlighted techniques
    if highlight_techniques:
        colorscale = [[0, 'white'], [0.5, 'rgb(17, 119, 51)'], [1, 'rgb(204, 0, 0)']]
    else:
        colorscale = [[0, 'white'], [1, 'rgb(17, 119, 51)']]
    
    # Create the heatmap
    fig = go.Figure(data=go.Heatmap(
        z=matrix,
        x=tactic_names,
        y=technique_labels,
        colorscale=colorscale,
        showscale=False,
        hoverinfo="text",
        text=[[f"Tactic: {tactic_names[j]}<br>Technique: {technique_labels[i]}" 
              for j in range(len(tactic_names))] 
              for i in range(len(technique_labels))]
    ))
    
    # Update layout
    fig.update_layout(
        title="MITRE ATT&CK Matrix",
        xaxis=dict(title="Tactics"),
        yaxis=dict(title="Techniques", autorange="reversed"),
        height=800,
        margin=dict(l=150, r=50, b=100, t=100),
    )
    
    return fig

def generate_coverage_heatmap(techniques_data, coverage_data):
    """
    Generate a MITRE ATT&CK coverage heatmap.
    
    Args:
        techniques_data: Dictionary containing tactics and techniques data
        coverage_data: Dictionary with technique IDs as keys and coverage values (0-1) as values
    
    Returns:
        Plotly figure object
    """
    tactics = techniques_data["tactics"]
    techniques = techniques_data["techniques"]
    
    # Create a dataframe for the heatmap
    tactic_ids = [tactic["tactic_id"] for tactic in tactics]
    tactic_names = [tactic["tactic_name"] for tactic in tactics]
    
    # Create a mapping from tactic_id to column index
    tactic_to_col = {tactic_id: i for i, tactic_id in enumerate(tactic_ids)}
    
    # Initialize the matrix with zeros
    matrix = np.zeros((len(techniques), len(tactics)))
    
    # Prepare technique labels
    technique_labels = []
    
    for i, technique in enumerate(techniques):
        technique_labels.append(f"{technique['technique_id']}: {technique['technique_name']}")
        
        # Fill the matrix with coverage values
        tactic_id = technique["tactic_id"]
        if tactic_id in tactic_to_col:
            col_idx = tactic_to_col[tactic_id]
            
            # Use coverage value if available, otherwise 0
            coverage = coverage_data.get(technique["technique_id"], 0)
            matrix[i, col_idx] = coverage
    
    # Create the heatmap with a color scale from white (0) to blue (1)
    fig = go.Figure(data=go.Heatmap(
        z=matrix,
        x=tactic_names,
        y=technique_labels,
        colorscale=[
            [0, 'white'],
            [0.25, 'rgba(173, 216, 230, 0.5)'],  # Light blue
            [0.5, 'rgba(30, 144, 255, 0.6)'],    # Dodger blue
            [0.75, 'rgba(0, 0, 205, 0.8)'],      # Medium blue
            [1, 'rgba(0, 0, 139, 1)']            # Dark blue
        ],
        showscale=True,
        colorbar=dict(
            title="Coverage",
            tickvals=[0, 0.25, 0.5, 0.75, 1],
            ticktext=["None", "Low", "Medium", "High", "Complete"]
        ),
        hoverinfo="text",
        text=[[f"Tactic: {tactic_names[j]}<br>Technique: {technique_labels[i]}<br>Coverage: {matrix[i, j]:.2f}" 
              for j in range(len(tactic_names))] 
              for i in range(len(technique_labels))]
    ))
    
    # Update layout
    fig.update_layout(
        title="TTP Coverage Heatmap",
        xaxis=dict(title="Tactics"),
        yaxis=dict(title="Techniques", autorange="reversed"),
        height=800,
        margin=dict(l=150, r=50, b=100, t=100),
    )
    
    return fig

def show_mitre_attack():
    """Display the MITRE ATT&CK intelligence page"""
    st.title("🎯 MITRE ATT&CK Intelligence")
    
    st.markdown("""
    The MITRE ATT&CK framework is a globally-accessible knowledge base of adversary tactics and 
    techniques based on real-world observations. This platform provides intelligence on known 
    tactics, techniques, and procedures (TTPs) used by threat actors.
    """)
    
    # Load MITRE ATT&CK data
    mitre_data = load_mitre_attack_data()
    
    # Create tabs for different views
    tabs = st.tabs(["ATT&CK Matrix", "TTP Coverage Heatmap", "Techniques Explorer", "TTP Trend Prediction"])
    
    with tabs[0]:
        st.subheader("MITRE ATT&CK Matrix")
        
        st.markdown("""
        The ATT&CK Matrix provides a visual representation of the tactics and techniques used by 
        adversaries. Each cell represents a specific technique associated with a tactic.
        """)
        
        # Option to highlight specific techniques
        with st.expander("Highlight Specific Techniques"):
            # Create a multiselect with technique IDs and names
            technique_options = [f"{t['technique_id']}: {t['technique_name']}" for t in mitre_data["techniques"]]
            selected_techniques = st.multiselect("Select techniques to highlight", options=technique_options)
            
            # Extract just the technique IDs from the selections
            highlight_techniques = [t.split(":")[0].strip() for t in selected_techniques]
        
        # Display the ATT&CK matrix with optional highlighting
        matrix_fig = generate_mitre_matrix(mitre_data, highlight_techniques=highlight_techniques if highlight_techniques else None)
        st.plotly_chart(matrix_fig, use_container_width=True)
        
    with tabs[1]:
        st.subheader("TTP Coverage Heatmap")
        
        st.markdown("""
        The TTP Coverage Heatmap shows the level of coverage your security controls provide against
        various MITRE ATT&CK techniques. Higher values (darker blue) indicate better coverage against
        that particular technique.
        """)
        
        # Simulate coverage data
        st.info("This is a simulated coverage visualization. In a production environment, this would be connected to your actual security controls and detection rules.")
        
        # Create coverage tabs for different scenarios
        coverage_scenario_tabs = st.tabs(["Current Coverage", "Recommended Coverage", "Gap Analysis"])
        
        with coverage_scenario_tabs[0]:
            # Generate simulated current coverage data
            current_coverage = {}
            for technique in mitre_data["techniques"]:
                # Random coverage value between 0 and 1
                current_coverage[technique["technique_id"]] = round(random.random(), 2)
            
            # Display the coverage heatmap
            coverage_fig = generate_coverage_heatmap(mitre_data, current_coverage)
            st.plotly_chart(coverage_fig, use_container_width=True, key="coverage_fig")
            
            # Calculate overall statistics
            covered_techniques = sum(1 for v in current_coverage.values() if v >= 0.5)
            total_techniques = len(current_coverage)
            coverage_percentage = (covered_techniques / total_techniques) * 100 if total_techniques > 0 else 0
            
            # Display coverage statistics
            st.metric("Overall Coverage", f"{coverage_percentage:.1f}%", 
                    delta=f"{covered_techniques} of {total_techniques} techniques", 
                    delta_color="normal")
            
        with coverage_scenario_tabs[1]:
            # Generate simulated recommended coverage data (higher than current)
            recommended_coverage = {}
            for technique in mitre_data["techniques"]:
                # Random coverage value between 0.3 and 1
                recommended_coverage[technique["technique_id"]] = round(max(0.3, random.random()), 2)
            
            # Display the coverage heatmap
            recommended_fig = generate_coverage_heatmap(mitre_data, recommended_coverage)
            st.plotly_chart(recommended_fig, use_container_width=True, key="recommended_fig")
            
            # Calculate improvement statistics
            improved_techniques = sum(1 for t_id in recommended_coverage if recommended_coverage[t_id] > current_coverage.get(t_id, 0))
            
            # Display potential improvement message
            st.info(f"Implementing recommended security controls would improve coverage for {improved_techniques} techniques.")
            
        with coverage_scenario_tabs[2]:
            # Identify coverage gaps
            gap_coverage = {}
            critical_gaps = []
            
            for technique in mitre_data["techniques"]:
                t_id = technique["technique_id"]
                current = current_coverage.get(t_id, 0)
                recommended = recommended_coverage.get(t_id, 0)
                
                # Calculate the gap
                gap = max(0, recommended - current)
                gap_coverage[t_id] = gap
                
                # Identify critical gaps (high difference between recommended and current)
                if gap > 0.5:
                    critical_gaps.append((t_id, technique["technique_name"], gap))
            
            # Display the gap heatmap
            gap_fig = generate_coverage_heatmap(mitre_data, gap_coverage)
            st.plotly_chart(gap_fig, use_container_width=True, key="gap_fig")
            
            # Display critical gaps
            if critical_gaps:
                st.subheader("Critical Coverage Gaps")
                for t_id, t_name, gap in sorted(critical_gaps, key=lambda x: x[2], reverse=True)[:5]:
                    st.warning(f"**{t_id}: {t_name}** - Coverage gap: {gap:.2f}")
            else:
                st.success("No critical coverage gaps identified.")
    
    with tabs[2]:
        st.subheader("Techniques Explorer")
        
        # Create a dataframe of techniques
        techniques_df = pd.DataFrame(mitre_data["techniques"])
        
        # Add tactic names to the dataframe
        tactic_map = {t["tactic_id"]: t["tactic_name"] for t in mitre_data["tactics"]}
        techniques_df["tactic_name"] = techniques_df["tactic_id"].map(tactic_map)
        
        # Filter options
        st.markdown("#### Filter Techniques")
        
        col1, col2 = st.columns(2)
        
        with col1:
            selected_tactics = st.multiselect(
                "Filter by Tactic",
                options=list(tactic_map.values()),
                default=[]
            )
        
        with col2:
            search_term = st.text_input("Search Techniques", "")
        
        # Apply filters
        filtered_df = techniques_df
        
        if selected_tactics:
            filtered_df = filtered_df[filtered_df["tactic_name"].isin(selected_tactics)]
        
        if search_term:
            search_term = search_term.lower()
            filtered_df = filtered_df[
                filtered_df["technique_name"].str.lower().str.contains(search_term) |
                filtered_df["description"].str.lower().str.contains(search_term) |
                filtered_df["technique_id"].str.lower().str.contains(search_term)
            ]
        
        # Display filtered techniques
        st.markdown(f"#### Found {len(filtered_df)} Techniques")
        
        if not filtered_df.empty:
            # Create an expander for each technique
            for _, technique in filtered_df.iterrows():
                with st.expander(f"{technique['technique_id']} - {technique['technique_name']}"):
                    st.markdown(f"**Tactic**: {technique['tactic_name']} ({technique['tactic_id']})")
                    st.markdown(f"**Description**: {technique['description']}")
                    
                    # Find parent-child relationships
                    if "." in technique["technique_id"]:
                        # This is a sub-technique
                        parent_id = technique["technique_id"].split(".")[0]
                        parent = techniques_df[techniques_df["technique_id"] == parent_id]
                        if not parent.empty:
                            st.markdown(f"**Parent Technique**: {parent_id} - {parent.iloc[0]['technique_name']}")
                    else:
                        # This might be a parent technique
                        sub_techniques = techniques_df[
                            techniques_df["technique_id"].str.startswith(f"{technique['technique_id']}.")
                        ]
                        if not sub_techniques.empty:
                            st.markdown("**Sub-Techniques**:")
                            for _, sub in sub_techniques.iterrows():
                                st.markdown(f"- {sub['technique_id']} - {sub['technique_name']}")
        else:
            st.info("No techniques found matching the filters")
    
    with tabs[2]:
        # Show ML-based TTP prediction
        predict_ttps_in_mitre_attack()
