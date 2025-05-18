import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import os
from ml_prediction import predict_ttps_in_mitre_attack

def load_mitre_attack_data():
    """Load MITRE ATT&CK data from JSON file"""
    # Check if file exists
    if os.path.exists("sample_data/mitre_attack_techniques.json"):
        with open("sample_data/mitre_attack_techniques.json", "r") as f:
            data = json.load(f)
        return data
    
    # If file doesn't exist, create sample data
    techniques = {
        "tactics": [
            {"tactic_id": "TA0001", "tactic_name": "Initial Access", "description": "The initial access tactic represents techniques that adversaries use to gain an initial foothold within a network."},
            {"tactic_id": "TA0002", "tactic_name": "Execution", "description": "The execution tactic represents techniques that result in execution of adversary-controlled code on a local or remote system."},
            {"tactic_id": "TA0003", "tactic_name": "Persistence", "description": "The persistence tactic contains techniques that adversaries use to maintain access to systems across restarts, changed credentials, and other interruptions."},
            {"tactic_id": "TA0004", "tactic_name": "Privilege Escalation", "description": "The privilege escalation tactic contains techniques that adversaries use to gain higher-level permissions on a system or network."},
            {"tactic_id": "TA0005", "tactic_name": "Defense Evasion", "description": "The defense evasion tactic consists of techniques that adversaries use to avoid detection throughout their compromise."},
            {"tactic_id": "TA0006", "tactic_name": "Credential Access", "description": "The credential access tactic represents techniques used by adversaries to steal credentials like account names and passwords."},
            {"tactic_id": "TA0007", "tactic_name": "Discovery", "description": "The discovery tactic contains techniques that adversaries use to gain knowledge about the system and network."},
            {"tactic_id": "TA0008", "tactic_name": "Lateral Movement", "description": "The lateral movement tactic contains techniques that adversaries use to enter and control remote systems on a network."},
            {"tactic_id": "TA0009", "tactic_name": "Collection", "description": "The collection tactic contains techniques used to gather information and sources of information of interest to the adversary."},
            {"tactic_id": "TA0010", "tactic_name": "Exfiltration", "description": "The exfiltration tactic refers to techniques that adversaries may use to steal data from your network."},
            {"tactic_id": "TA0011", "tactic_name": "Command and Control", "description": "The command and control tactic represents how adversaries communicate with systems under their control within a victim network."},
            {"tactic_id": "TA0040", "tactic_name": "Impact", "description": "The impact tactic consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes."}
        ],
        "techniques": [
            {"technique_id": "T1566", "technique_name": "Phishing", "tactic_id": "TA0001", "description": "Adversaries may send phishing messages to gain access to victim systems."},
            {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic_id": "TA0001", "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems."},
            {"technique_id": "T1566.002", "technique_name": "Spearphishing Link", "tactic_id": "TA0001", "description": "Adversaries may send spearphishing emails with a link to a malicious website in an attempt to gain access to victim systems."},
            {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic_id": "TA0001", "description": "Adversaries may attempt to exploit public-facing applications to gain initial access."},
            {"technique_id": "T1133", "technique_name": "External Remote Services", "tactic_id": "TA0001", "description": "Adversaries may leverage external remote services as a point of initial access."},
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic_id": "TA0001", "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access."},
            {"technique_id": "T1110", "technique_name": "Brute Force", "tactic_id": "TA0006", "description": "Adversaries may use brute force techniques to gain access to accounts."},
            {"technique_id": "T1110.003", "technique_name": "Password Spraying", "tactic_id": "TA0006", "description": "Adversaries may use a password spraying technique for authentication brute force."},
            {"technique_id": "T1110.004", "technique_name": "Credential Stuffing", "tactic_id": "TA0006", "description": "Adversaries may use stolen credential lists to attempt to gain access to victim systems."},
            {"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic_id": "TA0007", "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information."},
            {"technique_id": "T1046", "technique_name": "Network Service Scanning", "tactic_id": "TA0007", "description": "Adversaries may scan for services running on hosts to find opportunities for lateral movement or information gathering."},
            {"technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "tactic_id": "TA0010", "description": "Adversaries may exfiltrate data using a different protocol than that of the existing command and control channel."},
            {"technique_id": "T1567", "technique_name": "Exfiltration Over Web Service", "tactic_id": "TA0010", "description": "Adversaries may use an existing, legitimate web service to exfiltrate data."},
            {"technique_id": "T1567.002", "technique_name": "Exfiltration to Cloud Storage", "tactic_id": "TA0010", "description": "Adversaries may exfiltrate data to a cloud storage service."},
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic_id": "TA0002", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."},
            {"technique_id": "T1053", "technique_name": "Scheduled Task/Job", "tactic_id": "TA0003", "description": "Adversaries may use scheduled tasks to maintain persistence and execute programs at system startup or at specific times."},
            {"technique_id": "T1055", "technique_name": "Process Injection", "tactic_id": "TA0004", "description": "Adversaries may inject code into processes to evade process-based defenses and potentially elevate privileges."},
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "tactic_id": "TA0005", "description": "Adversaries may use obfuscation to hide artifacts of an intrusion from analysis."},
            {"technique_id": "T1021", "technique_name": "Remote Services", "tactic_id": "TA0008", "description": "Adversaries may use remote services to move laterally within a network."},
            {"technique_id": "T1114", "technique_name": "Email Collection", "tactic_id": "TA0009", "description": "Adversaries may collect emails from victims to gather information."}
        ]
    }
    
    # Save the data
    os.makedirs("sample_data", exist_ok=True)
    with open("sample_data/mitre_attack_techniques.json", "w") as f:
        json.dump(techniques, f, indent=2)
    
    return techniques

def generate_mitre_matrix(techniques_data):
    """Generate a MITRE ATT&CK matrix"""
    tactics = techniques_data["tactics"]
    techniques = techniques_data["techniques"]
    
    # Create a dataframe for the heatmap
    tactic_ids = [tactic["tactic_id"] for tactic in tactics]
    tactic_names = [tactic["tactic_name"] for tactic in tactics]
    
    # Create a mapping from tactic_id to column index
    tactic_to_col = {tactic_id: i for i, tactic_id in enumerate(tactic_ids)}
    
    # Initialize the matrix with zeros
    matrix = np.zeros((len(techniques), len(tactics)))
    
    # Fill the matrix
    for i, technique in enumerate(techniques):
        tactic_id = technique["tactic_id"]
        if tactic_id in tactic_to_col:
            col_idx = tactic_to_col[tactic_id]
            matrix[i, col_idx] = 1
    
    # Create the heatmap
    fig = go.Figure(data=go.Heatmap(
        z=matrix,
        x=tactic_names,
        y=[t["technique_name"] for t in techniques],
        colorscale=[[0, 'white'], [1, 'rgb(17, 119, 51)']],
        showscale=False
    ))
    
    fig.update_layout(
        title="MITRE ATT&CK Matrix",
        xaxis=dict(title="Tactics"),
        yaxis=dict(title="Techniques"),
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
    tabs = st.tabs(["ATT&CK Matrix", "Techniques Explorer", "TTP Trend Prediction"])
    
    with tabs[0]:
        st.subheader("MITRE ATT&CK Matrix")
        
        st.markdown("""
        The ATT&CK Matrix provides a visual representation of the tactics and techniques used by 
        adversaries. Each cell represents a specific technique associated with a tactic.
        """)
        
        # Display the ATT&CK matrix
        matrix_fig = generate_mitre_matrix(mitre_data)
        st.plotly_chart(matrix_fig, use_container_width=True)
    
    with tabs[1]:
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
