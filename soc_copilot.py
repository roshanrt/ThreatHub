import streamlit as st
import pandas as pd
import json
import re
import os
from datetime import datetime
from live_data_fetcher import fetch_virustotal_data
from threat_analysis import load_nlp_model, extract_iocs_from_text, extract_ttps_from_text
from mitre_attack import load_mitre_attack_data

def load_threat_knowledge_base():
    """
    Load threat intelligence knowledge base for the SOC Copilot.
    """
    # Load MITRE ATT&CK data as the foundation of our knowledge base
    mitre_data = load_mitre_attack_data()
    
    # Create a dictionary of techniques for quick lookup
    techniques = {}
    for technique in mitre_data["techniques"]:
        techniques[technique["technique_id"]] = {
            "name": technique["technique_name"],
            "tactic_id": technique["tactic_id"],
            "description": technique["description"]
        }
    
    # Create a dictionary of tactics for quick lookup
    tactics = {}
    for tactic in mitre_data["tactics"]:
        tactics[tactic["tactic_id"]] = {
            "name": tactic["tactic_name"],
            "description": tactic["description"]
        }
    
    # Common threat actor profiles
    threat_actors = {
        "APT29": {
            "name": "APT29 (Cozy Bear)",
            "attribution": "Russia",
            "motivation": "Espionage",
            "target_sectors": ["Government", "Diplomatic", "Think Tanks", "Healthcare"],
            "common_techniques": ["T1566.001", "T1078", "T1059.003", "T1027"],
            "description": "APT29 is a sophisticated threat group attributed to Russian intelligence services. They are known for spearphishing campaigns and custom malware."
        },
        "APT28": {
            "name": "APT28 (Fancy Bear)",
            "attribution": "Russia",
            "motivation": "Espionage, Information Operations",
            "target_sectors": ["Government", "Military", "Defense", "Journalism"],
            "common_techniques": ["T1566.002", "T1190", "T1055", "T1027"],
            "description": "APT28 is a Russian state-sponsored threat group known for targeted phishing campaigns and exploiting vulnerabilities in public-facing applications."
        },
        "Lazarus Group": {
            "name": "Lazarus Group",
            "attribution": "North Korea",
            "motivation": "Financial Gain, Espionage",
            "target_sectors": ["Financial", "Cryptocurrency", "Defense"],
            "common_techniques": ["T1566", "T1190", "T1059.003", "T1048"],
            "description": "Lazarus Group is a North Korean state-sponsored threat group known for financially motivated attacks including cryptocurrency theft and bank heists."
        },
        "APT41": {
            "name": "APT41",
            "attribution": "China",
            "motivation": "Espionage, Financial Gain",
            "target_sectors": ["Technology", "Healthcare", "Telecommunications"],
            "common_techniques": ["T1195.002", "T1190", "T1133", "T1078"],
            "description": "APT41 is a Chinese state-sponsored threat group that conducts espionage operations and financially motivated attacks, known for supply chain compromises."
        },
        "FIN7": {
            "name": "FIN7",
            "attribution": "Criminal",
            "motivation": "Financial Gain",
            "target_sectors": ["Retail", "Hospitality", "Restaurant"],
            "common_techniques": ["T1566.001", "T1204.002", "T1059.001", "T1027"],
            "description": "FIN7 is a financially motivated threat group targeting payment card data from point-of-sale systems, primarily in retail and hospitality sectors."
        }
    }
    
    # Common malware profiles
    malware_profiles = {
        "Cobalt Strike": {
            "type": "Commercial Penetration Testing Tool",
            "capabilities": ["C2", "Lateral Movement", "Credential Theft"],
            "common_techniques": ["T1059.003", "T1055", "T1021.002", "T1003"],
            "description": "Cobalt Strike is a commercial penetration testing tool that is frequently misused by threat actors for post-exploitation activities."
        },
        "Emotet": {
            "type": "Banking Trojan / Loader",
            "capabilities": ["Infection Vector", "Credential Theft", "Malware Delivery"],
            "common_techniques": ["T1566.001", "T1027", "T1059.003", "T1078"],
            "description": "Emotet is a modular banking Trojan that functions as a downloader for other malware and is primarily spread through phishing emails."
        },
        "Trickbot": {
            "type": "Banking Trojan / Loader",
            "capabilities": ["Credential Theft", "System Reconnaissance", "Banking Fraud"],
            "common_techniques": ["T1566", "T1059.003", "T1003", "T1057"],
            "description": "Trickbot is a banking Trojan that steals financial data and credentials, and can also act as a delivery mechanism for ransomware."
        },
        "Conti": {
            "type": "Ransomware",
            "capabilities": ["Data Encryption", "Data Exfiltration", "Extortion"],
            "common_techniques": ["T1486", "T1048", "T1082", "T1083"],
            "description": "Conti is a ransomware variant operated as a Ransomware-as-a-Service (RaaS) model, known for double-extortion tactics."
        },
        "Ryuk": {
            "type": "Ransomware",
            "capabilities": ["Data Encryption", "Persistence", "Anti-Recovery"],
            "common_techniques": ["T1486", "T1489", "T1490", "T1136"],
            "description": "Ryuk is a sophisticated ransomware that targets large organizations and is often deployed after initial compromise by other malware."
        }
    }
    
    # Return the complete knowledge base
    return {
        "techniques": techniques,
        "tactics": tactics,
        "threat_actors": threat_actors,
        "malware": malware_profiles
    }

def load_profiles(profile_path="data_resources/threat_profiles.json"):
    if os.path.exists(profile_path):
        with open(profile_path, "r") as f:
            return json.load(f)
    return {"actors": {}, "malware": {}}

def extract_iocs(text):
    # Simple regexes for IP, domain, hash
    ip_re = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    domain_re = r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b"
    hash_re = r"\b[a-fA-F0-9]{32,64}\b"
    ips = re.findall(ip_re, text)
    domains = [d for d in re.findall(domain_re, text) if not d[0].isdigit()]
    hashes = re.findall(hash_re, text)
    return {"ips": ips, "domains": domains, "hashes": hashes}

def enrich_ioc(ioc, vt_api_key):
    # Only call VT if key is set
    if not vt_api_key:
        return None
    return fetch_virustotal_data(vt_api_key, ioc)

def process_analyst_query(query, knowledge_base):
    """
    Process an analyst query and provide relevant threat intelligence.
    
    Args:
        query: The analyst's query text
        knowledge_base: The threat intelligence knowledge base
        
    Returns:
        Dictionary with response information
    """
    # Load NLP model
    nlp = load_nlp_model()
    
    # Extract potential IOCs and TTPs from the query
    iocs = extract_iocs_from_text(query, nlp)
    ttps = extract_ttps_from_text(query)
    
    # Look for mentions of threat actors
    mentioned_actors = []
    for actor_id, actor_info in knowledge_base["threat_actors"].items():
        if actor_id.lower() in query.lower() or actor_info["name"].lower() in query.lower():
            mentioned_actors.append(actor_id)
    
    # Look for mentions of malware
    mentioned_malware = []
    for malware_id, malware_info in knowledge_base["malware"].items():
        if malware_id.lower() in query.lower():
            mentioned_malware.append(malware_id)
    
    # Construct a response
    response = {
        "query": query,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "extracted_iocs": iocs,
        "extracted_ttps": ttps,
        "mentioned_actors": mentioned_actors,
        "mentioned_malware": mentioned_malware,
        "response_text": generate_copilot_response(query, iocs, ttps, mentioned_actors, mentioned_malware, knowledge_base)
    }
    
    return response

def generate_copilot_response(query, profiles, vt_api_key):
    # 1. Threat actor/malware profile lookup
    matched_profiles = []
    q_lower = query.lower()
    for name, profile in profiles.get("actors", {}).items():
        if name.lower() in q_lower:
            matched_profiles.append(("Threat Actor", name, profile))
    for name, profile in profiles.get("malware", {}).items():
        if name.lower() in q_lower:
            matched_profiles.append(("Malware", name, profile))
    # 2. IOC extraction and enrichment
    iocs = extract_iocs(query)
    ioc_analysis = []
    for ioc_type in ["ips", "domains", "hashes"]:
        for ioc in iocs[ioc_type]:
            vt_result = enrich_ioc(ioc, vt_api_key)
            ioc_analysis.append({"type": ioc_type[:-1], "value": ioc, "vt": vt_result})
    # 3. Format response
    response = []
    if matched_profiles:
        response.append("### Threat Profile(s)\n")
        for ptype, name, profile in matched_profiles:
            response.append(f"**{ptype}: {name}**\n" + "\n".join([f"- {k}: {v}" for k, v in profile.items()]))
    if ioc_analysis:
        response.append("\n### IOC Analysis\n")
        for ioc in ioc_analysis:
            vt = ioc["vt"]
            vt_summary = f" (VirusTotal: {vt['data']['attributes']['last_analysis_stats']} )" if vt and vt.get('data') else " (No VT data)"
            response.append(f"- {ioc['type'].upper()}: {ioc['value']}{vt_summary}")
    if not matched_profiles and not ioc_analysis:
        response.append("No threat profile or IOC found. Please rephrase or provide more details.")
    response.append("\n### Recommendation\n- Review the above context and investigate further as needed.")
    return "\n".join(response)

def show_chat_history(chat_history):
    """
    Display the chat history in the Streamlit UI.
    
    Args:
        chat_history: List of chat messages
    """
    for message in chat_history:
        if message["role"] == "user":
            st.chat_message("user").write(message["content"])
        else:
            with st.chat_message("assistant"):
                st.markdown(message["content"])

def show_soc_copilot():
    """Display the SOC Copilot interface"""
    st.title("🤖 SOC Copilot")
    
    st.markdown("""
    The SOC Copilot provides AI-driven support for security analysts. Ask questions about
    threat actors, TTPs, or IOCs to get contextual information and intelligence.
    """)
    
    # Initialize chat history in session state if it doesn't exist
    if "soc_chat_history" not in st.session_state:
        st.session_state.soc_chat_history = []
    
    # Initialize the knowledge base in session state if it doesn't exist
    if "soc_knowledge_base" not in st.session_state:
        st.session_state.soc_knowledge_base = load_threat_knowledge_base()
    
    # Securely load VT API key (from env or config, not UI)
    vt_api_key = os.environ.get("VT_API_KEY")
    profiles = load_profiles()
    
    # Create tabs for different interaction modes
    chat_tab, queries_tab, debug_tab = st.tabs(["Chat Interface", "Example Queries", "Knowledge Base"])
    
    with chat_tab:
        # Display chat history
        show_chat_history(st.session_state.soc_chat_history)
        
        # Chat input
        if query := st.chat_input("Ask about threats, actors, or IOCs..."):
            # Add user message to chat history
            st.session_state.soc_chat_history.append({"role": "user", "content": query})
            
            # Display user message
            st.chat_message("user").write(query)
            
            # Process the query and get response
            with st.spinner("Analyzing..."):
                response = process_analyst_query(query, st.session_state.soc_knowledge_base)
                
                # Display assistant response
                with st.chat_message("assistant"):
                    st.markdown(response["response_text"])
                
                # Add assistant response to chat history
                st.session_state.soc_chat_history.append({"role": "assistant", "content": response["response_text"]})
    
    with queries_tab:
        st.subheader("Example Queries")
        
        st.markdown("""
        Try these example queries to see the capabilities of the SOC Copilot:
        
        **Threat Actor Information:**
        - Tell me about APT29
        - What techniques does Lazarus Group use?
        - What sectors does FIN7 target?
        
        **TTP Information:**
        - What is T1566.001?
        - Tell me about Spearphishing Attachment
        - How can I detect T1078 (Valid Accounts)?
        
        **IOC Enrichment:**
        - Check this IP: 203.0.113.1
        - Enrich this domain: malicious-domain.com
        - Look up this hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        
        **TTP Attribution:**
        - Correlate these TTPs: T1566.001, T1078
        - Who might use techniques T1190 and T1133?
        - Attribute these techniques: T1059.003, T1027, T1055
        """)
        
        # Add example query buttons
        example_queries = [
            "Tell me about APT29",
            "What is T1566.001?",
            "Check this IP: 203.0.113.1",
            "Correlate these TTPs: T1566.001, T1078"
        ]
        
        for query in example_queries:
            if st.button(query, key=f"example_{hash(query)}"):
                # Add to chat history and rerun to process
                st.session_state.soc_chat_history.append({"role": "user", "content": query})
                st.rerun()
    
    with debug_tab:
        st.subheader("Knowledge Base Overview")
        
        st.markdown("""
        This tab shows the available threat intelligence in the knowledge base.
        """)
        
        # Show available threat actors
        with st.expander("Threat Actors"):
            actors_df = pd.DataFrame([
                {
                    "ID": actor_id,
                    "Name": actor_info["name"],
                    "Attribution": actor_info["attribution"],
                    "Motivation": actor_info["motivation"],
                    "Target Sectors": ", ".join(actor_info["target_sectors"])
                }
                for actor_id, actor_info in st.session_state.soc_knowledge_base["threat_actors"].items()
            ])
            st.dataframe(actors_df)
        
        # Show available malware
        with st.expander("Malware Profiles"):
            malware_df = pd.DataFrame([
                {
                    "Name": malware_id,
                    "Type": malware_info["type"],
                    "Capabilities": ", ".join(malware_info["capabilities"])
                }
                for malware_id, malware_info in st.session_state.soc_knowledge_base["malware"].items()
            ])
            st.dataframe(malware_df)
        
        # Show MITRE ATT&CK statistics
        with st.expander("MITRE ATT&CK Coverage"):
            tactics_count = len(st.session_state.soc_knowledge_base["tactics"])
            techniques_count = len(st.session_state.soc_knowledge_base["techniques"])
            
            st.metric("Tactics", tactics_count)
            st.metric("Techniques", techniques_count)
            
            # Display selected techniques
            selected_techniques = list(st.session_state.soc_knowledge_base["techniques"].items())[:10]

            techniques_overview_df = pd.DataFrame([
                {
                    "Technique ID": technique_id,
                    "Name": technique_info["name"],
                    "Description": technique_info["description"][:100] + "..."
                }
                for technique_id, technique_info in selected_techniques
            ])
            st.write("Current Attack Techniques:")
            st.dataframe(techniques_overview_df)