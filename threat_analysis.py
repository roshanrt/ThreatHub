import streamlit as st
import pandas as pd
import json
import re
import io
import base64
from datetime import datetime
import PyPDF2
import spacy
import plotly.express as px
import plotly.graph_objects as go
from web_scraper import process_website_content, save_website_report

# Load NLP model for entity extraction
@st.cache_resource
def load_nlp_model():
    try:
        return spacy.load("en_core_web_sm")
    except:
        import spacy.cli
        spacy.cli.download("en_core_web_sm")
        return spacy.load("en_core_web_sm")

def extract_iocs_from_text(text, nlp):
    """Extract indicators of compromise from text using NLP"""
    # Patterns for common IOCs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    hash_md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    hash_sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    hash_sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    
    # Extract IOCs using regex
    ips = re.findall(ip_pattern, text)
    domains = re.findall(domain_pattern, text)
    md5_hashes = re.findall(hash_md5_pattern, text)
    sha1_hashes = re.findall(hash_sha1_pattern, text)
    sha256_hashes = re.findall(hash_sha256_pattern, text)
    urls = re.findall(url_pattern, text)
    
    # Extract organizations, software, and other entities using NLP
    doc = nlp(text)
    orgs = [ent.text for ent in doc.ents if ent.label_ == "ORG"]
    
    # Combine all IOCs
    iocs = {
        "ip_addresses": list(set(ips)),
        "domains": list(set(domains)),
        "md5_hashes": list(set(md5_hashes)),
        "sha1_hashes": list(set(sha1_hashes)),
        "sha256_hashes": list(set(sha256_hashes)),
        "urls": list(set(urls)),
        "organizations": list(set(orgs))
    }
    
    return iocs

def extract_ttps_from_text(text):
    """Extract TTPs from text by looking for MITRE ATT&CK technique references"""
    # Look for MITRE ATT&CK technique IDs (e.g., T1566, T1566.001)
    ttp_pattern = r'T\d{4}(?:\.\d{3})?'
    ttps = re.findall(ttp_pattern, text)
    
    # Look for common technique names
    technique_keywords = {
        "Phishing": "T1566",
        "Spearphishing": "T1566.001",
        "Whaling": "T1566.002",
        "Drive-by Compromise": "T1189",
        "Exploit Public-Facing Application": "T1190",
        "Supply Chain Compromise": "T1195",
        "Trusted Relationship": "T1199",
        "Valid Accounts": "T1078",
        "External Remote Services": "T1133",
        "Brute Force": "T1110",
        "Credential Stuffing": "T1110.004",
        "Password Spraying": "T1110.003",
        "Command and Control": "TA0011",
        "Data Exfiltration": "TA0010",
        "Lateral Movement": "TA0008",
        "Privilege Escalation": "TA0004",
        "Defense Evasion": "TA0005",
        "Persistence": "TA0003",
        "Initial Access": "TA0001"
    }
    
    # Check for technique keywords in the text
    detected_techniques = {}
    for keyword, technique_id in technique_keywords.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
            if technique_id not in detected_techniques:
                detected_techniques[technique_id] = keyword
    
    # Combine explicitly mentioned technique IDs with keywords
    for ttp in ttps:
        if ttp not in detected_techniques:
            detected_techniques[ttp] = f"Technique {ttp}"
    
    return detected_techniques

def process_json_threat_report(file_content):
    """Process a JSON threat report to extract IOCs and TTPs"""
    try:
        # Parse JSON content
        data = json.loads(file_content)
        
        # Extract text content from JSON structure
        text_content = json.dumps(data)
        
        # Load NLP model
        nlp = load_nlp_model()
        
        # Extract IOCs and TTPs
        iocs = extract_iocs_from_text(text_content, nlp)
        ttps = extract_ttps_from_text(text_content)
        
        # Create response
        result = {
            "report_type": "json",
            "extracted_iocs": iocs,
            "extracted_ttps": ttps,
            "original_data": data
        }
        
        return result
    
    except Exception as e:
        st.error(f"Error processing JSON report: {str(e)}")
        return None

def process_pdf_threat_report(file_content):
    """Process a PDF threat report to extract IOCs and TTPs"""
    try:
        # Read PDF content
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_content))
        text_content = ""
        
        # Extract text from all pages
        for page_num in range(len(pdf_reader.pages)):
            text_content += pdf_reader.pages[page_num].extract_text()
        
        # Load NLP model
        nlp = load_nlp_model()
        
        # Extract IOCs and TTPs
        iocs = extract_iocs_from_text(text_content, nlp)
        ttps = extract_ttps_from_text(text_content)
        
        # Create response
        result = {
            "report_type": "pdf",
            "extracted_iocs": iocs,
            "extracted_ttps": ttps,
            "text_content": text_content[:1000] + "..." if len(text_content) > 1000 else text_content
        }
        
        return result
    
    except Exception as e:
        st.error(f"Error processing PDF report: {str(e)}")
        return None

def show_extraction_results(extracted_data):
    """Display the extracted IOCs and TTPs"""
    if not extracted_data:
        return
    
    st.subheader("Extracted Indicators of Compromise (IOCs)")
    
    iocs = extracted_data["extracted_iocs"]
    
    # Create tabs for different IOC types
    ioc_tabs = st.tabs(["IP Addresses", "Domains", "URLs", "Hashes", "Organizations"])
    
    with ioc_tabs[0]:
        if iocs["ip_addresses"]:
            st.write(f"Found {len(iocs['ip_addresses'])} IP addresses:")
            st.json(iocs["ip_addresses"])
        else:
            st.info("No IP addresses found in the report")
    
    with ioc_tabs[1]:
        if iocs["domains"]:
            st.write(f"Found {len(iocs['domains'])} domains:")
            st.json(iocs["domains"])
        else:
            st.info("No domains found in the report")
    
    with ioc_tabs[2]:
        if iocs["urls"]:
            st.write(f"Found {len(iocs['urls'])} URLs:")
            st.json(iocs["urls"])
        else:
            st.info("No URLs found in the report")
    
    with ioc_tabs[3]:
        # Combine all hash types
        all_hashes = []
        all_hashes.extend([("MD5", h) for h in iocs["md5_hashes"]])
        all_hashes.extend([("SHA1", h) for h in iocs["sha1_hashes"]])
        all_hashes.extend([("SHA256", h) for h in iocs["sha256_hashes"]])
        
        if all_hashes:
            st.write(f"Found {len(all_hashes)} file hashes:")
            df = pd.DataFrame(all_hashes, columns=["Type", "Hash"])
            st.dataframe(df)
        else:
            st.info("No file hashes found in the report")
    
    with ioc_tabs[4]:
        if iocs["organizations"]:
            st.write(f"Found {len(iocs['organizations'])} organizations:")
            st.json(iocs["organizations"])
        else:
            st.info("No organizations found in the report")
    
    # Display TTPs
    st.subheader("Extracted Tactics, Techniques, and Procedures (TTPs)")
    
    ttps = extracted_data["extracted_ttps"]
    
    if ttps:
        # Create a DataFrame for the TTPs
        ttp_data = []
        for ttp_id, ttp_name in ttps.items():
            ttp_data.append({"ID": ttp_id, "Name": ttp_name})
        
        ttp_df = pd.DataFrame(ttp_data)
        st.dataframe(ttp_df)
        
        # TTP ID distribution chart
        fig = px.bar(
            ttp_df, x="ID", y=ttp_df.index, 
            title="MITRE ATT&CK Techniques Identified",
            labels={"index": "Count", "ID": "Technique ID"},
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No MITRE ATT&CK techniques identified in the report")

def generate_sample_json_report():
    """Generate a sample threat report in JSON format"""
    sample_report = {
        "report_title": "Threat Intelligence Report: APT41 Campaign",
        "report_date": datetime.now().strftime("%Y-%m-%d"),
        "threat_actor": "APT41",
        "confidence_level": "High",
        "summary": "APT41 is conducting a widespread campaign targeting multiple sectors through phishing emails and exploiting vulnerabilities in public-facing applications. The campaign involves domain spoofing, malware distribution, and data exfiltration techniques.",
        "indicators": {
            "ip_addresses": [
                "192.168.1.100",
                "203.0.113.25",
                "198.51.100.75"
            ],
            "domains": [
                "malicious-domain.com",
                "fakeupdates.net",
                "secure-login-portal.com"
            ],
            "hashes": [
                {"type": "MD5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
                {"type": "SHA1", "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
                {"type": "SHA256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            ],
            "urls": [
                "https://malicious-domain.com/download.php",
                "http://fakeupdates.net/update.exe"
            ]
        },
        "techniques_observed": [
            {"id": "T1566", "name": "Phishing", "description": "The threat actor sent phishing emails with malicious attachments."},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "description": "The threat actor exploited vulnerabilities in public-facing web applications."},
            {"id": "T1110.004", "name": "Credential Stuffing", "description": "The threat actor attempted to gain access using credential stuffing attacks."},
            {"id": "T1078", "name": "Valid Accounts", "description": "The threat actor used compromised credentials to maintain access."}
        ]
    }
    
    return json.dumps(sample_report, indent=2)

def show_threat_analysis():
    """Display the threat analysis page"""
    st.title("🔍 Threat Analysis")
    
    st.markdown("""
    Upload threat reports in JSON or PDF format to automatically extract Indicators of Compromise (IOCs) 
    and MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs).
    """)
    
    # Create tabs for different input methods
    upload_tab, sample_tab = st.tabs(["Upload Threat Report", "Use Sample Report"])
    
    with upload_tab:
        uploaded_file = st.file_uploader("Upload a JSON or PDF threat report", type=["json", "pdf"])
        
        if uploaded_file:
            file_content = uploaded_file.getvalue()
            file_extension = uploaded_file.name.split(".")[-1].lower()
            
            with st.spinner("Processing report..."):
                if file_extension == "json":
                    result = process_json_threat_report(file_content)
                elif file_extension == "pdf":
                    result = process_pdf_threat_report(file_content)
                else:
                    st.error("Unsupported file format. Please upload a JSON or PDF file.")
                    result = None
                
                if result:
                    st.success(f"Successfully processed {file_extension.upper()} report")
                    show_extraction_results(result)
    
    with sample_tab:
        st.info("Using a sample threat report for demonstration purposes")
        
        sample_json = generate_sample_json_report()
        
        if st.button("Process Sample Report"):
            with st.spinner("Processing sample report..."):
                result = process_json_threat_report(sample_json)
                
                if result:
                    st.success("Successfully processed sample report")
                    show_extraction_results(result)
