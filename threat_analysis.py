# Improved code for better readability, maintainability, and performance
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
    """Load the spaCy NLP model for entity extraction."""
    try:
        return spacy.load("en_core_web_sm")
    except:
        import spacy.cli
        spacy.cli.download("en_core_web_sm")
        return spacy.load("en_core_web_sm")

def extract_iocs_from_text(text, nlp):
    """Extract indicators of compromise (IOCs) from text using regex and NLP."""
    # Patterns for common IOCs
    patterns = {
        "ip_addresses": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "domains": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        "md5_hashes": r'\b[a-fA-F0-9]{32}\b',
        "sha1_hashes": r'\b[a-fA-F0-9]{40}\b',
        "sha256_hashes": r'\b[a-fA-F0-9]{64}\b',
        "urls": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    }

    # Extract IOCs using regex
    iocs = {key: list(set(re.findall(pattern, text))) for key, pattern in patterns.items()}

    # Extract organizations using NLP
    doc = nlp(text)
    iocs["organizations"] = list(set(ent.text for ent in doc.ents if ent.label_ == "ORG"))

    return iocs

def extract_ttps_from_text(text):
    """Extract TTPs (Tactics, Techniques, and Procedures) from text."""
    # Look for MITRE ATT&CK technique IDs and keywords
    ttp_pattern = r'T\d{4}(?:\.\d{3})?'
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
        "Initial Access": "TA0001",
    }

    # Extract technique IDs and keywords
    ttps = {ttp: f"Technique {ttp}" for ttp in re.findall(ttp_pattern, text)}
    for keyword, technique_id in technique_keywords.items():
        if re.search(rf'\b{re.escape(keyword)}\b', text, re.IGNORECASE):
            ttps[technique_id] = keyword

    return ttps

def process_json_threat_report(file_content):
    """Process a JSON threat report to extract IOCs and TTPs."""
    try:
        data = json.loads(file_content)
        text_content = json.dumps(data)
        nlp = load_nlp_model()
        return {
            "report_type": "json",
            "extracted_iocs": extract_iocs_from_text(text_content, nlp),
            "extracted_ttps": extract_ttps_from_text(text_content),
            "original_data": data,
        }
    except Exception as e:
        st.error(f"Error processing JSON report: {str(e)}")
        return None

def process_pdf_threat_report(file_content):
    """Process a PDF threat report to extract IOCs and TTPs."""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_content))
        text_content = "".join(page.extract_text() for page in pdf_reader.pages)
        nlp = load_nlp_model()
        return {
            "report_type": "pdf",
            "extracted_iocs": extract_iocs_from_text(text_content, nlp),
            "extracted_ttps": extract_ttps_from_text(text_content),
            "text_content": text_content[:1000] + "..." if len(text_content) > 1000 else text_content,
        }
    except PyPDF2.errors.PdfReadError as e:
        st.error(f"Error reading PDF file: {str(e)}")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred while processing the PDF report: {str(e)}")
        return None

def show_extraction_results(extracted_data):
    """Display the extracted IOCs and TTPs."""
    if not extracted_data:
        return

    st.subheader("Extracted Indicators of Compromise (IOCs)")
    iocs = extracted_data["extracted_iocs"]
    ioc_tabs = st.tabs(["IP Addresses", "Domains", "URLs", "Hashes", "Organizations"])

    with ioc_tabs[0]:
        # Ensure the value is a valid JSON serializable object
        ip_addresses = iocs.get("ip_addresses", [])
        if not isinstance(ip_addresses, list):
            ip_addresses = []
        st.json(ip_addresses or "No IP addresses found.")

    with ioc_tabs[1]:
        st.json(iocs["domains"] or "No domains found.")

    with ioc_tabs[2]:
        st.json(iocs["urls"] or "No URLs found.")

    with ioc_tabs[3]:
        all_hashes = [
            ("MD5", h) for h in iocs["md5_hashes"]
        ] + [
            ("SHA1", h) for h in iocs["sha1_hashes"]
        ] + [
            ("SHA256", h) for h in iocs["sha256_hashes"]
        ]
        st.dataframe(pd.DataFrame(all_hashes, columns=["Type", "Hash"]) or "No hashes found.")

    with ioc_tabs[4]:
        st.json(iocs["organizations"] or "No organizations found.")

    st.subheader("Extracted Tactics, Techniques, and Procedures (TTPs)")
    ttps = extracted_data["extracted_ttps"]
    if ttps:
        ttp_df = pd.DataFrame([{ "ID": k, "Name": v } for k, v in ttps.items()])
        st.dataframe(ttp_df)
        st.plotly_chart(px.bar(ttp_df, x="ID", y=ttp_df.index, title="MITRE ATT&CK Techniques Identified"), use_container_width=True, key="ttp_bar_chart")
    else:
        st.info("No MITRE ATT&CK techniques identified.")

def generate_reference_json_report():
    """Generate a reference threat report in JSON format"""
    reference_report = {
        "report_title": "Threat Intelligence Report: APT41 Campaign",
        "report_date": datetime.now().strftime("%Y-%m-%d"),
        "threat_actor": "APT41",
        "confidence_level": "High",
        "summary": "APT41 is conducting a widespread campaign targeting multiple sectors through phishing emails and exploiting vulnerabilities in public-facing applications. The campaign involves domain spoofing, malware distribution, and data exfiltration techniques.",
        "indicators": {
            "ip_addresses": [
                "192.168.1.100",
                "203.0.113.25",
                "198.51.100.75",
            ],
            "domains": [
                "malicious-domain.com",
                "fakeupdates.net",
                "secure-login-portal.com",
            ],
            "hashes": [
                {"type": "MD5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
                {"type": "SHA1", "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
                {"type": "SHA256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            ],
            "urls": [
                "https://malicious-domain.com/download.php",
                "http://fakeupdates.net/update.exe",
            ],
        },
        "techniques_observed": [
            {"id": "T1566", "name": "Phishing", "description": "The threat actor sent phishing emails with malicious attachments."},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "description": "The threat actor exploited vulnerabilities in public-facing web applications."},
            {"id": "T1110.004", "name": "Credential Stuffing", "description": "The threat actor attempted to gain access using credential stuffing attacks."},
            {"id": "T1078", "name": "Valid Accounts", "description": "The threat actor used compromised credentials to maintain access."},
        ],
    }
    return json.dumps(reference_report, indent=2)

def show_threat_analysis():
    """Display the threat analysis page"""
    st.title("🔍 Threat Analysis")

    st.markdown(
        """
    Upload threat reports in JSON or PDF format to automatically extract Indicators of Compromise (IOCs) 
    and MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs).
    """
    )

    # Create tabs for different input methods
    upload_tab, web_tab, reference_tab = st.tabs(["Upload Threat Report", "Web Scraping", "Use Reference Report"])

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

    with web_tab:
        st.subheader("Extract Threat Intelligence from Websites")
        st.markdown(
            """
        Enter a URL of a threat intelligence blog, security advisory, or similar website to extract
        indicators of compromise (IOCs) and MITRE ATT&CK techniques.
        """
        )

        url = st.text_input("Enter website URL", placeholder="https://example.com/threat-report")

        if st.button("Extract Intelligence from Website"):
            if url:
                with st.spinner("Extracting intelligence from website..."):
                    try:
                        # Import here to avoid circular imports
                        from web_scraper import get_website_text_content

                        # Get website content
                        content = get_website_text_content(url)

                        if content:
                            # Extract IOCs and TTPs
                            nlp = load_nlp_model()
                            iocs = extract_iocs_from_text(content, nlp)
                            ttps = extract_ttps_from_text(content)

                            # Create result
                            result = {
                                "report_type": "web",
                                "source_url": url,
                                "extraction_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "extracted_iocs": iocs,
                                "extracted_ttps": ttps,
                                "text_content": content[:1000] + "..." if len(content) > 1000 else content,
                            }

                            st.success(f"Successfully extracted intelligence from {url}")
                            show_extraction_results(result)
                        else:
                            st.error("Failed to extract content from the website. Try a different URL.")
                    except Exception as e:
                        st.error(f"Error processing website: {str(e)}")
            else:
                st.warning("Please enter a valid URL.")

    with reference_tab:
        st.info("Using a reference threat report for validation and review.")
        reference_json = generate_reference_json_report()
        if st.button("Process Reference Report"):
            with st.spinner("Processing reference report..."):
                result = process_json_threat_report(reference_json)
                if result:
                    st.success("Successfully processed reference report")
                    show_extraction_results(result)
