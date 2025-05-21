import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import io
import base64
from datetime import datetime
import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

def create_pdf_report(report_data):
    """Create a PDF report with ReportLab"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        alignment=1,  # Center alignment
        spaceAfter=12
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Heading2'],
        alignment=0,  # Left alignment
        spaceAfter=6
    )
    
    normal_style = styles["Normal"]
    
    # Title
    elements.append(Paragraph(f"Security Intelligence Report", title_style))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d')}", styles["Italic"]))
    elements.append(Spacer(1, 0.2 * inch))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", subtitle_style))
    elements.append(Paragraph(report_data["executive_summary"], normal_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    # Threat Intelligence
    elements.append(Paragraph("Threat Intelligence", subtitle_style))
    
    # TTPs in tabular format
    if report_data["ttps"]:
        elements.append(Paragraph("MITRE ATT&CK Techniques Identified:", styles["Heading4"]))
        
        # Create table data
        ttp_table_data = [["Technique ID", "Technique Name"]]
        for ttp_id, ttp_name in report_data["ttps"].items():
            ttp_table_data.append([ttp_id, ttp_name])
        
        # Create table
        ttp_table = Table(ttp_table_data, colWidths=[1.5 * inch, 4.5 * inch])
        ttp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(ttp_table)
        elements.append(Spacer(1, 0.2 * inch))
    
    # IOCs in tabular format
    elements.append(Paragraph("Indicators of Compromise:", styles["Heading4"]))
    
    ioc_types = {
        "IP Addresses": report_data["iocs"].get("ip_addresses", []),
        "Domains": report_data["iocs"].get("domains", []),
        "URLs": report_data["iocs"].get("urls", []),
        "MD5 Hashes": report_data["iocs"].get("md5_hashes", []),
        "SHA1 Hashes": report_data["iocs"].get("sha1_hashes", []),
        "SHA256 Hashes": report_data["iocs"].get("sha256_hashes", [])
    }
    
    for ioc_type, ioc_values in ioc_types.items():
        if ioc_values:
            elements.append(Paragraph(ioc_type, styles["Heading4"]))
            
            # Create table data
            ioc_table_data = [["#", "Indicator"]]
            for i, ioc in enumerate(ioc_values):
                ioc_table_data.append([str(i + 1), ioc])
            
            # Create table
            ioc_table = Table(ioc_table_data, colWidths=[0.5 * inch, 5.5 * inch])
            ioc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(ioc_table)
            elements.append(Spacer(1, 0.1 * inch))
    
    # Recommendations
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph("Recommendations", subtitle_style))
    
    for i, recommendation in enumerate(report_data["recommendations"]):
        elements.append(Paragraph(f"{i+1}. {recommendation}", normal_style))
    
    # Build PDF
    doc.build(elements)
    
    return buffer

def get_download_link(buffer, filename):
    """Generate a download link for the PDF"""
    buffer.seek(0)
    b64 = base64.b64encode(buffer.read()).decode()
    return f'<a href="data:application/pdf;base64,{b64}" download="{filename}">Download {filename}</a>'

def show_report_generation():
    """Display the report generation page"""
    st.title("📄 Security Report Generation")
    
    st.markdown("""
    Generate comprehensive security reports with findings, indicators, and recommendations.
    The reports can be downloaded as PDF documents for sharing with stakeholders.
    """)
    
    # Create the report form
    with st.form("report_generation_form"):
        # Report details
        st.subheader("Report Details")
        
        report_title = st.text_input("Report Title", "Security Intelligence Report")
        
        # Executive summary
        st.subheader("Executive Summary")
        
        executive_summary = st.text_area(
            "Executive Summary",
            "This report provides an analysis of recent security threats and indicators of compromise "
            "identified during our investigation. The findings include malicious IP addresses, domains, "
            "and MITRE ATT&CK techniques used by threat actors. Based on these findings, we provide "
            "actionable recommendations to enhance security posture."
        )
        
        # Threat intelligence
        st.subheader("Threat Intelligence")
        
        # Indicators of Compromise
        st.subheader("Indicators of Compromise (IOCs)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            ip_addresses = st.text_area("IP Addresses (one per line)", 
                                       "192.168.1.100\n203.0.113.25")
            domains = st.text_area("Domains (one per line)", 
                                   "malicious-domain.com\nfakeupdates.net")
        
        with col2:
            urls = st.text_area("URLs (one per line)", 
                               "https://malicious-domain.com/download.php\nhttp://fakeupdates.net/update.exe")
            file_hashes = st.text_area("File Hashes (one per line, MD5/SHA1/SHA256)", 
                                      "d41d8cd98f00b204e9800998ecf8427e\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        
        # TTPs
        st.subheader("Tactics, Techniques, and Procedures (TTPs)")
        
        ttp_options = {
            "T1566": "Phishing",
            "T1566.001": "Spearphishing Attachment",
            "T1566.002": "Spearphishing Link",
            "T1190": "Exploit Public-Facing Application",
            "T1133": "External Remote Services",
            "T1078": "Valid Accounts",
            "T1110": "Brute Force",
            "T1110.003": "Password Spraying",
            "T1110.004": "Credential Stuffing",
            "T1083": "File and Directory Discovery",
            "T1046": "Network Service Scanning",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1567": "Exfiltration Over Web Service",
            "T1567.002": "Exfiltration to Cloud Storage"
        }
        
        selected_ttps = st.multiselect(
            "Select Observed TTPs",
            options=list(ttp_options.keys()),
            default=["T1566", "T1190"],
            format_func=lambda x: f"{x} - {ttp_options[x]}"
        )
        
        # Recommendations
        st.subheader("Recommendations")
        
        recommendations = st.text_area(
            "Recommendations (one per line)",
            "Block the identified malicious IP addresses at the firewall level.\n"
            "Add the malicious domains to your DNS blocklist.\n"
            "Implement email filtering to block phishing attempts.\n"
            "Deploy multi-factor authentication to mitigate credential stuffing attacks.\n"
            "Update all public-facing applications to prevent exploitation of vulnerabilities."
        )
        
        # Submit button
        submit_button = st.form_submit_button("Generate Report")
    
    # Process form submission
    if submit_button:
        # Parse and validate inputs
        parsed_ips = [ip.strip() for ip in ip_addresses.split("\n") if ip.strip()]
        parsed_domains = [domain.strip() for domain in domains.split("\n") if domain.strip()]
        parsed_urls = [url.strip() for url in urls.split("\n") if url.strip()]
        parsed_recommendations = [rec.strip() for rec in recommendations.split("\n") if rec.strip()]
        
        # Parse hashes and categorize by length
        md5_hashes = []
        sha1_hashes = []
        sha256_hashes = []
        
        for hash_value in [h.strip() for h in file_hashes.split("\n") if h.strip()]:
            if len(hash_value) == 32:  # MD5
                md5_hashes.append(hash_value)
            elif len(hash_value) == 40:  # SHA1
                sha1_hashes.append(hash_value)
            elif len(hash_value) == 64:  # SHA256
                sha256_hashes.append(hash_value)
        
        # Create TTPs dictionary
        selected_ttp_dict = {ttp_id: ttp_options[ttp_id] for ttp_id in selected_ttps}
        
        # Combine data for report
        report_data = {
            "title": report_title,
            "executive_summary": executive_summary,
            "iocs": {
                "ip_addresses": parsed_ips,
                "domains": parsed_domains,
                "urls": parsed_urls,
                "md5_hashes": md5_hashes,
                "sha1_hashes": sha1_hashes,
                "sha256_hashes": sha256_hashes
            },
            "ttps": selected_ttp_dict,
            "recommendations": parsed_recommendations
        }
        
        # Generate PDF report
        with st.spinner("Generating PDF report..."):
            pdf_buffer = create_pdf_report(report_data)
            st.success("Report generated successfully!")
            
            # Create download link
            report_filename = f"{report_title.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
            st.markdown(get_download_link(pdf_buffer, report_filename), unsafe_allow_html=True)
        
        # Display report preview
        st.subheader("Report Preview")
        
        # Create tabs for different sections
        preview_tabs = st.tabs(["Executive Summary", "Indicators of Compromise", "TTPs", "Recommendations"])
        
        with preview_tabs[0]:
            st.write(executive_summary)
        
        with preview_tabs[1]:
            # Display IOCs in tables
            if parsed_ips:
                st.write("IP Addresses:")
                st.table(pd.DataFrame({"IP Address": parsed_ips}))
            
            if parsed_domains:
                st.write("Domains:")
                st.table(pd.DataFrame({"Domain": parsed_domains}))
            
            if parsed_urls:
                st.write("URLs:")
                st.table(pd.DataFrame({"URL": parsed_urls}))
            
            if md5_hashes or sha1_hashes or sha256_hashes:
                st.write("File Hashes:")
                hash_data = []
                for h in md5_hashes:
                    hash_data.append({"Type": "MD5", "Hash": h})
                for h in sha1_hashes:
                    hash_data.append({"Type": "SHA1", "Hash": h})
                for h in sha256_hashes:
                    hash_data.append({"Type": "SHA256", "Hash": h})
                
                st.table(pd.DataFrame(hash_data))
        
        with preview_tabs[2]:
            if selected_ttp_dict:
                ttp_df = pd.DataFrame([
                    {"Technique ID": ttp_id, "Technique Name": ttp_name}
                    for ttp_id, ttp_name in selected_ttp_dict.items()
                ])
                
                st.table(ttp_df)
                
                # TTP visualization
                st.subheader("TTP Visualization")
                fig = px.bar(
                    ttp_df, x="Technique ID", y=[1] * len(ttp_df),
                    color="Technique ID",
                    labels={"y": "Observed", "Technique ID": "MITRE ATT&CK Technique"},
                    title="Observed MITRE ATT&CK Techniques"
                )
                st.plotly_chart(fig, use_container_width=True, key="report_fig")
        
        with preview_tabs[3]:
            for i, recommendation in enumerate(parsed_recommendations):
                st.write(f"{i+1}. {recommendation}")
