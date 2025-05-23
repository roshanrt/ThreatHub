import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import re
import datetime
import random
from io import StringIO
from threat_analysis import extract_iocs_from_text, extract_ttps_from_text, load_nlp_model, show_extraction_results
import spacy

def process_live_log_data(log_data, log_type="syslog"):
    """
    Process live log data to extract potential threat indicators and TTPs.
    
    Args:
        log_data: String containing log data
        log_type: Type of log (syslog, windows, etc.)
        
    Returns:
        Dictionary with extracted indicators and TTPs
    """
    # Load NLP model
    nlp = load_nlp_model()
    
    # Extract IOCs and TTPs from the log data
    iocs = extract_iocs_from_text(log_data, nlp)
    ttps = extract_ttps_from_text(log_data)
    
    # Create specific log patterns based on log type
    if log_type == "syslog":
        # Look for common attack patterns in syslog
        failed_auth_pattern = r'Failed password for .* from ([\d\.]+)'
        ip_matches = re.findall(failed_auth_pattern, log_data)
        
        if ip_matches:
            for ip in ip_matches:
                if ip not in iocs["ip_addresses"]:
                    iocs["ip_addresses"].append(ip)
            
            if "T1110" not in ttps:  # Brute Force
                ttps["T1110"] = "Brute Force"
    
    elif log_type == "windows":
        # Look for Windows-specific patterns
        logon_failure = r'logon failure.* Source Network Address:\s+([\d\.]+)'
        ip_matches = re.findall(logon_failure, log_data, re.IGNORECASE)
        
        if ip_matches:
            for ip in ip_matches:
                if ip not in iocs["ip_addresses"]:
                    iocs["ip_addresses"].append(ip)
            
            if "T1078" not in ttps:  # Valid Accounts
                ttps["T1078"] = "Valid Accounts"
    
    elif log_type == "web":
        # Look for web attack patterns
        sqli_pattern = r"('|--|;).*SELECT|UPDATE|INSERT|DELETE|DROP|UNION"
        xss_pattern = r"(<script|javascript:|on\w+\s*=)"
        
        if re.search(sqli_pattern, log_data, re.IGNORECASE):
            if "T1190" not in ttps:  # Exploit Public-Facing Application
                ttps["T1190"] = "Exploit Public-Facing Application"
        
        if re.search(xss_pattern, log_data, re.IGNORECASE):
            if "T1059" not in ttps:  # Command and Scripting Interpreter
                ttps["T1059"] = "Command and Scripting Interpreter"
    
    # Create result
    result = {
        "report_type": "live_logs",
        "detection_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_type": log_type,
        "extracted_iocs": iocs,
        "extracted_ttps": ttps,
        "sample_logs": log_data[:500] + "..." if len(log_data) > 500 else log_data
    }
    
    return result

def generate_mitre_recommendations(ttps):
    """
    Generate recommendations based on detected MITRE ATT&CK techniques.
    
    Args:
        ttps: Dictionary of detected TTPs
        
    Returns:
        List of recommendations
    """
    recommendations = []
    
    mitre_recommendations = {
        "T1110": [
            "Implement account lockout policies after multiple failed login attempts",
            "Enable multi-factor authentication where possible",
            "Monitor for login attempts from unusual IP addresses or locations",
            "Use strong password policies and enable account lockout"
        ],
        "T1078": [
            "Audit user accounts regularly and remove unused accounts",
            "Implement least privilege principles for all user accounts",
            "Enable multi-factor authentication for all privileged accounts",
            "Monitor for unusual account activity or access patterns"
        ],
        "T1190": [
            "Keep all public-facing applications patched and updated",
            "Implement a web application firewall (WAF)",
            "Conduct regular vulnerability scans of public-facing assets",
            "Use input validation and sanitization in web applications"
        ],
        "T1059": [
            "Restrict script execution permissions",
            "Implement application whitelisting to control script execution",
            "Monitor for unusual script execution or command-line activity",
            "Use content disarm and reconstruction (CDR) for files from external sources"
        ]
    }
    
    # Generate general recommendations if no specific TTPs are detected
    if not ttps:
        return [
            "Implement defense-in-depth security measures",
            "Keep all systems and applications updated with security patches",
            "Enable logging and monitoring across all critical systems",
            "Develop and regularly test an incident response plan"
        ]
    
    # Add specific recommendations based on detected TTPs
    for ttp_id in ttps.keys():
        if ttp_id in mitre_recommendations:
            # Add 2 random recommendations for each detected TTP
            ttp_recs = random.sample(mitre_recommendations[ttp_id], min(2, len(mitre_recommendations[ttp_id])))
            recommendations.extend(ttp_recs)
    
    # Add some general recommendations if we don't have many specific ones
    if len(recommendations) < 3:
        general_recs = [
            "Regularly backup critical data and test restoration procedures",
            "Implement network segmentation to limit lateral movement",
            "Develop and exercise an incident response plan"
        ]
        recommendations.extend(general_recs[:3-len(recommendations)])
    
    return recommendations

def generate_automated_response_actions(iocs, ttps):
    """
    Generate suggested automated response actions based on detected IOCs and TTPs.
    
    Args:
        iocs: Dictionary of extracted IOCs
        ttps: Dictionary of detected TTPs
        
    Returns:
        List of response actions
    """
    response_actions = []
    
    # IP-based actions
    if iocs.get("ip_addresses"):
        response_actions.append(f"Block {len(iocs['ip_addresses'])} malicious IP addresses at the firewall")
        if len(iocs['ip_addresses']) > 3:
            response_actions.append("Deploy IP reputation filtering for all inbound traffic")
    
    # Domain-based actions
    if iocs.get("domains"):
        response_actions.append(f"Add {len(iocs['domains'])} malicious domains to DNS sinkhole")
        if len(iocs['domains']) > 3:
            response_actions.append("Enable enhanced DNS monitoring for suspicious lookups")
    
    # TTP-specific actions
    if "T1110" in ttps:  # Brute Force
        response_actions.append("Temporarily increase account lockout threshold")
        response_actions.append("Enable additional authentication logging")
    
    if "T1078" in ttps:  # Valid Accounts
        response_actions.append("Force password reset for potentially compromised accounts")
        response_actions.append("Review and validate all recent privileged account activities")
    
    if "T1190" in ttps:  # Exploit Public-Facing Application
        response_actions.append("Enable WAF rule to block common web application attacks")
        response_actions.append("Temporarily place public-facing applications behind CAPTCHA")
    
    # Add some general actions if we don't have many specific ones
    if len(response_actions) < 3:
        general_actions = [
            "Increase logging verbosity across all security systems",
            "Alert SOC team for heightened monitoring",
            "Snapshot all critical systems for potential forensic analysis"
        ]
        response_actions.extend(general_actions[:3-len(response_actions)])
    
    return response_actions

def simulate_log_data(log_type="syslog", include_attacks=True):
    """
    Generate simulated log data for demonstration purposes.
    
    Args:
        log_type: Type of log to simulate
        include_attacks: Whether to include attack signatures in logs
        
    Returns:
        String containing simulated log data
    """
    timestamp = datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, 60))
    timestamps = [(timestamp - datetime.timedelta(seconds=random.randint(1, 3600))).strftime("%b %d %H:%M:%S") 
                 for _ in range(20)]
    timestamps.sort()
    
    log_lines = []
    
    if log_type == "syslog":
        hostnames = ["web01", "app02", "db01", "auth01", "proxy01"]
        services = ["sshd", "sudo", "systemd", "cron", "nginx"]
        
        for ts in timestamps:
            host = random.choice(hostnames)
            service = random.choice(services)
            
            # Regular logs
            regular_logs = [
                f"{service}[{random.randint(1000, 9999)}]: Started session {random.randint(1, 1000)} for user admin",
                f"{service}[{random.randint(1000, 9999)}]: Received disconnect from 10.0.0.{random.randint(1, 255)}",
                f"{service}[{random.randint(1000, 9999)}]: New connection from 10.0.0.{random.randint(1, 255)}",
                f"{service}[{random.randint(1000, 9999)}]: Successfully authenticated user admin",
                f"{service}[{random.randint(1000, 9999)}]: Connection closed by 10.0.0.{random.randint(1, 255)}"
            ]
            
            # Attack logs
            attack_logs = [
                f"sshd[{random.randint(1000, 9999)}]: Failed password for invalid user admin from 203.0.113.{random.randint(1, 255)} port {random.randint(30000, 65000)}",
                f"sshd[{random.randint(1000, 9999)}]: Failed password for root from 198.51.100.{random.randint(1, 255)} port {random.randint(30000, 65000)}",
                f"sudo[{random.randint(1000, 9999)}]: authentication failure; logname=admin uid=1001 euid=0 tty=/dev/pts/0 ruser=admin rhost= user=root",
                f"nginx[{random.randint(1000, 9999)}]: Access denied: 192.0.2.{random.randint(1, 255)} - - \"GET /admin/config HTTP/1.1\" 403",
                f"nginx[{random.randint(1000, 9999)}]: Suspicious request: 192.0.2.{random.randint(1, 255)} - - \"GET /wp-login.php?action=rpc HTTP/1.1\" 404"
            ]
            
            if include_attacks and random.random() < 0.3:  # 30% chance of attack log
                log_line = f"{ts} {host} {random.choice(attack_logs)}"
            else:
                log_line = f"{ts} {host} {random.choice(regular_logs)}"
            
            log_lines.append(log_line)
            
    elif log_type == "windows":
        event_ids = [4624, 4625, 4634, 4648, 4672, 4688, 4720, 4724, 4738]
        users = ["Administrator", "SYSTEM", "jsmith", "abell", "mwilliams"]
        domains = ["CORP", "WORKGROUP"]
        
        for ts in timestamps:
            event_id = random.choice(event_ids)
            user = random.choice(users)
            domain = random.choice(domains)
            
            # Regular logs
            regular_logs = [
                f"The Windows Security Audit log was cleared",
                f"Special privileges assigned to new logon. Subject: {domain}\\{user}",
                f"User Account Created. Account Name: {user}",
                f"A member was added to a security-enabled global group",
                f"A scheduled task was created"
            ]
            
            # Attack logs
            attack_logs = [
                f"An account failed to log on. Account Name: {user} Source Network Address: 203.0.113.{random.randint(1, 255)}",
                f"A computer account was created. Security ID: SYSTEM Account Name: $ Workstation: ",
                f"Special privileges assigned to new logon. Account Name: Administrator",
                f"A logon was attempted using explicit credentials. Account Name: {domain}\\Administrator",
                f"An attempt was made to reset an account's password. Account Name: Administrator"
            ]
            
            log_content = random.choice(attack_logs if include_attacks and random.random() < 0.3 else regular_logs)
            log_line = f"{ts} {domain} Microsoft-Windows-Security-Auditing[{random.randint(1000, 9999)}]: {event_id}: {log_content}"
            log_lines.append(log_line)
            
    elif log_type == "web":
        ips = [f"10.0.0.{random.randint(1, 255)}", f"192.168.0.{random.randint(1, 255)}"]
        attack_ips = [f"203.0.113.{random.randint(1, 255)}", f"198.51.100.{random.randint(1, 255)}"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        paths = ["/", "/login", "/dashboard", "/api/users", "/admin", "/profile"]
        status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500]
        
        for ts in timestamps:
            method = random.choice(methods)
            path = random.choice(paths)
            status = random.choice(status_codes)
            
            # Regular logs
            if include_attacks and random.random() < 0.3:  # 30% chance of attack log
                ip = random.choice(attack_ips)
                
                # Attack requests
                attack_paths = [
                    "/admin/config.php?id=1' OR '1'='1",
                    "/search?q=<script>alert('XSS')</script>",
                    "/login' UNION SELECT username, password FROM users--",
                    "/wp-login.php?action=lostpassword",
                    "/admin/.git/config"
                ]
                
                path = random.choice(attack_paths)
            else:
                ip = random.choice(ips)
            
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            referer = "https://testreferer.com/"
            log_line = f'{ip} - - [{ts.replace(" ", "/")}] "{method} {path} HTTP/1.1" {status} {random.randint(100, 10000)} "{referer}" "{user_agent}"'
            log_lines.append(log_line)
    
    # Reorder slightly to make it look more realistic
    random.shuffle(log_lines)
    log_lines.sort(key=lambda x: x.split()[0:2])
    
    return "\n".join(log_lines)

def show_live_detection():
    """Display the live detection page"""
    st.title("🚨 Live TTP Detection")
    
    st.markdown("""
    This page demonstrates real-time detection of Tactics, Techniques, and Procedures (TTPs) 
    from logs, telemetry, and threat reports. The system can identify potential threats and 
    provide AI-driven recommendations for response.
    """)
    
    # Create tabs for different input methods
    telemetry_tab, logs_tab, demo_tab = st.tabs(["Telemetry Analysis", "Log Analysis", "Demo Mode"])
    
    with telemetry_tab:
        st.subheader("Upload Telemetry Data")
        st.markdown("""
        Upload network or system telemetry data in CSV or JSON format for analysis.
        The system will identify potential threats and associated MITRE ATT&CK techniques.
        """)
        
        uploaded_file = st.file_uploader("Upload telemetry data", type=["csv", "json"])
        
        if uploaded_file:
            file_content = uploaded_file.getvalue()
            file_extension = uploaded_file.name.split(".")[-1].lower()
            
            with st.spinner("Analyzing telemetry data..."):
                text_content = file_content.decode("utf-8")
                
                # Load NLP model and extract intelligence
                nlp = load_nlp_model()
                iocs = extract_iocs_from_text(text_content, nlp)
                ttps = extract_ttps_from_text(text_content)
                
                # Create result
                result = {
                    "report_type": "telemetry",
                    "detection_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "extracted_iocs": iocs,
                    "extracted_ttps": ttps,
                    "text_content": text_content[:500] + "..." if len(text_content) > 500 else text_content
                }
                
                if result:
                    st.success(f"Successfully analyzed {file_extension.upper()} telemetry data")
                    
                    # Show extraction results
                    show_extraction_results(result)
                    
                    # Show AI-driven recommendations
                    st.subheader("AI-Driven Recommendations")
                    recommendations = generate_mitre_recommendations(result["extracted_ttps"])
                    
                    for i, rec in enumerate(recommendations):
                        st.markdown(f"**{i+1}.** {rec}")
                    
                    # Show automated response actions
                    st.subheader("Suggested Automated Response Actions")
                    response_actions = generate_automated_response_actions(result["extracted_iocs"], result["extracted_ttps"])
                    
                    for i, action in enumerate(response_actions):
                        st.markdown(f"**{i+1}.** {action}")
    
    with logs_tab:
        st.subheader("Analyze Log Data")
        st.markdown("""
        Paste log data or upload a log file for analysis. The system supports various log formats
        including syslog, Windows event logs, and web server logs.
        """)
        
        log_type = st.selectbox("Log Type", ["syslog", "windows", "web"])
        
        log_data = st.text_area("Paste Log Data", height=200, placeholder="Paste log data here...")
        
        log_file = st.file_uploader("Or Upload Log File", type=["log", "txt"])
        
        if log_file:
            log_data = log_file.getvalue().decode("utf-8")
        
        if st.button("Analyze Logs") and log_data:
            with st.spinner("Analyzing log data..."):
                result = process_live_log_data(log_data, log_type)
                
                if result:
                    st.success(f"Successfully analyzed {log_type} log data")
                    
                    # Show extraction results
                    show_extraction_results(result)
                    
                    # Show AI-driven recommendations
                    st.subheader("AI-Driven Recommendations")
                    recommendations = generate_mitre_recommendations(result["extracted_ttps"])
                    
                    for i, rec in enumerate(recommendations):
                        st.markdown(f"**{i+1}.** {rec}")
                    
                    # Show automated response actions
                    st.subheader("Suggested Automated Response Actions")
                    response_actions = generate_automated_response_actions(result["extracted_iocs"], result["extracted_ttps"])
                    
                    for i, action in enumerate(response_actions):
                        st.markdown(f"**{i+1}.** {action}")
    
    with demo_tab:
        st.subheader("Demo Mode")
        st.markdown("""
        This demo mode simulates real-time threat detection from various log sources.
        You can choose a log type and whether to include attack signatures in the generated logs.
        """)
        
        demo_col1, demo_col2 = st.columns(2)
        
        with demo_col1:
            demo_log_type = st.selectbox("Demo Log Type", ["syslog", "windows", "web"], key="demo_log_type")
        
        with demo_col2:
            include_attacks = st.checkbox("Include Attack Signatures", value=True)
        
        if st.button("Generate Demo Logs and Detect Threats"):
            with st.spinner("Generating and analyzing demo logs..."):
                # Generate simulated log data
                log_data = simulate_log_data(demo_log_type, include_attacks)
                
                # Show sample of generated logs
                with st.expander("View Sample Log Data"):
                    st.code(log_data[:1000] + ("..." if len(log_data) > 1000 else ""))
                
                # Process the simulated logs
                result = process_live_log_data(log_data, demo_log_type)
                
                if result:
                    st.success(f"Successfully analyzed demo {demo_log_type} logs")
                    
                    # Show extraction results
                    show_extraction_results(result)
                    
                    # Show AI-driven recommendations
                    st.subheader("AI-Driven Recommendations")
                    recommendations = generate_mitre_recommendations(result["extracted_ttps"])
                    
                    for i, rec in enumerate(recommendations):
                        st.markdown(f"**{i+1}.** {rec}")
                    
                    # Show automated response actions
                    st.subheader("Suggested Automated Response Actions")
                    response_actions = generate_automated_response_actions(result["extracted_iocs"], result["extracted_ttps"])
                    
                    for i, action in enumerate(response_actions):
                        st.markdown(f"**{i+1}.** {action}")