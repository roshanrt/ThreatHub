import streamlit as st
import pandas as pd
import json
import re
import io
import base64
from datetime import datetime
import PyPDF2
import os

def validate_ioc(ioc_type, value):
    """Validate if a string matches the expected IOC format"""
    if ioc_type == "ip":
        # Simple IPv4 validation
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, value):
            # Check each octet is in range 0-255
            return all(0 <= int(octet) <= 255 for octet in value.split('.'))
        return False
    
    elif ioc_type == "domain":
        # Domain name validation
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, value))
    
    elif ioc_type == "url":
        # URL validation
        pattern = r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        return bool(re.match(pattern, value))
    
    elif ioc_type == "md5":
        # MD5 validation (32 hex characters)
        pattern = r'^[a-fA-F0-9]{32}$'
        return bool(re.match(pattern, value))
    
    elif ioc_type == "sha1":
        # SHA1 validation (40 hex characters)
        pattern = r'^[a-fA-F0-9]{40}$'
        return bool(re.match(pattern, value))
    
    elif ioc_type == "sha256":
        # SHA256 validation (64 hex characters)
        pattern = r'^[a-fA-F0-9]{64}$'
        return bool(re.match(pattern, value))
    
    return False

def parse_iocs_from_text(text):
    """Extract and validate IOCs from text"""
    iocs = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "md5_hashes": [],
        "sha1_hashes": [],
        "sha256_hashes": []
    }
    
    # IP pattern
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    for match in re.finditer(ip_pattern, text):
        ip = match.group(0)
        if validate_ioc("ip", ip) and ip not in iocs["ip_addresses"]:
            iocs["ip_addresses"].append(ip)
    
    # Domain pattern
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    for match in re.finditer(domain_pattern, text):
        domain = match.group(0)
        if validate_ioc("domain", domain) and domain not in iocs["domains"]:
            iocs["domains"].append(domain)
    
    # URL pattern
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    for match in re.finditer(url_pattern, text):
        url = match.group(0)
        if validate_ioc("url", url) and url not in iocs["urls"]:
            iocs["urls"].append(url)
    
    # Hash patterns
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    for match in re.finditer(md5_pattern, text):
        hash_value = match.group(0)
        if validate_ioc("md5", hash_value) and hash_value not in iocs["md5_hashes"]:
            iocs["md5_hashes"].append(hash_value)
    
    for match in re.finditer(sha1_pattern, text):
        hash_value = match.group(0)
        if validate_ioc("sha1", hash_value) and hash_value not in iocs["sha1_hashes"]:
            iocs["sha1_hashes"].append(hash_value)
    
    for match in re.finditer(sha256_pattern, text):
        hash_value = match.group(0)
        if validate_ioc("sha256", hash_value) and hash_value not in iocs["sha256_hashes"]:
            iocs["sha256_hashes"].append(hash_value)
    
    return iocs

def extract_text_from_pdf(pdf_content):
    """Extract text from a PDF file"""
    pdf_reader = PyPDF2.PdfReader(io.BytesIO(pdf_content))
    text = ""
    
    for page_num in range(len(pdf_reader.pages)):
        text += pdf_reader.pages[page_num].extract_text()
    
    return text

def parse_json_threat_report(json_content):
    """Parse a JSON threat report to extract structured data"""
    try:
        data = json.loads(json_content)
        
        report = {
            "title": data.get("report_title", "Unknown Report"),
            "date": data.get("report_date", datetime.now().strftime("%Y-%m-%d")),
            "threat_actor": data.get("threat_actor", "Unknown"),
            "confidence": data.get("confidence_level", "Medium"),
            "summary": data.get("summary", "No summary provided"),
            "iocs": {
                "ip_addresses": [],
                "domains": [],
                "urls": [],
                "md5_hashes": [],
                "sha1_hashes": [],
                "sha256_hashes": []
            },
            "techniques": []
        }
        
        # Extract IOCs
        if "indicators" in data:
            indicators = data["indicators"]
            
            if "ip_addresses" in indicators:
                report["iocs"]["ip_addresses"] = indicators["ip_addresses"]
            
            if "domains" in indicators:
                report["iocs"]["domains"] = indicators["domains"]
            
            if "urls" in indicators:
                report["iocs"]["urls"] = indicators["urls"]
            
            if "hashes" in indicators:
                for hash_obj in indicators["hashes"]:
                    hash_type = hash_obj.get("type", "").lower()
                    hash_value = hash_obj.get("value", "")
                    
                    if hash_type == "md5" and validate_ioc("md5", hash_value):
                        report["iocs"]["md5_hashes"].append(hash_value)
                    elif hash_type == "sha1" and validate_ioc("sha1", hash_value):
                        report["iocs"]["sha1_hashes"].append(hash_value)
                    elif hash_type == "sha256" and validate_ioc("sha256", hash_value):
                        report["iocs"]["sha256_hashes"].append(hash_value)
        
        # Extract techniques
        if "techniques_observed" in data:
            for technique in data["techniques_observed"]:
                report["techniques"].append({
                    "id": technique.get("id", "Unknown"),
                    "name": technique.get("name", "Unknown"),
                    "description": technique.get("description", "No description")
                })
        
        return report
    
    except Exception as e:
        st.error(f"Error parsing JSON report: {str(e)}")
        return None

def save_processed_data(data, file_name):
    """Save processed data to a file"""
    os.makedirs("sample_data", exist_ok=True)
    
    with open(f"sample_data/{file_name}", "w") as f:
        json.dump(data, f, indent=2)
    
    return f"sample_data/{file_name}"
