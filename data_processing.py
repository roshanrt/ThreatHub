import streamlit as st
import pandas as pd
import json
import re
import io
import base64
from datetime import datetime
import PyPDF2
import os
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for regex patterns
IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
URL_PATTERN = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'

def validate_ioc(ioc_type: str, value: str) -> bool:
    """Validate if a string matches the expected IOC format"""
    try:
        if ioc_type == "ip":
            if re.match(IP_PATTERN, value):
                return all(0 <= int(octet) <= 255 for octet in value.split('.'))
            return False
        elif ioc_type == "domain":
            return bool(re.match(DOMAIN_PATTERN, value))
        elif ioc_type == "url":
            return bool(re.match(URL_PATTERN, value))
        elif ioc_type == "md5":
            return bool(re.match(MD5_PATTERN, value))
        elif ioc_type == "sha1":
            return bool(re.match(SHA1_PATTERN, value))
        elif ioc_type == "sha256":
            return bool(re.match(SHA256_PATTERN, value))
        return False
    except Exception as e:
        logging.error(f"Error validating IOC: {e}")
        return False

def parse_iocs_from_text(text: str) -> dict:
    """Extract and validate IOCs from text"""
    iocs = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "md5_hashes": [],
        "sha1_hashes": [],
        "sha256_hashes": []
    }
    try:
        for match in re.finditer(IP_PATTERN, text):
            ip = match.group(0)
            if validate_ioc("ip", ip) and ip not in iocs["ip_addresses"]:
                iocs["ip_addresses"].append(ip)

        for match in re.finditer(DOMAIN_PATTERN, text):
            domain = match.group(0)
            if validate_ioc("domain", domain) and domain not in iocs["domains"]:
                iocs["domains"].append(domain)

        for match in re.finditer(URL_PATTERN, text):
            url = match.group(0)
            if validate_ioc("url", url) and url not in iocs["urls"]:
                iocs["urls"].append(url)

        for match in re.finditer(MD5_PATTERN, text):
            hash_value = match.group(0)
            if validate_ioc("md5", hash_value) and hash_value not in iocs["md5_hashes"]:
                iocs["md5_hashes"].append(hash_value)

        for match in re.finditer(SHA1_PATTERN, text):
            hash_value = match.group(0)
            if validate_ioc("sha1", hash_value) and hash_value not in iocs["sha1_hashes"]:
                iocs["sha1_hashes"].append(hash_value)

        for match in re.finditer(SHA256_PATTERN, text):
            hash_value = match.group(0)
            if validate_ioc("sha256", hash_value) and hash_value not in iocs["sha256_hashes"]:
                iocs["sha256_hashes"].append(hash_value)

    except Exception as e:
        logging.error(f"Error parsing IOCs from text: {e}")

    return iocs

def extract_text_from_pdf(pdf_content: bytes) -> str:
    """Extract text from a PDF file"""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(pdf_content))
        text = ""
        for page_num in range(len(pdf_reader.pages)):
            text += pdf_reader.pages[page_num].extract_text()
        return text
    except Exception as e:
        logging.error(f"Error extracting text from PDF: {e}")
        return ""

def parse_json_threat_report(json_content: str) -> dict:
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

        if "indicators" in data:
            indicators = data["indicators"]
            report["iocs"].update({
                "ip_addresses": indicators.get("ip_addresses", []),
                "domains": indicators.get("domains", []),
                "urls": indicators.get("urls", [])
            })

            if "hashes" in indicators:
                for hash_obj in indicators["hashes"]:
                    hash_type = hash_obj.get("type", "").lower()
                    hash_value = hash_obj.get("value", "")
                    if hash_type in ["md5", "sha1", "sha256"] and validate_ioc(hash_type, hash_value):
                        report["iocs"][f"{hash_type}_hashes"].append(hash_value)

        if "techniques_observed" in data:
            report["techniques"] = [
                {
                    "id": technique.get("id", "Unknown"),
                    "name": technique.get("name", "Unknown"),
                    "description": technique.get("description", "No description")
                } for technique in data["techniques_observed"]
            ]

        return report
    except Exception as e:
        logging.error(f"Error parsing JSON report: {e}")
        return {}

def save_processed_data(data: dict, file_name: str) -> str:
    """Save processed data to a file"""
    try:
        os.makedirs("sample_data", exist_ok=True)
        file_path = f"sample_data/{file_name}"
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)
        logging.info(f"Data saved to {file_path}")
        return file_path
    except Exception as e:
        logging.error(f"Error saving processed data: {e}")
        return ""
