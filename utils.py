import streamlit as st
import pandas as pd
import json
import io
import base64
from datetime import datetime
import re
import hashlib

def create_download_link(file_content, file_name, file_label=None):
    """Create a download link for a file"""
    if isinstance(file_content, str):
        file_content = file_content.encode()
    
    b64 = base64.b64encode(file_content).decode()
    
    if file_label is None:
        file_label = file_name
    
    href = f'<a href="data:file/octet-stream;base64,{b64}" download="{file_name}">{file_label}</a>'
    return href

def format_timestamp(timestamp=None):
    """Format a timestamp for display"""
    if timestamp is None:
        timestamp = datetime.now()
    
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        except:
            try:
                timestamp = datetime.strptime(timestamp, "%Y-%m-%d")
            except:
                return timestamp
    
    return timestamp.strftime("%b %d, %Y %H:%M:%S")

def sanitize_filename(filename):
    """Sanitize a filename to remove unsafe characters"""
    # Remove anything that's not alphanumeric, underscore, hyphen, or period
    filename = re.sub(r'[^\w\-\.]', '_', filename)
    
    return filename

def truncate_text(text, max_length=100):
    """Truncate text to a maximum length"""
    if len(text) <= max_length:
        return text
    
    return text[:max_length] + "..."

def hash_string(text):
    """Create a hash of a string"""
    return hashlib.sha256(text.encode()).hexdigest()

def validate_json(json_str):
    """Validate if a string is valid JSON"""
    try:
        json.loads(json_str)
        return True
    except:
        return False

def parse_csv_to_dataframe(csv_content):
    """Parse CSV content to a pandas DataFrame"""
    try:
        if isinstance(csv_content, bytes):
            return pd.read_csv(io.BytesIO(csv_content))
        else:
            return pd.read_csv(io.StringIO(csv_content))
    except Exception as e:
        st.error(f"Error parsing CSV: {str(e)}")
        return None

def create_empty_state(message="No data available", icon="ℹ️"):
    """Create a consistent empty state display"""
    st.markdown(f"""
    <div style="text-align: center; padding: 30px;">
        <div style="font-size: 48px;">{icon}</div>
        <p>{message}</p>
    </div>
    """, unsafe_allow_html=True)

def highlight_severity(severity):
    """Return a color for a severity level"""
    severity = severity.lower()
    if severity == "critical":
        return "red"
    elif severity == "high":
        return "orange"
    elif severity == "medium":
        return "yellow"
    elif severity == "low":
        return "green"
    else:
        return "gray"
