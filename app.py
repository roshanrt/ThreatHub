import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import json

from auth import login, logout, check_authentication, is_admin
from dashboard import show_dashboard
from threat_analysis import show_threat_analysis
from rule_generation import show_rule_generation
from report_generation import show_report_generation
from mitre_attack import show_mitre_attack
from database import init_db

# Page configuration
st.set_page_config(
    page_title="CyberShield - Security Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database
init_db()

# Session state initialization
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'role' not in st.session_state:
    st.session_state.role = None
if 'active_page' not in st.session_state:
    st.session_state.active_page = "Dashboard"

# Authentication check
if not st.session_state.authenticated:
    login()
else:
    # Main application layout for authenticated users
    st.sidebar.title(f"🛡️ CyberShield")
    st.sidebar.subheader(f"Welcome, {st.session_state.username}")
    st.sidebar.caption(f"Role: {st.session_state.role}")
    
    # Navigation
    pages = {
        "Dashboard": "📊",
        "MITRE ATT&CK Intelligence": "🎯",
        "Threat Analysis": "🔍",
        "Security Rule Generation": "⚙️",
        "Report Generation": "📄"
    }
    
    # Only show admin options to admin users
    if not is_admin() and st.session_state.active_page == "User Management":
        st.session_state.active_page = "Dashboard"
    
    st.sidebar.header("Navigation")
    
    for page_name, page_icon in pages.items():
        if st.sidebar.button(f"{page_icon} {page_name}", key=page_name, 
                             use_container_width=True,
                             help=f"Navigate to {page_name}"):
            st.session_state.active_page = page_name
            st.rerun()
    
    # Logout button
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        logout()
        st.rerun()
    
    # Render the selected page
    if st.session_state.active_page == "Dashboard":
        show_dashboard()
    elif st.session_state.active_page == "MITRE ATT&CK Intelligence":
        show_mitre_attack()
    elif st.session_state.active_page == "Threat Analysis":
        show_threat_analysis()
    elif st.session_state.active_page == "Security Rule Generation":
        show_rule_generation()
    elif st.session_state.active_page == "Report Generation":
        show_report_generation()

# Add footer
st.sidebar.markdown("---")
st.sidebar.caption("© 2023 CyberShield Security Platform")
