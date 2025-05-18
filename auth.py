import streamlit as st
import sqlite3
import hashlib
import secrets
import datetime
from database import get_db_connection

# User roles
ROLES = {
    "admin": "Administrator",
    "analyst": "Security Analyst"
}

def hash_password(password, salt=None):
    """Hash a password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    pwdhash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000
    ).hex()
    
    return f"{salt}${pwdhash}"

def verify_password(stored_password, provided_password):
    """Verify a password against its hash"""
    salt, stored_hash = stored_password.split('$')
    provided_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        provided_password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000
    ).hex()
    
    return provided_hash == stored_hash

def create_user(username, password, role):
    """Create a new user in the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists"
    
    # Hash the password with salt
    hashed_password = hash_password(password)
    
    # Insert the new user
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hashed_password, role, datetime.datetime.now())
        )
        conn.commit()
        conn.close()
        return True, "User created successfully"
    except Exception as e:
        conn.close()
        return False, f"Error creating user: {str(e)}"

def authenticate_user(username, password):
    """Authenticate a user by checking username and password"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user from the database
    cursor.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return False, None
    
    # Verify the password
    stored_password = user[1]
    if verify_password(stored_password, password):
        conn.close()
        return True, user[2]  # Return role
    
    conn.close()
    return False, None

def login():
    """Display login form and handle login logic"""
    st.title("🛡️ CyberShield Security Platform")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login", use_container_width=True):
            if username and password:
                success, role = authenticate_user(username, password)
                if success:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.role = role
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")
            else:
                st.warning("Please enter both username and password")
    
    with col2:
        st.header("About CyberShield")
        st.markdown("""
        **CyberShield Security Intelligence Platform** provides comprehensive 
        cybersecurity capabilities:
        
        - 🎯 MITRE ATT&CK Intelligence
        - 🔍 Advanced Threat Analysis
        - ⚙️ Automated Security Rule Generation
        - 📊 Interactive Security Dashboards
        - 📄 Security Report Generation
        
        Login with your credentials to access the platform.
        """)
        
        # Demo credentials for first-time users
        with st.expander("Demo Credentials"):
            st.info("""
            **Admin User:**
            - Username: admin
            - Password: admin123
            
            **Analyst User:**
            - Username: analyst
            - Password: analyst123
            """)

def logout():
    """Log the user out"""
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.active_page = "Dashboard"

def check_authentication():
    """Check if the user is authenticated"""
    return st.session_state.authenticated

def is_admin():
    """Check if the current user is an admin"""
    return st.session_state.role == "admin"

def create_initial_users():
    """Create initial admin and analyst users if they don't exist"""
    # Create admin user
    create_user("admin", "admin123", "admin")
    
    # Create analyst user
    create_user("analyst", "analyst123", "analyst")
