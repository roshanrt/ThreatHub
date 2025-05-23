import streamlit as st
import sqlite3
import hashlib
import secrets
import datetime
import bcrypt
import pyotp
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
    """Create a new user in the database with TOTP secret"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists"
    
    # Hash the password with salt
    hashed_password = hash_password(password)
    
    # Generate TOTP secret
    totp_secret = pyotp.random_base32()
    
    # Insert the new user
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, totp_secret, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, hashed_password, role, totp_secret, datetime.datetime.now())
        )
        conn.commit()
        conn.close()
        
        # Optionally: show QR code for TOTP setup
        provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="CyberShield")
        st.info("Scan this QR code with your authenticator app:")
        import qrcode
        import io
        buf = io.BytesIO()
        qrcode.make(provisioning_uri).save(buf, format="PNG")
        st.image(buf.getvalue())
        st.code(totp_secret, language="text")
        
        return True, "User created successfully. Scan the QR code above to set up MFA."
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

# Add multi-factor authentication (MFA) support
def generate_mfa_secret():
    """Generate a secret key for MFA."""
    return pyotp.random_base32()

def verify_mfa_token(secret, token):
    """Verify an MFA token."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def login():
    """Display login form and handle login logic with TOTP 2FA"""
    st.title("🛡️ CyberShield Enterprise Security Platform")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("Secure Login")
        
        # Styled login box
        with st.container():
            st.markdown("""
            <style>
            .login-box {
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            </style>
            """, unsafe_allow_html=True)
            
            with st.container():
                st.markdown('<div class="login-box">', unsafe_allow_html=True)
                username = st.text_input("Username", key="login_username")
                password = st.text_input("Password", type="password", key="login_password")
                st.markdown('</div>', unsafe_allow_html=True)
            
            if st.button("Sign In", use_container_width=True):
                if username and password:
                    # Step 1: Check username/password
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("SELECT password_hash, role, totp_secret FROM users WHERE username = ?", (username,))
                    user = cursor.fetchone()
                    conn.close()
                    
                    if not user:
                        st.error("Invalid credentials")
                        return
                    
                    stored_password, role, totp_secret = user
                    
                    if not verify_password(stored_password, password):
                        st.error("Invalid credentials")
                        return
                    
                    # Step 2: Prompt for TOTP code
                    st.session_state["pending_2fa_user"] = username
                    st.session_state["pending_2fa_role"] = role
                    st.session_state["pending_2fa_secret"] = totp_secret
                    st.session_state["pending_2fa"] = True
                    st.experimental_rerun()
                else:
                    st.warning("Please enter your credentials")
    
    # TOTP 2FA step
    if st.session_state.get("pending_2fa"):
        st.info("Enter your 6-digit code from your authenticator app.")
        code = st.text_input("TOTP Code", max_chars=6, key="totp_code")
        
        if st.button("Verify Code", key="verify_totp"):
            secret = st.session_state.get("pending_2fa_secret")
            username = st.session_state.get("pending_2fa_user")
            role = st.session_state.get("pending_2fa_role")
            
            if not secret:
                st.error("No TOTP secret found for this user. Contact admin.")
                return
            
            totp = pyotp.TOTP(secret)
            
            if not code or not totp.verify(code):
                st.error("Invalid TOTP code.")
                return
            
            # Success: set session state
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.role = role
            st.session_state["pending_2fa"] = False
            st.session_state["pending_2fa_user"] = None
            st.session_state["pending_2fa_role"] = None
            st.session_state["pending_2fa_secret"] = None
            st.success("Authentication successful")
            st.rerun()
    
    with col2:
        st.header("Enterprise Security Suite")
        st.markdown("""
        <style>
        .feature-list {
            margin-top: 20px;
        }
        .feature-item {
            margin-bottom: 12px;
        }
        </style>
        
        <div class="feature-list">
        <p><strong>CyberShield</strong> delivers comprehensive security intelligence for modern enterprises:</p>
        
        <div class="feature-item">🔒 <strong>Threat Intelligence:</strong> Real-time insights with MITRE ATT&CK framework integration</div>
        <div class="feature-item">🔍 <strong>Threat Analysis:</strong> Advanced detection of indicators of compromise</div>
        <div class="feature-item">🔄 <strong>STIX/TAXII Integration:</strong> Standardized threat intelligence sharing</div>
        <div class="feature-item">⚙️ <strong>Security Rules:</strong> Automated generation for SIEM and EDR platforms</div>
        <div class="feature-item">📊 <strong>Executive Dashboards:</strong> Comprehensive security posture visualization</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Account credentials
        with st.expander("Demo Access"):
            st.info("""
            **Administrator Account**
            - Username: admin
            - Password: admin123
            
            **Security Analyst Account**
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

def show_admin_user_management():
    # Access control
    if st.session_state.get("role") != "admin":
        st.error("Access denied. Admins only.")
        st.stop()

    st.title("Admin User Management")

    # Helper: fetch all users
    def fetch_users():
        conn = get_db_connection()
        users = conn.execute("SELECT username, role FROM users").fetchall()
        conn.close()
        return users

    # Helper: add user
    def add_user(username, password, role):
        conn = get_db_connection()
        try:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            totp_secret = pyotp.random_base32()
            conn.execute(
                "INSERT INTO users (username, password_hash, role, totp_secret, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                (username, hashed, role, totp_secret)
            )
            conn.commit()
            return True, "User added successfully. TOTP secret: " + totp_secret
        except sqlite3.IntegrityError:
            return False, "Username already exists."
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            conn.close()

    # Helper: change role
    def change_role(username, new_role):
        conn = get_db_connection()
        try:
            conn.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
            conn.commit()
            return True, "Role updated."
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            conn.close()

    # Helper: delete user
    def delete_user(username):
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            return True, "User deleted."
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            conn.close()

    # User table
    st.subheader("All Users")
    users = fetch_users()
    st.table(users)

    # Add user form
    st.subheader("Add New User")
    with st.form("add_user_form"):
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["admin", "analyst"])
        submitted = st.form_submit_button("Add User")
        if submitted:
            if not new_username or not new_password:
                st.error("Username and password required.")
            else:
                ok, msg = add_user(new_username, new_password, new_role)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
                st.experimental_rerun()

    # Change role & delete section
    st.subheader("Manage Existing Users")
    current_admin = st.session_state.get("username")
    for user, role in users:
        if user == current_admin:
            st.write(f"{user} (You) - {role}")
            continue
        col1, col2, col3 = st.columns([2,2,1])
        with col1:
            new_role = st.selectbox(f"Role for {user}", ["admin", "analyst"], index=0 if role=="admin" else 1, key=f"role_{user}")
        with col2:
            if st.button(f"Change Role: {user}", key=f"change_{user}"):
                ok, msg = change_role(user, new_role)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
                st.experimental_rerun()
        with col3:
            if st.button(f"Delete {user}", key=f"delete_{user}"):
                ok, msg = delete_user(user)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
                st.experimental_rerun()
