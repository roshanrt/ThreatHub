import sqlite3
import os
import hashlib
import secrets
import datetime
from contextlib import contextmanager

# Database initialization
def init_db():
    """Initialize the SQLite database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        last_login TIMESTAMP
    )
    ''')
    
    # Create reports table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        report_data TEXT NOT NULL
    )
    ''')
    
    # Create indicators table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_type TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT,
        added_by TEXT NOT NULL,
        added_at TIMESTAMP NOT NULL,
        UNIQUE(indicator_type, value)
    )
    ''')
    
    # Create rules table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        rule_content TEXT NOT NULL
    )
    ''')
    
    # Insert default users if they don't exist
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    if user_count == 0:
        # Create admin user
        admin_pwd_hash = hash_password("admin123")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", admin_pwd_hash, "admin", datetime.datetime.now())
        )
        
        # Create analyst user
        analyst_pwd_hash = hash_password("analyst123")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("analyst", analyst_pwd_hash, "analyst", datetime.datetime.now())
        )
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get a connection to the SQLite database"""
    # Create the directory if it doesn't exist
    os.makedirs("data", exist_ok=True)
    
    # Connect to SQLite database
    conn = sqlite3.connect("data/cybershield.db")
    conn.row_factory = sqlite3.Row
    
    return conn

@contextmanager
def db_connection():
    """Context manager for database connections"""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

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

def save_report(title, username, report_data):
    """Save a report to the database"""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO reports (title, created_by, created_at, report_data) VALUES (?, ?, ?, ?)",
            (title, username, datetime.datetime.now(), report_data)
        )
        conn.commit()
        return cursor.lastrowid

def get_reports(username=None):
    """Get reports from the database, optionally filtered by username"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        if username:
            cursor.execute(
                "SELECT * FROM reports WHERE created_by = ? ORDER BY created_at DESC",
                (username,)
            )
        else:
            cursor.execute("SELECT * FROM reports ORDER BY created_at DESC")
        
        return cursor.fetchall()

def save_indicator(indicator_type, value, source, username):
    """Save an indicator to the database"""
    with db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO indicators (indicator_type, value, source, added_by, added_at) VALUES (?, ?, ?, ?, ?)",
                (indicator_type, value, source, username, datetime.datetime.now())
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Indicator already exists
            return False

def get_indicators(indicator_type=None):
    """Get indicators from the database, optionally filtered by type"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        if indicator_type:
            cursor.execute(
                "SELECT * FROM indicators WHERE indicator_type = ? ORDER BY added_at DESC",
                (indicator_type,)
            )
        else:
            cursor.execute("SELECT * FROM indicators ORDER BY added_at DESC")
        
        return cursor.fetchall()

def save_rule(rule_name, rule_type, rule_content, username):
    """Save a rule to the database"""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO rules (rule_name, rule_type, created_by, created_at, rule_content) VALUES (?, ?, ?, ?, ?)",
            (rule_name, rule_type, username, datetime.datetime.now(), rule_content)
        )
        conn.commit()
        return cursor.lastrowid

def get_rules(rule_type=None):
    """Get rules from the database, optionally filtered by type"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        if rule_type:
            cursor.execute(
                "SELECT * FROM rules WHERE rule_type = ? ORDER BY created_at DESC",
                (rule_type,)
            )
        else:
            cursor.execute("SELECT * FROM rules ORDER BY created_at DESC")
        
        return cursor.fetchall()
