import streamlit as st
import pandas as pd
import plotly.express as px
import json
import sqlite3
from datetime import datetime
import os
import hashlib
from database import db_connection, get_db_connection

def init_threat_intel_feed_db():
    """Initialize the threat intel feed database tables if they don't exist"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Create threat intel feeds table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intel_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            source TEXT NOT NULL,
            feed_type TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            created_by TEXT NOT NULL,
            last_updated TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Create threat intel items table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intel_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            added_at TIMESTAMP NOT NULL,
            added_by TEXT NOT NULL,
            tags TEXT,
            reference_url TEXT,
            FOREIGN KEY (feed_id) REFERENCES threat_intel_feeds (id) ON DELETE CASCADE,
            UNIQUE(feed_id, ioc_type, ioc_value)
        )
        ''')
        
        conn.commit()

def create_feed(title, description, source, feed_type, username):
    """Create a new threat intelligence feed"""
    with db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO threat_intel_feeds (title, description, source, feed_type, created_at, created_by, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (title, description, source, feed_type, datetime.now(), username, datetime.now())
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            conn.rollback()
            st.error(f"Error creating feed: {str(e)}")
            return None

def add_intel_item(feed_id, title, description, ioc_type, ioc_value, severity, confidence, username, first_seen=None, last_seen=None, tags=None, reference_url=None):
    """Add a new intelligence item to a feed"""
    with db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Convert tags list to JSON string if provided
            tags_json = json.dumps(tags) if tags else None
            
            # Use current datetime if first/last seen not provided
            current_time = datetime.now()
            first_seen = first_seen if first_seen else current_time
            last_seen = last_seen if last_seen else current_time
            
            cursor.execute(
                """INSERT INTO threat_intel_items 
                   (feed_id, title, description, ioc_type, ioc_value, severity, confidence, 
                    first_seen, last_seen, added_at, added_by, tags, reference_url) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (feed_id, title, description, ioc_type, ioc_value, severity, confidence,
                 first_seen, last_seen, current_time, username, tags_json, reference_url)
            )
            
            # Update the last_updated timestamp of the feed
            cursor.execute(
                "UPDATE threat_intel_feeds SET last_updated = ? WHERE id = ?",
                (current_time, feed_id)
            )
            
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # Item already exists, update it instead
            # Use current datetime if first/last seen not provided
            current_time = datetime.now()
            
            # Convert tags list to JSON string if provided
            tags_json = json.dumps(tags) if tags else None
            
            cursor.execute(
                """UPDATE threat_intel_items 
                   SET title = ?, description = ?, severity = ?, confidence = ?,
                       last_seen = ?, tags = ?, reference_url = ?
                   WHERE feed_id = ? AND ioc_type = ? AND ioc_value = ?""",
                (title, description, severity, confidence,
                 last_seen or current_time, tags_json, reference_url,
                 feed_id, ioc_type, ioc_value)
            )
            
            # Update the last_updated timestamp of the feed
            cursor.execute(
                "UPDATE threat_intel_feeds SET last_updated = ? WHERE id = ?",
                (current_time, feed_id)
            )
            
            conn.commit()
            return None
        except Exception as e:
            conn.rollback()
            st.error(f"Error adding intel item: {str(e)}")
            return None

def get_feeds(active_only=True):
    """Get all threat intelligence feeds"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        if active_only:
            cursor.execute("SELECT * FROM threat_intel_feeds WHERE is_active = 1 ORDER BY last_updated DESC")
        else:
            cursor.execute("SELECT * FROM threat_intel_feeds ORDER BY last_updated DESC")
        
        return cursor.fetchall()

def get_feed_by_id(feed_id):
    """Get a specific feed by ID"""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_intel_feeds WHERE id = ?", (feed_id,))
        return cursor.fetchone()

def get_feed_items(feed_id=None, ioc_type=None, severity=None, days=None):
    """
    Get intelligence items, optionally filtered by feed_id, type, severity, or timeframe
    
    Args:
        feed_id: Filter by specific feed ID
        ioc_type: Filter by IOC type (ip, domain, hash, etc.)
        severity: Filter by severity (critical, high, medium, low)
        days: Only include items from the last X days
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        query = "SELECT * FROM threat_intel_items"
        conditions = []
        params = []
        
        if feed_id:
            conditions.append("feed_id = ?")
            params.append(feed_id)
            
        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)
            
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
            
        if days:
            conditions.append("added_at >= datetime('now', ?)") 
            params.append(f'-{days} days')
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY added_at DESC"
        
        cursor.execute(query, params)
        return cursor.fetchall()

def update_feed(feed_id, title=None, description=None, source=None, feed_type=None, is_active=None):
    """Update a threat intelligence feed"""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Build the update query dynamically based on what's provided
        update_fields = []
        params = []
        
        if title is not None:
            update_fields.append("title = ?")
            params.append(title)
            
        if description is not None:
            update_fields.append("description = ?")
            params.append(description)
            
        if source is not None:
            update_fields.append("source = ?")
            params.append(source)
            
        if feed_type is not None:
            update_fields.append("feed_type = ?")
            params.append(feed_type)
            
        if is_active is not None:
            update_fields.append("is_active = ?")
            params.append(1 if is_active else 0)
            
        if not update_fields:
            return False
            
        # Add last updated timestamp and feed ID
        update_fields.append("last_updated = ?")
        params.append(datetime.now())
        params.append(feed_id)
        
        query = f"UPDATE threat_intel_feeds SET {', '.join(update_fields)} WHERE id = ?"
        
        try:
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            st.error(f"Error updating feed: {str(e)}")
            return False

def delete_intel_item(item_id):
    """Delete a specific intelligence item"""
    with db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Get the feed ID first to update its last_updated timestamp
            cursor.execute("SELECT feed_id FROM threat_intel_items WHERE id = ?", (item_id,))
            result = cursor.fetchone()
            
            if not result:
                return False
                
            feed_id = result[0]
            
            # Delete the item
            cursor.execute("DELETE FROM threat_intel_items WHERE id = ?", (item_id,))
            
            # Update the feed's last_updated timestamp
            cursor.execute(
                "UPDATE threat_intel_feeds SET last_updated = ? WHERE id = ?",
                (datetime.now(), feed_id)
            )
            
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            conn.rollback()
            st.error(f"Error deleting intel item: {str(e)}")
            return False

def generate_sample_threat_feed():
    """Generate a sample threat intelligence feed for demonstration"""
    # Clear existing sample data if any
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threat_intel_items WHERE feed_id IN (SELECT id FROM threat_intel_feeds WHERE source = 'Sample Data')")
        cursor.execute("DELETE FROM threat_intel_feeds WHERE source = 'Sample Data'")
        conn.commit()
    
    # Create sample feeds
    feed_types = ["IP Blocklist", "Malware Indicators", "APT Campaigns", "Phishing URLs"]
    sample_feeds = []
    
    for feed_type in feed_types:
        feed_id = create_feed(
            title=f"Sample {feed_type}",
            description=f"Sample threat intelligence feed for {feed_type}",
            source="Sample Data",
            feed_type=feed_type,
            username="system"
        )
        sample_feeds.append((feed_id, feed_type))
    
    # Add sample IOCs for each feed
    for feed_id, feed_type in sample_feeds:
        if feed_type == "IP Blocklist":
            for i in range(10):
                add_intel_item(
                    feed_id=feed_id,
                    title=f"Malicious IP {i+1}",
                    description=f"IP address associated with {['botnet activity', 'scanning', 'brute force attempts', 'C2 server'][i % 4]}",
                    ioc_type="ip",
                    ioc_value=f"203.0.113.{i+1}",
                    severity=["Critical", "High", "Medium", "Low"][i % 4],
                    confidence=["High", "Medium", "Low"][i % 3],
                    username="system",
                    tags=["malicious", "botnet" if i % 2 == 0 else "scanner"],
                    reference_url="https://example.com/threat-report"
                )
        
        elif feed_type == "Malware Indicators":
            for i in range(8):
                # Add file hashes
                hash_type = ["md5", "sha1", "sha256"][i % 3]
                add_intel_item(
                    feed_id=feed_id,
                    title=f"Malware Sample {i+1}",
                    description=f"File hash for {['Emotet', 'Trickbot', 'Ryuk', 'Conti'][i % 4]} malware variant",
                    ioc_type=hash_type,
                    ioc_value=hashlib.sha256(f"malware{i}".encode()).hexdigest()[:32 if hash_type == "md5" else 40 if hash_type == "sha1" else 64],
                    severity=["Critical", "High", "Medium"][i % 3],
                    confidence="High",
                    username="system",
                    tags=["malware", ["Emotet", "Trickbot", "Ryuk", "Conti"][i % 4]],
                    reference_url="https://example.com/malware-analysis"
                )
        
        elif feed_type == "APT Campaigns":
            apt_groups = ["APT29", "APT28", "APT41", "Lazarus Group"]
            for i, apt in enumerate(apt_groups):
                # Add domain IOC
                add_intel_item(
                    feed_id=feed_id,
                    title=f"{apt} C2 Domain",
                    description=f"Command and Control domain used by {apt} in recent campaigns",
                    ioc_type="domain",
                    ioc_value=f"{apt.lower().replace(' ', '-')}-command.example.com",
                    severity="High",
                    confidence="Medium",
                    username="system",
                    tags=["apt", apt],
                    reference_url="https://example.com/apt-report"
                )
                
                # Add IP IOC
                add_intel_item(
                    feed_id=feed_id,
                    title=f"{apt} Exfiltration Server",
                    description=f"Data exfiltration server used by {apt}",
                    ioc_type="ip",
                    ioc_value=f"198.51.100.{i+1}",
                    severity="Critical",
                    confidence="High",
                    username="system",
                    tags=["apt", apt, "exfiltration"],
                    reference_url="https://example.com/apt-report"
                )
        
        elif feed_type == "Phishing URLs":
            for i in range(6):
                add_intel_item(
                    feed_id=feed_id,
                    title=f"Phishing Campaign {i+1}",
                    description=f"URL used in recent phishing campaign targeting {['financial', 'healthcare', 'government', 'energy', 'retail', 'education'][i % 6]} sector",
                    ioc_type="url",
                    ioc_value=f"https://phishing-{i}.example.com/login.php",
                    severity=["High", "Medium"][i % 2],
                    confidence=["High", "Medium", "Low"][i % 3],
                    username="system",
                    tags=["phishing", ["financial", "healthcare", "government", "energy", "retail", "education"][i % 6]],
                    reference_url="https://example.com/phishing-analysis"
                )

def show_threat_intel_management():
    """Display the threat intelligence feed management interface for admins"""
    st.title("🔄 Threat Intelligence Feed Management")
    
    st.markdown("""
    This interface allows administrators to manage threat intelligence feeds and add new threat indicators.
    These feeds will be available to analysts in real-time through the Threat Analysis module.
    """)
    
    # Initialize the database tables if they don't exist
    init_threat_intel_feed_db()
    
    # Create tabs for different management functions
    manage_tab, add_tab, sample_tab = st.tabs(["Manage Feeds", "Add Intelligence", "Sample Data"])
    
    with manage_tab:
        st.subheader("Manage Threat Intelligence Feeds")
        
        # Get all feeds
        feeds = get_feeds(active_only=False)
        
        if not feeds:
            st.info("No threat intelligence feeds available. Create a new feed in the 'Add Intelligence' tab or generate sample data.")
        else:
            # Display feeds in expandable sections
            for feed in feeds:
                feed_id = feed['id']
                feed_title = feed['title']
                feed_source = feed['source']
                feed_type = feed['feed_type']
                feed_status = "Active" if feed['is_active'] else "Inactive"
                last_updated = feed['last_updated']
                
                with st.expander(f"{feed_title} ({feed_type}) - {feed_status}"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**Source:** {feed_source}")
                        st.write(f"**Description:** {feed['description']}")
                        st.write(f"**Last Updated:** {last_updated}")
                        st.write(f"**Created By:** {feed['created_by']}")
                    
                    with col2:
                        # Toggle active status
                        new_status = not feed['is_active']
                        if st.button(f"{'Activate' if new_status else 'Deactivate'}", key=f"toggle_{feed_id}"):
                            if update_feed(feed_id, is_active=new_status):
                                st.success(f"Feed {'activated' if new_status else 'deactivated'} successfully!")
                                st.rerun()
                    
                    # Get feed items
                    items = get_feed_items(feed_id=feed_id)
                    
                    if items:
                        st.subheader(f"Intelligence Items ({len(items)})")
                        
                        # Create a dataframe to display items
                        items_df = pd.DataFrame([{
                            "ID": item['id'],
                            "Type": item['ioc_type'].upper(),
                            "Value": item['ioc_value'],
                            "Severity": item['severity'],
                            "Title": item['title'],
                            "Added": item['added_at'],
                            "Tags": json.loads(item['tags']) if item['tags'] else []
                        } for item in items])
                        
                        st.dataframe(items_df)
                        
                        # Add option to delete items
                        # Create a readable format function that handles potential DataFrame indexing issues
                        def format_item(item_id):
                            matching_rows = items_df[items_df['ID'] == item_id]
                            if len(matching_rows) > 0:
                                return f"{matching_rows['Type'].values[0]}: {matching_rows['Value'].values[0]}"
                            return f"Item {item_id}"
                        
                        item_to_delete = st.selectbox(
                            "Select item to delete:",
                            options=items_df['ID'].tolist(),
                            format_func=format_item,
                            key=f"delete_select_{feed_id}"
                        )
                        
                        if st.button("Delete Selected Item", key=f"delete_btn_{feed_id}"):
                            if delete_intel_item(item_to_delete):
                                st.success("Item deleted successfully!")
                                st.rerun()
                            else:
                                st.error("Failed to delete item")
                    else:
                        st.info("This feed doesn't have any intelligence items yet.")
    
    with add_tab:
        st.subheader("Add Threat Intelligence")
        
        # Create two sub-tabs: one for creating a new feed, one for adding items to existing feeds
        new_feed_tab, add_items_tab = st.tabs(["Create New Feed", "Add Intelligence Items"])
        
        with new_feed_tab:
            with st.form("new_feed_form"):
                feed_title = st.text_input("Feed Title", placeholder="e.g., APT29 Indicators")
                feed_description = st.text_area("Description", placeholder="Description of this threat intelligence feed")
                feed_source = st.text_input("Source", placeholder="e.g., Internal Research, OSINT, Vendor XYZ")
                feed_type = st.selectbox(
                    "Feed Type",
                    options=["IP Blocklist", "Domain Watchlist", "Malware Indicators", "APT Campaigns", "Phishing URLs", "Vulnerability Indicators", "Other"]
                )
                
                submit_button = st.form_submit_button("Create Feed")
            
            if submit_button:
                if feed_title and feed_source and feed_type:
                    feed_id = create_feed(
                        title=feed_title,
                        description=feed_description,
                        source=feed_source,
                        feed_type=feed_type,
                        username=st.session_state.username
                    )
                    
                    if feed_id:
                        st.success(f"Feed '{feed_title}' created successfully!")
                        st.session_state.new_feed_id = feed_id
                        st.rerun()
                    else:
                        st.error("Failed to create feed")
                else:
                    st.warning("Please fill in all required fields")
        
        with add_items_tab:
            # Get active feeds for the dropdown
            feeds = get_feeds(active_only=True)
            
            if not feeds:
                st.info("No active feeds available. Please create a new feed first.")
            else:
                feed_options = {f"{feed['title']} ({feed['feed_type']})": feed['id'] for feed in feeds}
                
                # Pre-select newly created feed if available
                default_index = 0
                if hasattr(st.session_state, 'new_feed_id'):
                    for i, (_, feed_id) in enumerate(feed_options.items()):
                        if feed_id == st.session_state.new_feed_id:
                            default_index = i
                            break
                
                with st.form("add_intel_form"):
                    selected_feed = st.selectbox(
                        "Select Feed",
                        options=list(feed_options.keys()),
                        index=default_index
                    )
                    
                    feed_id = feed_options[selected_feed]
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        ioc_type = st.selectbox(
                            "IOC Type",
                            options=["ip", "domain", "url", "md5", "sha1", "sha256", "email", "filename", "filepath", "registry", "other"]
                        )
                        
                        severity = st.selectbox(
                            "Severity",
                            options=["Critical", "High", "Medium", "Low"]
                        )
                    
                    with col2:
                        ioc_value = st.text_input("IOC Value", placeholder="e.g., 192.168.1.1, malicious.com")
                        
                        confidence = st.selectbox(
                            "Confidence",
                            options=["High", "Medium", "Low"]
                        )
                    
                    intel_title = st.text_input("Title", placeholder="Brief title for this indicator")
                    intel_desc = st.text_area("Description", placeholder="Detailed description of this threat indicator")
                    
                    # Tags as comma-separated values
                    tags_input = st.text_input("Tags (comma-separated)", placeholder="e.g., ransomware, financial, APT29")
                    
                    # Optional reference URL
                    reference_url = st.text_input("Reference URL", placeholder="https://example.com/threat-report")
                    
                    submit_intel = st.form_submit_button("Add Intelligence Item")
                
                if submit_intel:
                    if intel_title and ioc_value:
                        # Process tags
                        tags = [tag.strip() for tag in tags_input.split(",")] if tags_input else []
                        
                        # Add the intelligence item
                        result = add_intel_item(
                            feed_id=feed_id,
                            title=intel_title,
                            description=intel_desc,
                            ioc_type=ioc_type,
                            ioc_value=ioc_value,
                            severity=severity,
                            confidence=confidence,
                            username=st.session_state.username,
                            tags=tags,
                            reference_url=reference_url
                        )
                        
                        if result is not None:
                            st.success("Intelligence item added successfully!")
                        else:
                            st.info("Item already exists and has been updated")
                    else:
                        st.warning("Please provide at least a title and IOC value")
    
    with sample_tab:
        st.subheader("Generate Sample Data")
        
        st.markdown("""
        For demonstration purposes, you can generate sample threat intelligence feeds with realistic data.
        This will create several feeds with various types of intelligence items.
        """)
        
        if st.button("Generate Sample Threat Intelligence Feeds"):
            with st.spinner("Generating sample data..."):
                generate_sample_threat_feed()
                st.success("Sample threat intelligence feeds generated successfully!")
                st.rerun()

def show_threat_intel_feed():
    """Display the threat intelligence feed interface for analysts"""
    st.title("🔔 Threat Intelligence Feed")
    
    st.markdown("""
    Stay up-to-date with the latest threat intelligence. This feed provides real-time intelligence
    on potential threats including malicious IPs, domains, file hashes, and more.
    """)
    
    # Initialize the database tables if they don't exist
    init_threat_intel_feed_db()
    
    # Add filters in the sidebar
    st.sidebar.header("Intelligence Filters")
    
    # Get active feeds for filter
    feeds = get_feeds(active_only=True)
    feed_options = {f"{feed['title']} ({feed['feed_type']})": feed['id'] for feed in feeds}
    feed_options["All Feeds"] = None
    
    selected_feed_name = st.sidebar.selectbox(
        "Feed",
        options=list(feed_options.keys()),
        index=0 if len(feed_options) > 1 else 0  # Default to "All Feeds"
    )
    selected_feed_id = feed_options[selected_feed_name]
    
    # Add other filters
    selected_ioc_type = st.sidebar.selectbox(
        "IOC Type",
        options=["All Types", "ip", "domain", "url", "md5", "sha1", "sha256", "email", "filename"]
    )
    
    selected_severity = st.sidebar.selectbox(
        "Severity",
        options=["All Severities", "Critical", "High", "Medium", "Low"]
    )
    
    timeframe = st.sidebar.slider("Timeframe (days)", min_value=1, max_value=90, value=30)
    
    # Apply filters
    ioc_type_filter = selected_ioc_type if selected_ioc_type != "All Types" else None
    severity_filter = selected_severity if selected_severity != "All Severities" else None
    
    # Get intelligence items based on filters
    intel_items = get_feed_items(
        feed_id=selected_feed_id,
        ioc_type=ioc_type_filter,
        severity=severity_filter,
        days=timeframe
    )
    
    # Display intelligence items
    if not intel_items:
        st.info("No threat intelligence items match your filters")
    else:
        # Create tabs for different view modes
        list_tab, table_tab, stats_tab = st.tabs(["Feed View", "Table View", "Statistics"])
        
        with list_tab:
            # Group items by feed
            feed_item_map = {}
            for item in intel_items:
                feed_id = item['feed_id']
                if feed_id not in feed_item_map:
                    feed_item_map[feed_id] = []
                feed_item_map[feed_id].append(item)
            
            # Display items by feed
            for feed_id, items in feed_item_map.items():
                feed = get_feed_by_id(feed_id)
                if not feed:
                    continue
                
                st.subheader(f"{feed['title']} ({len(items)} items)")
                st.caption(f"Source: {feed['source']} | Last Updated: {feed['last_updated']}")
                
                # Display items in expandable cards
                for item in items:
                    severity_color = {
                        "Critical": "red",
                        "High": "orange",
                        "Medium": "blue",
                        "Low": "green"
                    }.get(item['severity'], "gray")
                    
                    # Parse tags
                    tags = json.loads(item['tags']) if item['tags'] else []
                    tags_str = ", ".join(tags) if tags else "No tags"
                    
                    with st.expander(f"[{item['ioc_type'].upper()}] {item['title']} - :{severity_color}[{item['severity']}]"):
                        st.markdown(f"**Value:** `{item['ioc_value']}`")
                        st.markdown(f"**Description:** {item['description'] or 'No description provided'}")
                        st.markdown(f"**Confidence:** {item['confidence']}")
                        st.markdown(f"**First Seen:** {item['first_seen']}")
                        st.markdown(f"**Last Seen:** {item['last_seen']}")
                        st.markdown(f"**Tags:** {tags_str}")
                        
                        if item['reference_url']:
                            st.markdown(f"**Reference:** [View Source]({item['reference_url']})")
        
        with table_tab:
            # Create a dataframe for tabular view
            intel_df = pd.DataFrame([{
                "Title": item['title'],
                "Type": item['ioc_type'].upper(),
                "Value": item['ioc_value'],
                "Severity": item['severity'],
                "Confidence": item['confidence'],
                "Feed": get_feed_by_id(item['feed_id'])['title'],
                "Added": item['added_at'],
                "Last Seen": item['last_seen'],
                "Tags": json.loads(item['tags']) if item['tags'] else []
            } for item in intel_items])
            
            st.dataframe(intel_df)
            
            # Add download option
            csv = intel_df.to_csv(index=False)
            st.download_button(
                "Download as CSV",
                csv,
                "threat_intelligence.csv",
                "text/csv",
                key="download-csv"
            )
        
        with stats_tab:
            st.subheader("Intelligence Statistics")
            
            # Create statistics
            total_items = len(intel_items)
            unique_iocs = len(set(item['ioc_value'] for item in intel_items))
            
            # Display metrics
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Intelligence Items", total_items)
            
            with col2:
                st.metric("Unique IOCs", unique_iocs)
            
            with col3:
                critical_items = sum(1 for item in intel_items if item['severity'] == "Critical")
                st.metric("Critical Items", critical_items)
            
            # Create charts
            
            # IOC Type Distribution
            ioc_counts = {}
            for item in intel_items:
                ioc_type = item['ioc_type']
                ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + 1
            
            ioc_df = pd.DataFrame({
                "Type": list(ioc_counts.keys()),
                "Count": list(ioc_counts.values())
            })
            
            fig1 = px.pie(
                ioc_df, values="Count", names="Type",
                title="IOC Type Distribution",
                hole=0.4
            )
            
            # Severity Distribution
            severity_counts = {}
            for item in intel_items:
                severity = item['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            severity_df = pd.DataFrame({
                "Severity": list(severity_counts.keys()),
                "Count": list(severity_counts.values())
            })
            
            severity_order = ["Critical", "High", "Medium", "Low"]
            severity_df['Severity'] = pd.Categorical(
                severity_df['Severity'], 
                categories=severity_order, 
                ordered=True
            )
            severity_df = severity_df.sort_values('Severity')
            
            color_map = {
                "Critical": "red",
                "High": "orange",
                "Medium": "blue",
                "Low": "green"
            }
            
            fig2 = px.bar(
                severity_df, x="Severity", y="Count",
                title="Severity Distribution",
                color="Severity",
                color_discrete_map=color_map
            )
            
            # Timeline of additions
            timeline_df = pd.DataFrame([{
                "Date": item['added_at'].split(' ')[0],  # Just get the date part
                "Count": 1,
                "Severity": item['severity']
            } for item in intel_items])
            
            timeline_df = timeline_df.groupby(['Date', 'Severity']).sum().reset_index()
            
            fig3 = px.line(
                timeline_df, x="Date", y="Count", color="Severity",
                title="Intelligence Items Timeline",
                color_discrete_map=color_map
            )
            
            # Display the charts
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(fig1, use_container_width=True)
            
            with col2:
                st.plotly_chart(fig2, use_container_width=True)
            
            st.plotly_chart(fig3, use_container_width=True)