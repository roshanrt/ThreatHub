import streamlit as st
import stix2
import taxii2client
import taxii2client.v20
import taxii2client.v21
import json
import yaml
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import os
from database import db_connection
from threat_intel_feed import add_intel_item, get_feeds, create_feed

def discover_taxii_server(url, version="2.1", username=None, password=None):
    """
    Discover available collections on a TAXII server
    
    Args:
        url: TAXII server discovery URL
        version: TAXII version (2.0 or 2.1)
        username: Optional username for authentication
        password: Optional password for authentication
        
    Returns:
        Dictionary with server info and available collections
    """
    try:
        if version == "2.1":
            # TAXII 2.1
            if username and password:
                server = taxii2client.v21.Server(
                    url,
                    user=username,
                    password=password
                )
            else:
                server = taxii2client.v21.Server(url)
                
            api_roots = []
            for api_root_url in server.api_roots:
                api_root = taxii2client.v21.ApiRoot(api_root_url)
                collections = []
                
                for collection in api_root.collections:
                    collections.append({
                        "id": collection.id,
                        "title": collection.title,
                        "description": collection.description,
                        "url": collection.url
                    })
                
                api_roots.append({
                    "title": api_root.title,
                    "description": api_root.description,
                    "url": api_root_url,
                    "collections": collections
                })
                
            return {
                "version": "2.1",
                "title": server.title,
                "description": server.description,
                "api_roots": api_roots
            }
            
        else:
            # TAXII 2.0
            if username and password:
                server = taxii2client.v20.Server(
                    url,
                    user=username,
                    password=password
                )
            else:
                server = taxii2client.v20.Server(url)
                
            api_roots = []
            for api_root_url in server.api_roots:
                api_root = taxii2client.v20.ApiRoot(api_root_url)
                collections = []
                
                for collection in api_root.collections:
                    collections.append({
                        "id": collection.id,
                        "title": collection.title,
                        "description": collection.description,
                        "url": collection.url
                    })
                
                api_roots.append({
                    "title": api_root.title,
                    "description": api_root.description,
                    "url": api_root_url,
                    "collections": collections
                })
                
            return {
                "version": "2.0",
                "title": server.title,
                "description": server.description,
                "api_roots": api_roots
            }
            
    except Exception as e:
        st.error(f"Error discovering TAXII server: {str(e)}")
        return None

def get_collection_objects(collection_url, version="2.1", added_after=None, username=None, password=None):
    """
    Get objects from a TAXII collection
    
    Args:
        collection_url: URL of the TAXII collection
        version: TAXII version (2.0 or 2.1)
        added_after: Optional datetime to filter by
        username: Optional username for authentication
        password: Optional password for authentication
        
    Returns:
        List of STIX objects
    """
    try:
        if version == "2.1":
            # TAXII 2.1
            if username and password:
                collection = taxii2client.v21.Collection(
                    collection_url,
                    user=username,
                    password=password
                )
            else:
                collection = taxii2client.v21.Collection(collection_url)
                
            # Get objects, optionally filtered by time
            if added_after:
                objects = collection.get_objects(added_after=added_after)
            else:
                objects = collection.get_objects()
                
            return objects.get("objects", [])
            
        else:
            # TAXII 2.0
            if username and password:
                collection = taxii2client.v20.Collection(
                    collection_url,
                    user=username,
                    password=password
                )
            else:
                collection = taxii2client.v20.Collection(collection_url)
                
            # Get objects, optionally filtered by time
            if added_after:
                objects = collection.get_objects(added_after=added_after)
            else:
                objects = collection.get_objects()
                
            return objects.get("objects", [])
            
    except Exception as e:
        st.error(f"Error getting collection objects: {str(e)}")
        return []

def extract_iocs_from_stix(stix_objects):
    """
    Extract indicators of compromise from STIX objects
    
    Args:
        stix_objects: List of STIX objects
        
    Returns:
        Dictionary of extracted IOCs by type
    """
    iocs = {
        "ipv4": [],
        "ipv6": [],
        "domain": [],
        "url": [],
        "email": [],
        "file_hash": {
            "md5": [],
            "sha1": [],
            "sha256": []
        }
    }
    
    for obj in stix_objects:
        # Skip non-indicator objects
        if obj.get("type") != "indicator":
            continue
            
        pattern = obj.get("pattern", "")
        
        # Extract IPv4 addresses
        if "ipv4-addr" in pattern:
            parts = pattern.split("ipv4-addr:value")
            for part in parts[1:]:
                if "'" in part or '"' in part:
                    # Extract the IP within quotes
                    ip = part.split("'")[1] if "'" in part else part.split('"')[1]
                    if ip not in iocs["ipv4"]:
                        iocs["ipv4"].append(ip)
                        
        # Extract IPv6 addresses
        if "ipv6-addr" in pattern:
            parts = pattern.split("ipv6-addr:value")
            for part in parts[1:]:
                if "'" in part or '"' in part:
                    # Extract the IP within quotes
                    ip = part.split("'")[1] if "'" in part else part.split('"')[1]
                    if ip not in iocs["ipv6"]:
                        iocs["ipv6"].append(ip)
                        
        # Extract domains
        if "domain-name" in pattern:
            parts = pattern.split("domain-name:value")
            for part in parts[1:]:
                if "'" in part or '"' in part:
                    # Extract the domain within quotes
                    domain = part.split("'")[1] if "'" in part else part.split('"')[1]
                    if domain not in iocs["domain"]:
                        iocs["domain"].append(domain)
                        
        # Extract URLs
        if "url:value" in pattern:
            parts = pattern.split("url:value")
            for part in parts[1:]:
                if "'" in part or '"' in part:
                    # Extract the URL within quotes
                    url = part.split("'")[1] if "'" in part else part.split('"')[1]
                    if url not in iocs["url"]:
                        iocs["url"].append(url)
                        
        # Extract email addresses
        if "email-addr" in pattern:
            parts = pattern.split("email-addr:value")
            for part in parts[1:]:
                if "'" in part or '"' in part:
                    # Extract the email within quotes
                    email = part.split("'")[1] if "'" in part else part.split('"')[1]
                    if email not in iocs["email"]:
                        iocs["email"].append(email)
                        
        # Extract file hashes
        if "file:hashes" in pattern:
            # MD5
            if "MD5" in pattern:
                parts = pattern.split("file:hashes.MD5")
                for part in parts[1:]:
                    if "'" in part or '"' in part:
                        # Extract the hash within quotes
                        hash_val = part.split("'")[1] if "'" in part else part.split('"')[1]
                        if hash_val not in iocs["file_hash"]["md5"]:
                            iocs["file_hash"]["md5"].append(hash_val)
                            
            # SHA-1
            if "SHA-1" in pattern:
                parts = pattern.split("file:hashes.SHA-1")
                for part in parts[1:]:
                    if "'" in part or '"' in part:
                        # Extract the hash within quotes
                        hash_val = part.split("'")[1] if "'" in part else part.split('"')[1]
                        if hash_val not in iocs["file_hash"]["sha1"]:
                            iocs["file_hash"]["sha1"].append(hash_val)
                            
            # SHA-256
            if "SHA-256" in pattern:
                parts = pattern.split("file:hashes.SHA-256")
                for part in parts[1:]:
                    if "'" in part or '"' in part:
                        # Extract the hash within quotes
                        hash_val = part.split("'")[1] if "'" in part else part.split('"')[1]
                        if hash_val not in iocs["file_hash"]["sha256"]:
                            iocs["file_hash"]["sha256"].append(hash_val)
                            
    return iocs

def get_stix_object_metadata(obj):
    """
    Extract metadata from a STIX object
    
    Args:
        obj: STIX object
        
    Returns:
        Dictionary with metadata
    """
    metadata = {
        "id": obj.get("id", ""),
        "type": obj.get("type", ""),
        "created": obj.get("created", ""),
        "modified": obj.get("modified", ""),
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "labels": obj.get("labels", []),
    }
    
    # Add specific fields based on object type
    if obj.get("type") == "indicator":
        metadata["pattern"] = obj.get("pattern", "")
        metadata["valid_from"] = obj.get("valid_from", "")
        metadata["valid_until"] = obj.get("valid_until", "")
        metadata["indicator_types"] = obj.get("indicator_types", [])
        
    elif obj.get("type") == "threat-actor":
        metadata["aliases"] = obj.get("aliases", [])
        metadata["roles"] = obj.get("roles", [])
        metadata["goals"] = obj.get("goals", [])
        metadata["sophistication"] = obj.get("sophistication", "")
        
    elif obj.get("type") == "malware":
        metadata["malware_types"] = obj.get("malware_types", [])
        metadata["is_family"] = obj.get("is_family", False)
        metadata["kill_chain_phases"] = obj.get("kill_chain_phases", [])
        
    return metadata

def import_stix_objects_to_feed(stix_objects, feed_id, username):
    """
    Import STIX objects to a threat intel feed
    
    Args:
        stix_objects: List of STIX objects
        feed_id: ID of the feed to import to
        username: Username of the importing user
        
    Returns:
        Dictionary with import statistics
    """
    stats = {
        "total": len(stix_objects),
        "imported": 0,
        "skipped": 0,
        "by_type": {}
    }
    
    for obj in stix_objects:
        obj_type = obj.get("type", "unknown")
        
        # Initialize counter for this type if not exists
        if obj_type not in stats["by_type"]:
            stats["by_type"][obj_type] = {
                "total": 0,
                "imported": 0,
                "skipped": 0
            }
            
        stats["by_type"][obj_type]["total"] += 1
        
        # We mainly care about indicators for IOCs
        if obj_type == "indicator":
            try:
                # Extract basic metadata
                name = obj.get("name", "")
                description = obj.get("description", "")
                pattern = obj.get("pattern", "")
                created = obj.get("created", "")
                
                # Default to medium confidence and severity if not specified
                confidence = "Medium"
                severity = "Medium"
                
                # Get labels for additional context
                labels = obj.get("labels", [])
                
                # Set confidence based on labels if available
                if "high-confidence" in labels:
                    confidence = "High"
                elif "low-confidence" in labels:
                    confidence = "Low"
                    
                # Set severity based on labels if available
                if any(l for l in labels if "critical" in l.lower()):
                    severity = "Critical"
                elif any(l for l in labels if "high" in l.lower()):
                    severity = "High"
                elif any(l for l in labels if "low" in l.lower()):
                    severity = "Low"
                    
                # Process different indicator types
                if "ipv4-addr" in pattern:
                    parts = pattern.split("ipv4-addr:value")
                    for part in parts[1:]:
                        if "'" in part or '"' in part:
                            ip = part.split("'")[1] if "'" in part else part.split('"')[1]
                            # Add to feed
                            result = add_intel_item(
                                feed_id=feed_id,
                                title=name or f"IPv4 Indicator: {ip}",
                                description=description or f"IPv4 address extracted from STIX indicator: {ip}",
                                ioc_type="ip",
                                ioc_value=ip,
                                severity=severity,
                                confidence=confidence,
                                username=username,
                                first_seen=created if created else None,
                                tags=labels,
                                reference_url=None
                            )
                            if result is not None:
                                stats["imported"] += 1
                                stats["by_type"][obj_type]["imported"] += 1
                            else:
                                stats["skipped"] += 1
                                stats["by_type"][obj_type]["skipped"] += 1
                                
                elif "domain-name" in pattern:
                    parts = pattern.split("domain-name:value")
                    for part in parts[1:]:
                        if "'" in part or '"' in part:
                            domain = part.split("'")[1] if "'" in part else part.split('"')[1]
                            # Add to feed
                            result = add_intel_item(
                                feed_id=feed_id,
                                title=name or f"Domain Indicator: {domain}",
                                description=description or f"Domain extracted from STIX indicator: {domain}",
                                ioc_type="domain",
                                ioc_value=domain,
                                severity=severity,
                                confidence=confidence,
                                username=username,
                                first_seen=created if created else None,
                                tags=labels,
                                reference_url=None
                            )
                            if result is not None:
                                stats["imported"] += 1
                                stats["by_type"][obj_type]["imported"] += 1
                            else:
                                stats["skipped"] += 1
                                stats["by_type"][obj_type]["skipped"] += 1
                                
                elif "url:value" in pattern:
                    parts = pattern.split("url:value")
                    for part in parts[1:]:
                        if "'" in part or '"' in part:
                            url = part.split("'")[1] if "'" in part else part.split('"')[1]
                            # Add to feed
                            result = add_intel_item(
                                feed_id=feed_id,
                                title=name or f"URL Indicator: {url[:30]}...",
                                description=description or f"URL extracted from STIX indicator: {url}",
                                ioc_type="url",
                                ioc_value=url,
                                severity=severity,
                                confidence=confidence,
                                username=username,
                                first_seen=created if created else None,
                                tags=labels,
                                reference_url=None
                            )
                            if result is not None:
                                stats["imported"] += 1
                                stats["by_type"][obj_type]["imported"] += 1
                            else:
                                stats["skipped"] += 1
                                stats["by_type"][obj_type]["skipped"] += 1
                                
                elif "file:hashes" in pattern:
                    # Extract file hashes
                    hash_types = [
                        ("MD5", "md5"),
                        ("SHA-1", "sha1"),
                        ("SHA-256", "sha256")
                    ]
                    
                    for stix_hash_name, ioc_hash_type in hash_types:
                        if stix_hash_name in pattern:
                            parts = pattern.split(f"file:hashes.{stix_hash_name}")
                            for part in parts[1:]:
                                if "'" in part or '"' in part:
                                    hash_val = part.split("'")[1] if "'" in part else part.split('"')[1]
                                    # Add to feed
                                    result = add_intel_item(
                                        feed_id=feed_id,
                                        title=name or f"{stix_hash_name} Hash: {hash_val[:10]}...",
                                        description=description or f"{stix_hash_name} hash extracted from STIX indicator",
                                        ioc_type=ioc_hash_type,
                                        ioc_value=hash_val,
                                        severity=severity,
                                        confidence=confidence,
                                        username=username,
                                        first_seen=created if created else None,
                                        tags=labels,
                                        reference_url=None
                                    )
                                    if result is not None:
                                        stats["imported"] += 1
                                        stats["by_type"][obj_type]["imported"] += 1
                                    else:
                                        stats["skipped"] += 1
                                        stats["by_type"][obj_type]["skipped"] += 1
                
                else:
                    # Skip indicators with patterns we don't handle
                    stats["skipped"] += 1
                    stats["by_type"][obj_type]["skipped"] += 1
                
            except Exception as e:
                st.error(f"Error importing indicator: {str(e)}")
                stats["skipped"] += 1
                stats["by_type"][obj_type]["skipped"] += 1
                
        else:
            # Skip non-indicator objects for now
            stats["skipped"] += 1
            stats["by_type"][obj_type]["skipped"] += 1
            
    return stats

def create_stix_object(obj_type, **kwargs):
    """
    Create a new STIX object
    
    Args:
        obj_type: Type of STIX object to create
        **kwargs: Object properties
        
    Returns:
        STIX object
    """
    try:
        if obj_type == "indicator":
            return stix2.Indicator(
                id=kwargs.get("id"),
                created=kwargs.get("created"),
                modified=kwargs.get("modified"),
                name=kwargs.get("name"),
                description=kwargs.get("description", ""),
                indicator_types=kwargs.get("indicator_types", ["malicious-activity"]),
                pattern=kwargs.get("pattern"),
                pattern_type="stix",
                valid_from=kwargs.get("valid_from", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
                valid_until=kwargs.get("valid_until"),
                labels=kwargs.get("labels", []),
                confidence=kwargs.get("confidence", 50),
            )
        
        elif obj_type == "malware":
            return stix2.Malware(
                id=kwargs.get("id"),
                created=kwargs.get("created"),
                modified=kwargs.get("modified"),
                name=kwargs.get("name"),
                description=kwargs.get("description", ""),
                malware_types=kwargs.get("malware_types", ["unknown"]),
                is_family=kwargs.get("is_family", False),
                labels=kwargs.get("labels", []),
                kill_chain_phases=kwargs.get("kill_chain_phases", []),
            )
            
        elif obj_type == "threat-actor":
            return stix2.ThreatActor(
                id=kwargs.get("id"),
                created=kwargs.get("created"),
                modified=kwargs.get("modified"),
                name=kwargs.get("name"),
                description=kwargs.get("description", ""),
                threat_actor_types=kwargs.get("threat_actor_types", ["unknown"]),
                aliases=kwargs.get("aliases", []),
                roles=kwargs.get("roles", []),
                goals=kwargs.get("goals", []),
                sophistication=kwargs.get("sophistication"),
                labels=kwargs.get("labels", []),
            )
            
        else:
            st.error(f"Unsupported STIX object type: {obj_type}")
            return None
            
    except Exception as e:
        st.error(f"Error creating STIX object: {str(e)}")
        return None

def export_to_stix_bundle(intel_items, collection_name):
    """
    Export threat intelligence items to a STIX bundle
    
    Args:
        intel_items: List of threat intelligence items to export
        collection_name: Name to use in the bundle
        
    Returns:
        STIX bundle as JSON string
    """
    try:
        stix_objects = []
        
        for item in intel_items:
            now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Map severity to confidence (0-100)
            confidence_map = {
                "Critical": 90,
                "High": 75,
                "Medium": 50,
                "Low": 25
            }
            confidence = confidence_map.get(item["severity"], 50)
            
            # Parse tags
            tags = json.loads(item["tags"]) if item["tags"] else []
            
            # Set first seen/valid from date
            first_seen = item["first_seen"] if item["first_seen"] else now
            
            # Create indicator objects based on IOC type
            if item["ioc_type"] == "ip":
                pattern = f"[ipv4-addr:value = '{item['ioc_value']}']"
                indicator = create_stix_object(
                    "indicator",
                    name=item["title"],
                    description=item["description"] or f"IP address: {item['ioc_value']}",
                    pattern=pattern,
                    valid_from=first_seen,
                    labels=tags + ["malicious-ip"],
                    indicator_types=["malicious-activity"],
                    confidence=confidence
                )
                if indicator:
                    stix_objects.append(indicator)
                    
            elif item["ioc_type"] == "domain":
                pattern = f"[domain-name:value = '{item['ioc_value']}']"
                indicator = create_stix_object(
                    "indicator",
                    name=item["title"],
                    description=item["description"] or f"Domain: {item['ioc_value']}",
                    pattern=pattern,
                    valid_from=first_seen,
                    labels=tags + ["malicious-domain"],
                    indicator_types=["malicious-activity"],
                    confidence=confidence
                )
                if indicator:
                    stix_objects.append(indicator)
                    
            elif item["ioc_type"] == "url":
                pattern = f"[url:value = '{item['ioc_value']}']"
                indicator = create_stix_object(
                    "indicator",
                    name=item["title"],
                    description=item["description"] or f"URL: {item['ioc_value']}",
                    pattern=pattern,
                    valid_from=first_seen,
                    labels=tags + ["malicious-url"],
                    indicator_types=["malicious-activity"],
                    confidence=confidence
                )
                if indicator:
                    stix_objects.append(indicator)
                    
            elif item["ioc_type"] in ["md5", "sha1", "sha256"]:
                hash_type_map = {
                    "md5": "MD5",
                    "sha1": "SHA-1",
                    "sha256": "SHA-256"
                }
                stix_hash_type = hash_type_map.get(item["ioc_type"])
                pattern = f"[file:hashes.'{stix_hash_type}' = '{item['ioc_value']}']"
                indicator = create_stix_object(
                    "indicator",
                    name=item["title"],
                    description=item["description"] or f"{stix_hash_type} Hash: {item['ioc_value']}",
                    pattern=pattern,
                    valid_from=first_seen,
                    labels=tags + ["malicious-file"],
                    indicator_types=["malicious-activity"],
                    confidence=confidence
                )
                if indicator:
                    stix_objects.append(indicator)
        
        # Create bundle
        if stix_objects:
            bundle = stix2.Bundle(objects=stix_objects)
            return bundle.serialize(pretty=True)
        else:
            return json.dumps({"type": "bundle", "id": f"bundle--{stix2.utils.gen_uuid()}", "objects": []})
            
    except Exception as e:
        st.error(f"Error exporting to STIX bundle: {str(e)}")
        return json.dumps({"error": str(e)})

def save_taxii_servers(servers_config):
    """
    Save TAXII server configuration to database
    
    Args:
        servers_config: List of server configurations
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS taxii_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            discovery_url TEXT NOT NULL,
            version TEXT NOT NULL,
            username TEXT,
            password TEXT,
            added_by TEXT NOT NULL,
            added_at TIMESTAMP NOT NULL,
            last_used TIMESTAMP
        )
        ''')
        
        # Save each server
        for server in servers_config:
            cursor.execute(
                """INSERT INTO taxii_servers
                   (name, discovery_url, version, username, password, added_by, added_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    server["name"],
                    server["discovery_url"],
                    server["version"],
                    server.get("username"),
                    server.get("password"),
                    server["added_by"],
                    datetime.now()
                )
            )
        
        conn.commit()

def get_taxii_servers():
    """
    Get saved TAXII server configurations
    
    Returns:
        List of server configurations
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS taxii_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            discovery_url TEXT NOT NULL,
            version TEXT NOT NULL,
            username TEXT,
            password TEXT,
            added_by TEXT NOT NULL,
            added_at TIMESTAMP NOT NULL,
            last_used TIMESTAMP
        )
        ''')
        
        cursor.execute("SELECT * FROM taxii_servers ORDER BY added_at DESC")
        return cursor.fetchall()

def update_taxii_server_last_used(server_id):
    """
    Update the last used timestamp for a TAXII server
    
    Args:
        server_id: ID of the server to update
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE taxii_servers SET last_used = ? WHERE id = ?",
            (datetime.now(), server_id)
        )
        conn.commit()

def delete_taxii_server(server_id):
    """
    Delete a TAXII server configuration
    
    Args:
        server_id: ID of the server to delete
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM taxii_servers WHERE id = ?", (server_id,))
        conn.commit()

def show_stix_taxii_integration():
    """Display the STIX/TAXII integration interface"""
    st.title("STIX/TAXII Integration")
    
    st.markdown("""
    This module allows you to integrate with external threat intelligence sources using the STIX and TAXII standards. 
    You can import threat intelligence from TAXII servers and export your threat intelligence in STIX format.
    
    [STIX (Structured Threat Information Expression)](https://oasis-open.github.io/cti-documentation/stix/intro.html) is a standardized language for describing cyber threat intelligence.
    
    [TAXII (Trusted Automated Exchange of Intelligence Information)](https://oasis-open.github.io/cti-documentation/taxii/intro.html) is the transport mechanism for sharing STIX data.
    """)
    
    # Create tabs for different functions
    import_tab, export_tab, manage_tab = st.tabs([
        "Import from TAXII", 
        "Export as STIX", 
        "Manage TAXII Servers"
    ])
    
    with import_tab:
        st.subheader("Import from TAXII Servers")
        
        # Get saved TAXII servers
        saved_servers = get_taxii_servers()
        
        if not saved_servers:
            st.info("No TAXII servers have been configured. Add a server in the 'Manage TAXII Servers' tab.")
        else:
            # Select a server
            server_options = {f"{server['name']} ({server['discovery_url']})": server["id"] for server in saved_servers}
            selected_server_name = st.selectbox("Select TAXII Server", list(server_options.keys()))
            selected_server_id = server_options[selected_server_name]
            
            # Find the selected server
            selected_server = next((s for s in saved_servers if s["id"] == selected_server_id), None)
            
            if selected_server:
                # Show server details
                st.markdown(f"""
                **URL:** {selected_server['discovery_url']}  
                **Version:** {selected_server['version']}  
                **Added by:** {selected_server['added_by']}  
                """)
                
                # Discover server capabilities
                if st.button("Discover Server Collections"):
                    with st.spinner("Connecting to TAXII server..."):
                        server_info = discover_taxii_server(
                            selected_server["discovery_url"],
                            selected_server["version"],
                            selected_server["username"],
                            selected_server["password"]
                        )
                        
                        if not server_info:
                            st.error("Failed to connect to TAXII server. Please check the server details and try again.")
                        else:
                            # Update last used timestamp
                            update_taxii_server_last_used(selected_server_id)
                            
                            # Display server info
                            st.success(f"Successfully connected to TAXII server: {server_info.get('title', 'Unnamed')}")
                            
                            # Store API roots in session state
                            st.session_state.api_roots = server_info.get("api_roots", [])
                            
                            # Display API roots and collections
                            for i, api_root in enumerate(server_info.get("api_roots", [])):
                                with st.expander(f"API Root: {api_root.get('title', f'Root {i+1}')}"):
                                    st.markdown(f"**Description:** {api_root.get('description', 'No description')}")
                                    st.markdown(f"**URL:** {api_root.get('url', 'No URL')}")
                                    
                                    # Display collections
                                    collections = api_root.get("collections", [])
                                    if collections:
                                        st.markdown(f"**Collections ({len(collections)}):**")
                                        
                                        for coll in collections:
                                            st.markdown(f"""
                                            - **{coll.get('title', 'Unnamed Collection')}**  
                                              ID: {coll.get('id', 'No ID')}  
                                              {coll.get('description', 'No description')}
                                            """)
                                    else:
                                        st.info("No collections available in this API root.")
                
                # Show collection selection if API roots are available
                if hasattr(st.session_state, "api_roots") and st.session_state.api_roots:
                    st.subheader("Import Threat Intelligence")
                    
                    # Flatten all collections from all API roots
                    all_collections = []
                    for api_root in st.session_state.api_roots:
                        for coll in api_root.get("collections", []):
                            all_collections.append({
                                "id": coll.get("id", ""),
                                "title": coll.get("title", "Unnamed Collection"),
                                "description": coll.get("description", ""),
                                "url": coll.get("url", ""),
                                "api_root": api_root.get("title", "")
                            })
                    
                    # Select collection
                    if all_collections:
                        collection_options = {f"{c['title']} (API Root: {c['api_root']})": i for i, c in enumerate(all_collections)}
                        selected_collection_name = st.selectbox("Select Collection", list(collection_options.keys()))
                        selected_collection_index = collection_options[selected_collection_name]
                        selected_collection = all_collections[selected_collection_index]
                        
                        # Show collection details
                        st.markdown(f"""
                        **Collection:** {selected_collection['title']}  
                        **Description:** {selected_collection['description']}  
                        **API Root:** {selected_collection['api_root']}  
                        """)
                        
                        # Time filter
                        time_filter = st.selectbox(
                            "Import Time Range",
                            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Available"]
                        )
                        
                        # Determine added_after timestamp
                        added_after = None
                        if time_filter == "Last 24 Hours":
                            added_after = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                        elif time_filter == "Last 7 Days":
                            added_after = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
                        elif time_filter == "Last 30 Days":
                            added_after = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
                            
                        # Select target feed
                        feeds = get_feeds(active_only=True)
                        if not feeds:
                            st.warning("No active threat intelligence feeds found. Please create a feed first.")
                        else:
                            feed_options = {f"{feed['title']} ({feed['feed_type']})": feed['id'] for feed in feeds}
                            feed_options["Create New Feed"] = "new"
                            
                            selected_feed_name = st.selectbox("Import Into Feed", list(feed_options.keys()))
                            selected_feed_id = feed_options[selected_feed_name]
                            
                            # Option to create new feed
                            if selected_feed_id == "new":
                                with st.form("new_feed_for_import"):
                                    feed_title = st.text_input("Feed Title", f"Imported from {selected_collection['title']}")
                                    feed_description = st.text_area("Description", f"Threat intelligence imported from TAXII collection {selected_collection['title']} on {datetime.now().strftime('%Y-%m-%d')}")
                                    feed_type = st.selectbox(
                                        "Feed Type",
                                        ["TAXII Import", "APT Campaigns", "Malware Indicators", "IP Blocklist", "Domain Watchlist", "Phishing URLs"]
                                    )
                                    
                                    submit_button = st.form_submit_button("Create Feed")
                                    
                                    if submit_button:
                                        new_feed_id = create_feed(
                                            title=feed_title,
                                            description=feed_description,
                                            source=f"TAXII: {selected_server['name']}",
                                            feed_type=feed_type,
                                            username=st.session_state.username
                                        )
                                        
                                        if new_feed_id:
                                            st.success(f"Feed '{feed_title}' created successfully!")
                                            selected_feed_id = new_feed_id
                                            st.rerun()
                                        else:
                                            st.error("Failed to create feed")
                            
                            # Import button
                            if st.button("Import Threat Intelligence"):
                                if selected_feed_id != "new":
                                    with st.spinner("Retrieving STIX objects from TAXII collection..."):
                                        # Get STIX objects
                                        stix_objects = get_collection_objects(
                                            selected_collection["url"],
                                            selected_server["version"],
                                            added_after,
                                            selected_server["username"],
                                            selected_server["password"]
                                        )
                                        
                                        if not stix_objects:
                                            st.warning("No STIX objects found in the selected collection for the specified time range.")
                                        else:
                                            st.info(f"Retrieved {len(stix_objects)} STIX objects from the collection.")
                                            
                                            # Display object breakdown by type
                                            object_types = {}
                                            for obj in stix_objects:
                                                obj_type = obj.get("type", "unknown")
                                                object_types[obj_type] = object_types.get(obj_type, 0) + 1
                                                
                                            # Display as a table
                                            st.markdown("**STIX Object Types:**")
                                            type_df = pd.DataFrame({
                                                "Type": list(object_types.keys()),
                                                "Count": list(object_types.values())
                                            })
                                            st.dataframe(type_df)
                                            
                                            # Import into feed
                                            with st.spinner("Importing threat intelligence into feed..."):
                                                stats = import_stix_objects_to_feed(
                                                    stix_objects,
                                                    selected_feed_id,
                                                    st.session_state.username
                                                )
                                                
                                                st.success(f"Import completed: {stats['imported']} objects imported, {stats['skipped']} skipped")
                                                
                                                # Display import stats as a table
                                                st.markdown("**Import Statistics by Object Type:**")
                                                
                                                stats_data = []
                                                for obj_type, type_stats in stats["by_type"].items():
                                                    stats_data.append({
                                                        "Type": obj_type,
                                                        "Total": type_stats["total"],
                                                        "Imported": type_stats["imported"],
                                                        "Skipped": type_stats["skipped"]
                                                    })
                                                    
                                                if stats_data:
                                                    stats_df = pd.DataFrame(stats_data)
                                                    st.dataframe(stats_df)
                                            
                                                # Update last used timestamp
                                                update_taxii_server_last_used(selected_server_id)
                    else:
                        st.info("No collections available from this server.")
                        
    with export_tab:
        st.subheader("Export Threat Intelligence as STIX")
        
        # Get feeds for export
        feeds = get_feeds(active_only=True)
        if not feeds:
            st.warning("No active threat intelligence feeds found. Please create a feed first.")
        else:
            # Select feed to export
            feed_options = {f"{feed['title']} ({feed['feed_type']})": feed['id'] for feed in feeds}
            selected_feed_name = st.selectbox("Select Feed to Export", list(feed_options.keys()))
            selected_feed_id = feed_options[selected_feed_name]
            
            # Get items from the selected feed
            from threat_intel_feed import get_feed_items
            intel_items = get_feed_items(feed_id=selected_feed_id)
            
            if not intel_items:
                st.warning("The selected feed does not contain any intelligence items.")
            else:
                st.info(f"This feed contains {len(intel_items)} intelligence items that can be exported.")
                
                # Export options
                st.subheader("Export Options")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    export_format = st.selectbox(
                        "Export Format",
                        ["STIX JSON", "STIX YAML"]
                    )
                
                with col2:
                    collection_name = st.text_input(
                        "Collection Name",
                        value=f"CyberShield - {feeds[0]['title']}"
                    )
                
                # Export button
                if st.button("Generate STIX Export"):
                    with st.spinner("Generating STIX bundle..."):
                        stix_bundle = export_to_stix_bundle(intel_items, collection_name)
                        
                        if export_format == "STIX YAML":
                            # Convert to YAML
                            stix_bundle_obj = json.loads(stix_bundle)
                            stix_yaml = yaml.dump(stix_bundle_obj, default_flow_style=False)
                            
                            # Display sample
                            st.subheader("STIX Bundle (YAML)")
                            with st.expander("Preview"):
                                st.code(stix_yaml[:1000] + "...", language="yaml")
                                
                            # Create download link
                            filename = f"{collection_name.replace(' ', '_')}_stix_bundle.yaml"
                            st.download_button(
                                "Download STIX Bundle (YAML)",
                                stix_yaml,
                                file_name=filename,
                                mime="application/x-yaml"
                            )
                        else:
                            # Display sample
                            st.subheader("STIX Bundle (JSON)")
                            with st.expander("Preview"):
                                st.code(stix_bundle[:1000] + "...", language="json")
                                
                            # Create download link
                            filename = f"{collection_name.replace(' ', '_')}_stix_bundle.json"
                            st.download_button(
                                "Download STIX Bundle (JSON)",
                                stix_bundle,
                                file_name=filename,
                                mime="application/json"
                            )
                
    with manage_tab:
        st.subheader("Manage TAXII Servers")
        
        # Get saved TAXII servers
        saved_servers = get_taxii_servers()
        
        # Display existing servers
        if saved_servers:
            st.markdown("### Saved TAXII Servers")
            
            for server in saved_servers:
                with st.expander(f"{server['name']} ({server['discovery_url']})"):
                    st.markdown(f"""
                    **URL:** {server['discovery_url']}  
                    **Version:** {server['version']}  
                    **Added by:** {server['added_by']}  
                    **Added at:** {server['added_at']}  
                    **Last used:** {server['last_used'] or 'Never'}
                    """)
                    
                    # Delete button
                    if st.button("Delete Server", key=f"delete_{server['id']}"):
                        delete_taxii_server(server['id'])
                        st.success(f"Server '{server['name']}' deleted")
                        st.rerun()
        
        # Add new server
        st.markdown("### Add TAXII Server")
        
        with st.form("add_taxii_server"):
            server_name = st.text_input("Server Name", placeholder="e.g., MITRE ATT&CK TAXII Server")
            discovery_url = st.text_input(
                "Discovery URL", 
                placeholder="e.g., https://cti-taxii.mitre.org/taxii/"
            )
            server_version = st.selectbox("TAXII Version", ["2.1", "2.0"])
            
            # Optional authentication
            use_auth = st.checkbox("Server requires authentication")
            
            username = None
            password = None
            
            if use_auth:
                col1, col2 = st.columns(2)
                with col1:
                    username = st.text_input("Username")
                with col2:
                    password = st.text_input("Password", type="password")
            
            submit_button = st.form_submit_button("Add Server")
            
            if submit_button:
                if server_name and discovery_url:
                    # Create server configuration
                    server_config = [{
                        "name": server_name,
                        "discovery_url": discovery_url,
                        "version": server_version,
                        "username": username,
                        "password": password,
                        "added_by": st.session_state.username
                    }]
                    
                    # Save to database
                    save_taxii_servers(server_config)
                    
                    st.success(f"TAXII server '{server_name}' added successfully!")
                    st.rerun()
                else:
                    st.warning("Please provide both a server name and discovery URL.")
        
        # Add sample servers
        if not saved_servers:
            if st.button("Add Sample TAXII Servers"):
                # Sample TAXII servers configurations
                sample_servers = [
                    {
                        "name": "MITRE ATT&CK",
                        "discovery_url": "https://cti-taxii.mitre.org/taxii/",
                        "version": "2.1",
                        "username": None,
                        "password": None,
                        "added_by": st.session_state.username
                    },
                    {
                        "name": "STIX Samples",
                        "discovery_url": "https://oasis-open.github.io/cti-taxii-server/discovery/",
                        "version": "2.1",
                        "username": None,
                        "password": None,
                        "added_by": st.session_state.username
                    }
                ]
                
                # Save sample servers
                save_taxii_servers(sample_servers)
                
                st.success("Sample TAXII servers added successfully!")
                st.rerun()