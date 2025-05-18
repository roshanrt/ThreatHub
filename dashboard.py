import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import random
from datetime import datetime, timedelta
import os

def load_sample_data():
    """Load sample telemetry data for dashboard visualizations"""
    # If the sample data file exists, load it
    if os.path.exists("sample_data/threat_telemetry.csv"):
        try:
            df = pd.read_csv("sample_data/threat_telemetry.csv")
            return df
        except Exception as e:
            st.error(f"Error loading sample data: {e}")
    
    # Generate sample data if file doesn't exist
    # This is for demonstration purposes only
    dates = [(datetime.now() - timedelta(days=x)).strftime("%Y-%m-%d") for x in range(30)]
    
    attack_types = ["Phishing", "Malware", "Ransomware", "DDoS", "SQLi", "XSS", "Credential Stuffing"]
    severities = ["Critical", "High", "Medium", "Low"]
    
    data = []
    for date in dates:
        for _ in range(random.randint(5, 15)):
            attack_type = random.choice(attack_types)
            severity = random.choice(severities)
            detected = random.choice([True, False])
            blocked = detected and random.choice([True, False])
            
            data.append({
                "date": date,
                "attack_type": attack_type,
                "severity": severity,
                "detected": detected,
                "blocked": blocked
            })
    
    df = pd.DataFrame(data)
    
    # Save the generated data
    os.makedirs("sample_data", exist_ok=True)
    df.to_csv("sample_data/threat_telemetry.csv", index=False)
    
    return df

def show_dashboard():
    """Display the main security dashboard"""
    st.title("📊 Enterprise Security Dashboard")
    
    st.markdown("""
    ### Real-time Security Intelligence Overview
    Monitor your organization's security posture with actionable threat intelligence.
    """)
    
    # Load telemetry data
    df = load_sample_data()
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_attacks = len(df)
    detected_attacks = df[df["detected"] == True].shape[0]
    blocked_attacks = df[df["blocked"] == True].shape[0]
    detection_rate = (detected_attacks / total_attacks) * 100 if total_attacks > 0 else 0
    
    with col1:
        st.metric(label="Total Attacks", value=f"{total_attacks}")
    
    with col2:
        st.metric(label="Detected Attacks", value=f"{detected_attacks}")
    
    with col3:
        st.metric(label="Blocked Attacks", value=f"{blocked_attacks}")
    
    with col4:
        st.metric(label="Detection Rate", value=f"{detection_rate:.1f}%")
    
    # Attacks over time
    st.subheader("Attack Trends")
    
    # Prepare data for line chart - handle different data formats
    if "date" in df.columns:
        # Convert to datetime if not already
        if not pd.api.types.is_datetime64_any_dtype(df["date"]):
            df["date"] = pd.to_datetime(df["date"], errors="coerce")
            
        # Group by date
        time_series = df.groupby("date").size().reset_index(name="count")
        time_series = time_series.sort_values("date")
    else:
        # Create sample date range if date column doesn't exist
        dates = pd.date_range(end=pd.Timestamp.now(), periods=30, freq="D")
        time_series = pd.DataFrame({
            "date": dates,
            "count": [random.randint(3, 15) for _ in range(len(dates))]
        })
    
    fig1 = px.line(
        time_series, x="date", y="count",
        title="Attack Volume Over Time",
        labels={"date": "Date", "count": "Number of Attacks"}
    )
    
    st.plotly_chart(fig1, use_container_width=True)
    
    # Split the dashboard into two columns
    col1, col2 = st.columns(2)
    
    with col1:
        # Attack types breakdown
        if "attack_type" in df.columns:
            attack_counts = df["attack_type"].value_counts().reset_index()
            attack_counts.columns = ["attack_type", "count"]
        else:
            # Fallback to a different column if attack_type doesn't exist
            # Using technique_id or technique_name if they exist, or creating a placeholder
            if "technique_name" in df.columns:
                attack_counts = df["technique_name"].value_counts().reset_index()
                attack_counts.columns = ["attack_type", "count"]  
            elif "technique_id" in df.columns:
                attack_counts = df["technique_id"].value_counts().reset_index()
                attack_counts.columns = ["attack_type", "count"]
            else:
                # Create a placeholder dataframe
                attack_counts = pd.DataFrame({
                    "attack_type": ["Phishing", "Malware", "Ransomware", "DDoS", "SQLi"],
                    "count": [5, 4, 3, 2, 1]
                })
        
        fig2 = px.pie(
            attack_counts, values="count", names="attack_type",
            title="Attack Types Distribution",
            hole=0.4
        )
        
        st.plotly_chart(fig2, use_container_width=True)
    
    with col2:
        # Severity distribution
        severity_order = ["Critical", "High", "Medium", "Low"]
        
        # Check if severity column exists
        if "severity" in df.columns:
            # Get counts and reindex to ensure all severity levels are included
            severity_counts = df["severity"].value_counts()
            severity_counts = severity_counts.reindex(severity_order, fill_value=0).reset_index()
            severity_counts.columns = ["severity", "count"]
        else:
            # Create a placeholder dataframe with severity levels
            severity_counts = pd.DataFrame({
                "severity": severity_order,
                "count": [random.randint(3, 10) for _ in range(len(severity_order))]
            })
        
        fig3 = px.bar(
            severity_counts, x="severity", y="count",
            title="Attack Severity Distribution",
            color="severity",
            color_discrete_map={
                "Critical": "red",
                "High": "orange",
                "Medium": "yellow",
                "Low": "green"
            },
            category_orders={"severity": severity_order}
        )
        
        st.plotly_chart(fig3, use_container_width=True)
    
    # Security posture analysis
    st.subheader("Security Posture Analysis")
    
    # Detection vs. blocking rates by attack type - handle different data formats
    if all(col in df.columns for col in ["attack_type", "detected", "blocked"]):
        attack_stats = df.groupby("attack_type").agg(
            total=("attack_type", "count"),
            detected=("detected", "sum"),
            blocked=("blocked", "sum")
        ).reset_index()
    elif "technique_id" in df.columns:
        if "detected" in df.columns and "blocked" in df.columns:
            attack_stats = df.groupby("technique_id").agg(
                total=("technique_id", "count"),
                detected=("detected", "sum"),
                blocked=("blocked", "sum")
            ).reset_index()
            attack_stats.rename(columns={"technique_id": "attack_type"}, inplace=True)
        else:
            # Create placeholder detected/blocked data based on technique_id
            attack_stats = df.groupby("technique_id").size().reset_index(name="total")
            attack_stats.rename(columns={"technique_id": "attack_type"}, inplace=True)
            attack_stats["detected"] = attack_stats["total"].apply(lambda x: random.randint(0, x))
            attack_stats["blocked"] = attack_stats["detected"].apply(lambda x: random.randint(0, x))
    else:
        # Create fallback data if necessary columns don't exist
        attack_types = ["Phishing", "Malware", "Ransomware", "DDoS", "SQLi"]
        attack_stats = pd.DataFrame({
            "attack_type": attack_types,
            "total": [random.randint(10, 20) for _ in range(len(attack_types))],
        })
        attack_stats["detected"] = attack_stats["total"].apply(lambda x: random.randint(0, x))
        attack_stats["blocked"] = attack_stats["detected"].apply(lambda x: random.randint(0, x))
    
    attack_stats["detection_rate"] = (attack_stats["detected"] / attack_stats["total"]) * 100
    attack_stats["blocking_rate"] = (attack_stats["blocked"] / attack_stats["total"]) * 100
    
    fig4 = go.Figure()
    
    fig4.add_trace(go.Bar(
        x=attack_stats["attack_type"],
        y=attack_stats["detection_rate"],
        name="Detection Rate",
        marker_color="rgb(55, 83, 109)"
    ))
    
    fig4.add_trace(go.Bar(
        x=attack_stats["attack_type"],
        y=attack_stats["blocking_rate"],
        name="Blocking Rate",
        marker_color="rgb(26, 118, 255)"
    ))
    
    fig4.update_layout(
        title="Detection and Blocking Rates by Attack Type",
        xaxis_title="Attack Type",
        yaxis_title="Rate (%)",
        barmode="group"
    )
    
    st.plotly_chart(fig4, use_container_width=True)
    
    # Add an expander with the raw data
    with st.expander("View Raw Telemetry Data"):
        st.dataframe(df)
