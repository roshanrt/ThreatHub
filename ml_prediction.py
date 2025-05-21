import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import base64
import io
from datetime import datetime, timedelta
import random

def generate_reference_ttp_data():
    """Generate reference TTP data for machine learning prediction"""
    # MITRE ATT&CK techniques
    techniques = [
        {"id": "T1566", "name": "Phishing"},
        {"id": "T1566.001", "name": "Spearphishing Attachment"},
        {"id": "T1566.002", "name": "Spearphishing Link"},
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1133", "name": "External Remote Services"},
        {"id": "T1078", "name": "Valid Accounts"},
        {"id": "T1110", "name": "Brute Force"},
        {"id": "T1110.003", "name": "Password Spraying"},
        {"id": "T1110.004", "name": "Credential Stuffing"},
        {"id": "T1083", "name": "File and Directory Discovery"},
        {"id": "T1046", "name": "Network Service Scanning"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        {"id": "T1567", "name": "Exfiltration Over Web Service"},
        {"id": "T1567.002", "name": "Exfiltration to Cloud Storage"}
    ]
    
    # Threat actors
    threat_actors = ["APT29", "APT28", "FIN7", "Lazarus Group", "Carbanak", "Silence Group", "APT41"]
    
    # Industries
    industries = ["Financial", "Healthcare", "Government", "Energy", "Retail", "Technology", "Manufacturing"]
    
    # Time periods
    start_date = datetime.now() - timedelta(days=365*2)  # 2 years ago
    end_date = datetime.now()
    
    # Generate random data
    data = []
    
    for _ in range(500):
        actor = random.choice(threat_actors)
        industry = random.choice(industries)
        date = start_date + timedelta(days=random.randint(0, (end_date - start_date).days))
        technique = random.choice(techniques)
        success = random.choice([True, False])
        
        # Add some correlation between actor, industry, and technique
        if actor == "APT29" and random.random() < 0.7:
            technique = next((t for t in techniques if t["id"] in ["T1566", "T1566.001"]), technique)
            if random.random() < 0.6:
                industry = "Government"
        
        if actor == "FIN7" and random.random() < 0.7:
            technique = next((t for t in techniques if t["id"] in ["T1190", "T1110.004"]), technique)
            if random.random() < 0.6:
                industry = "Financial"
        
        data.append({
            "date": date.strftime("%Y-%m-%d"),
            "threat_actor": actor,
            "industry": industry,
            "technique_id": technique["id"],
            "technique_name": technique["name"],
            "success": success
        })
    
    df = pd.DataFrame(data)
    
    # Save the generated data
    df.to_csv("data_resources/threat_telemetry.csv", index=False)
    return df

def train_ttp_prediction_model(df):
    """Train a machine learning model to predict TTP trends"""
    # Prepare the data
    df["date"] = pd.to_datetime(df["date"])
    df["month"] = df["date"].dt.month
    df["year"] = df["date"].dt.year
    df["quarter"] = df["date"].dt.quarter
    
    # Create feature encoders
    threat_actor_encoder = LabelEncoder()
    industry_encoder = LabelEncoder()
    technique_encoder = LabelEncoder()
    
    df["threat_actor_encoded"] = threat_actor_encoder.fit_transform(df["threat_actor"])
    df["industry_encoded"] = industry_encoder.fit_transform(df["industry"])
    df["technique_encoded"] = technique_encoder.fit_transform(df["technique_id"])
    
    # Create feature matrix
    X = df[["threat_actor_encoded", "industry_encoded", "month", "quarter", "year"]]
    y = df["technique_encoded"]
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train the model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    # Feature importance
    feature_importance = pd.DataFrame({
        "Feature": X.columns,
        "Importance": model.feature_importances_
    }).sort_values("Importance", ascending=False)
    
    # Return the model and encoders
    return {
        "model": model,
        "threat_actor_encoder": threat_actor_encoder,
        "industry_encoder": industry_encoder,
        "technique_encoder": technique_encoder,
        "technique_mapping": dict(zip(
            technique_encoder.transform(df["technique_id"].unique()),
            df["technique_id"].unique()
        )),
        "accuracy": accuracy,
        "feature_importance": feature_importance
    }

def predict_emerging_ttps(model_data, threat_actor, industry, future_months=3):
    """Predict emerging TTPs for the next few months"""
    # Get current date components
    now = datetime.now()
    current_year = now.year
    current_month = now.month
    current_quarter = (current_month - 1) // 3 + 1
    
    # Prepare future data points
    future_data = []
    
    for month_offset in range(future_months):
        future_month = (current_month + month_offset) % 12 + 1
        future_year = current_year + (current_month + month_offset) // 12
        future_quarter = (future_month - 1) // 3 + 1
        
        future_data.append({
            "threat_actor_encoded": model_data["threat_actor_encoder"].transform([threat_actor])[0],
            "industry_encoded": model_data["industry_encoder"].transform([industry])[0],
            "month": future_month,
            "quarter": future_quarter,
            "year": future_year
        })
    
    # Convert to DataFrame
    future_df = pd.DataFrame(future_data)
    
    # Make predictions
    predicted_techniques_encoded = model_data["model"].predict(future_df)
    predicted_proba = model_data["model"].predict_proba(future_df)
    
    # Map encoded predictions back to technique IDs
    predicted_techniques = [model_data["technique_mapping"][encoded] for encoded in predicted_techniques_encoded]
    
    # Get top 3 most likely techniques for each month
    predictions = []
    
    for i, month_offset in enumerate(range(future_months)):
        future_month = (current_month + month_offset) % 12 + 1
        future_date = datetime(
            current_year + (current_month + month_offset) // 12,
            future_month, 
            1
        ).strftime("%Y-%m")
        
        # Get probabilities for top techniques
        probs = predicted_proba[i]
        top_indices = probs.argsort()[-3:][::-1]  # Top 3 indices
        
        for index in top_indices:
            if probs[index] > 0.05:  # Only include if probability > 5%
                technique_id = model_data["technique_mapping"][index]
                predictions.append({
                    "date": future_date,
                    "technique_id": technique_id,
                    "probability": probs[index] * 100  # Convert to percentage
                })
    
    return pd.DataFrame(predictions)

def predict_ttps_in_mitre_attack():
    """Make TTP predictions based on MITRE ATT&CK data"""
    # Try to load the reference data
    try:
        # Load the CSV file
        df = pd.read_csv("data_resources/threat_telemetry.csv")
    except:
        # Generate reference data if not available
        df = generate_reference_ttp_data()
    
    # Train the model
    model_data = train_ttp_prediction_model(df)
    
    st.subheader("TTP Trend Prediction")
    
    st.markdown("""
    This model predicts which MITRE ATT&CK techniques are likely to be used by threat actors 
    against specific industries in the coming months, based on historical attack data.
    """)
    
    # Input form for prediction
    col1, col2 = st.columns(2)
    
    with col1:
        # Get unique threat actors from the encoder
        threat_actors = list(model_data["threat_actor_encoder"].classes_)
        selected_threat_actor = st.selectbox("Select Threat Actor", threat_actors)
    
    with col2:
        # Get unique industries from the encoder
        industries = list(model_data["industry_encoder"].classes_)
        selected_industry = st.selectbox("Select Industry", industries)
    
    prediction_months = st.slider("Prediction Horizon (Months)", 1, 6, 3)
    
    if st.button("Predict Emerging TTPs"):
        with st.spinner("Generating predictions..."):
            # Make predictions
            predictions = predict_emerging_ttps(
                model_data, 
                selected_threat_actor, 
                selected_industry, 
                prediction_months
            )
            
            if not predictions.empty:
                st.success(f"Generated predictions for {selected_threat_actor} targeting {selected_industry}")
                
                # Display predictions
                st.subheader("Predicted TTPs")
                
                # Create a visualization
                fig = px.bar(
                    predictions, 
                    x="technique_id", 
                    y="probability", 
                    color="date",
                    labels={"probability": "Probability (%)", "technique_id": "MITRE ATT&CK Technique"},
                    title=f"Predicted TTP Usage - {selected_threat_actor} targeting {selected_industry}",
                    height=500
                )
                
                st.plotly_chart(fig, use_container_width=True, key="ml_prediction_fig1")
                
                # Show detailed table
                st.dataframe(predictions)
                
                # Recommendations based on predictions
                st.subheader("Defensive Recommendations")
                
                top_techniques = predictions.sort_values("probability", ascending=False)["technique_id"].unique()[:3]
                
                mitre_defense_recommendations = {
                    "T1566": [
                        "Implement email filtering and anti-phishing solutions",
                        "Conduct user awareness training on phishing threats",
                        "Deploy multi-factor authentication"
                    ],
                    "T1566.001": [
                        "Block or strip potentially malicious attachments",
                        "Use sandboxing to analyze email attachments",
                        "Disable macros in Microsoft Office products"
                    ],
                    "T1566.002": [
                        "Implement URL filtering",
                        "Use browser isolation technology",
                        "Deploy web proxies with reputation filtering"
                    ],
                    "T1190": [
                        "Implement regular vulnerability scanning and patching",
                        "Deploy web application firewalls",
                        "Use network segmentation to restrict access to public-facing applications"
                    ],
                    "T1133": [
                        "Implement multi-factor authentication for remote services",
                        "Restrict access to remote services based on source IP",
                        "Monitor for unusual access patterns"
                    ],
                    "T1078": [
                        "Implement strong password policies",
                        "Deploy privileged access management solutions",
                        "Monitor for suspicious account usage"
                    ],
                    "T1110": [
                        "Implement account lockout policies",
                        "Monitor for failed login attempts",
                        "Use CAPTCHA to prevent automated attacks"
                    ],
                    "T1110.003": [
                        "Implement account lockout policies across all systems",
                        "Monitor for login attempts across multiple accounts",
                        "Use threat intelligence to block known password spraying IPs"
                    ],
                    "T1110.004": [
                        "Monitor for login attempts with credentials known to be exposed in breaches",
                        "Implement multi-factor authentication",
                        "Deploy account fraud detection"
                    ],
                    "T1083": [
                        "Restrict file system permissions",
                        "Monitor for unusual file access patterns",
                        "Implement application control"
                    ],
                    "T1046": [
                        "Deploy network intrusion detection systems",
                        "Monitor for port scanning activity",
                        "Implement network segmentation"
                    ],
                    "T1048": [
                        "Monitor for unusual outbound connections",
                        "Implement data loss prevention solutions",
                        "Block unauthorized protocols at network boundaries"
                    ],
                    "T1567": [
                        "Monitor for unusual uploads to web services",
                        "Implement web filtering to block unauthorized services",
                        "Deploy data loss prevention solutions"
                    ],
                    "T1567.002": [
                        "Monitor for unusual access to cloud storage",
                        "Implement cloud access security broker (CASB) solutions",
                        "Restrict access to cloud storage services"
                    ]
                }
                
                for technique in top_techniques:
                    if technique in mitre_defense_recommendations:
                        st.write(f"**For {technique}:**")
                        for recommendation in mitre_defense_recommendations[technique]:
                            st.write(f"- {recommendation}")
            else:
                st.warning("No predictions could be generated with the current settings")
        
        # Show model information
        with st.expander("Model Information"):
            st.write(f"Model Accuracy: {model_data['accuracy']:.2f}")
            
            st.write("Feature Importance:")
            fig = px.bar(
                model_data["feature_importance"],
                x="Feature",
                y="Importance",
                title="Feature Importance",
                height=300
            )
            st.plotly_chart(fig, use_container_width=True, key="ml_prediction_fig2")
