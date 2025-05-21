CyberShield is an advanced cybersecurity platform designed to revolutionize threat intelligence and detection engineering. It leverages AI and automation to streamline the extraction of Indicators of Compromise (IOCs), map Tactics, Techniques, and Procedures (TTPs) to the MITRE ATT&CK framework, and generate actionable security content such as Sigma, YARA, and Snort rules.

🎯 What We Aim to Do:
Automate the ingestion and analysis of threat intelligence reports (PDF, JSON).

Extract and visualize IOCs and TTPs using advanced NLP and AI models.

Predict emerging TTP trends to proactively strengthen defenses.

Provide a SOC Copilot powered by AI for real-time analyst support and faster decision-making.

Automatically generate and export security detection rules for popular security tools.

Deliver interactive dashboards and comprehensive PDF reports to simplify threat analysis.

CyberShield empowers security teams to reduce manual effort, improve threat detection accuracy, and respond to cyber threats faster and more effectively.

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/threathub.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   streamlit run app.py
   ```

4. Configure TAXII servers and other settings in the application interface.

## Troubleshooting

- If you encounter issues with TAXII server connections, ensure the server details are correct and retry.
- For MFA setup, ensure you have a compatible authenticator app like Google Authenticator or Authy.
