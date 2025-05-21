import requests
import json
import os

# Constants
OUTPUT_DIR = "data_resources"
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "mitre_attack_techniques.json")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def fetch_mitre_data(url):
    """Fetch MITRE ATT&CK data from the given URL."""
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

def parse_tactics(data):
    """Parse tactics from MITRE ATT&CK data."""
    tactics = {}
    for obj in data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            tactic_id = next((ref["external_id"] for ref in obj.get("external_references", []) if "external_id" in ref), None)
            if tactic_id:
                tactics[tactic_id] = {
                    "tactic_id": tactic_id,
                    "tactic_name": obj.get("name"),
                    "description": obj.get("description", "")
                }
    return tactics

def parse_techniques(data, tactics):
    """Parse techniques from MITRE ATT&CK data."""
    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            technique_id = next((ref["external_id"] for ref in obj.get("external_references", []) if "external_id" in ref and ref["external_id"].startswith("T")), None)
            technique_name = obj.get("name")
            description = obj.get("description", "")
            for phase in obj.get("kill_chain_phases", []):
                tactic_name = phase.get("phase_name")
                tactic_id = next((t["tactic_id"] for t in tactics.values() if t["tactic_name"].lower().replace(" ", "_") == tactic_name), None)
                if tactic_id and technique_id:
                    techniques.append({
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "tactic_id": tactic_id,
                        "description": description
                    })
    return techniques

def save_to_file(data, file_path):
    """Save data to a JSON file."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"MITRE ATT&CK data saved to {file_path}")

def main():
    """Main function to fetch, parse, and save MITRE ATT&CK data."""
    try:
        data = fetch_mitre_data(MITRE_URL)
        tactics = parse_tactics(data)
        techniques = parse_techniques(data, tactics)
        result = {
            "tactics": list(tactics.values()),
            "techniques": techniques
        }
        save_to_file(result, OUTPUT_FILE)
    except requests.RequestException as e:
        print(f"Error fetching MITRE ATT&CK data: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
