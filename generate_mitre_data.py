import json
import os
import enterpriseattack

# Initialize the ATT&CK object
attack = enterpriseattack.Attack()

# Prepare output structure
output = {
    "tactics": [],
    "techniques": []
}

# Collect all tactics
print("[*] Extracting tactics...")
for tactic in attack.tactics:
    output["tactics"].append({
        "tactic_id": tactic.id,  # changed from tactic.external_id to tactic.id
        "tactic_name": tactic.name,
        "description": tactic.description or ""
    })
print(f"[+] Extracted {len(output['tactics'])} tactics.")

# Map tactic name to ID
tactic_name_to_id = {t["tactic_name"]: t["tactic_id"] for t in output["tactics"]}

# Collect all techniques
print("[*] Extracting techniques...")
for technique in attack.techniques:
    for tactic in technique.tactics:
        tactic_id = tactic_name_to_id.get(tactic.name)
        if tactic_id:
            output["techniques"].append({
                "technique_id": technique.id,  # changed from technique.external_id to technique.id
                "technique_name": technique.name,
                "tactic_id": tactic_id,
                "description": technique.description or ""
            })
print(f"[+] Extracted {len(output['techniques'])} techniques.")

# Save to file
os.makedirs("data_resources", exist_ok=True)
output_path = "data_resources/mitre_attack_ttps.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)

print(f"[✓] Saved TTP data to {output_path}")
