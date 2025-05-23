from OTXv2 import OTXv2
import json

# Replace with your API key
API_KEY = "37f90b51674fe0e181c752cd1bcec3f5c3e0bce4bb21730097455036fa7db290"

def list_collections(api_key, query="", limit=20):
    otx = OTXv2(api_key)
    try:
        results = otx.search_pulses(query=query, page=1)
        pulses = results.get("results", [])[:limit]

        for i, pulse in enumerate(pulses, 1):
            print(f"\n[{i}] Title: {pulse['name']}")
            print(f"    ID: {pulse['id']}")
            print(f"    Author: {pulse.get('author_name', 'Unknown')}")
            print(f"    Created: {pulse['created']}")
            print(f"    Tags: {', '.join(pulse.get('tags', []))}")
    except Exception as e:
        print(f"[!] Error fetching collections: {e}")

if __name__ == "__main__":
    list_collections(API_KEY, query="", limit=10)
