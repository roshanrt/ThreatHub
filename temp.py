import sys
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

# Replace with your actual OTX API key
API_KEY = '37f90b51674fe0e181c752cd1bcec3f5c3e0bce4bb21730097455036fa7db290'

def fetch_subscribed_pulses(api_key):
    otx = OTXv2(api_key)
    try:
        # Fetch pulses you've subscribed to
        pulses = otx.getall()
        print(f"Retrieved {len(pulses)} pulses.")
        return pulses
    except Exception as e:
        print(f"Error fetching pulses: {e}")
        sys.exit(1)

def fetch_indicators_from_pulses(otx, pulses):
    indicators = []
    for pulse in pulses:
        pulse_id = pulse.get('id')
        pulse_name = pulse.get('name')
        try:
            pulse_indicators = otx.get_pulse_indicators(pulse_id)
            for indicator in pulse_indicators:
                indicators.append({
                    'pulse_name': pulse_name,
                    'indicator': indicator.get('indicator'),
                    'type': indicator.get('type'),
                    'description': indicator.get('description')
                })
        except Exception as e:
            print(f"Error fetching indicators for pulse {pulse_id}: {e}")
    return indicators

def main():
    otx = OTXv2(API_KEY)
    pulses = fetch_subscribed_pulses(API_KEY)
    indicators = fetch_indicators_from_pulses(otx, pulses)
    
    print(f"\nTotal indicators retrieved: {len(indicators)}\n")
    for idx, indicator in enumerate(indicators, start=1):
        print(f"{idx}. Pulse: {indicator['pulse_name']}")
        print(f"   Indicator: {indicator['indicator']}")
        print(f"   Type: {indicator['type']}")
        print(f"   Description: {indicator['description']}\n")

if __name__ == "__main__":
    main()
