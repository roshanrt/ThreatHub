import unittest
from soc_copilot import generate_copilot_response

class TestSocCopilot(unittest.TestCase):

    def setUp(self):
        self.knowledge_base = {
            "techniques": {
                "T1566": {
                    "name": "Phishing",
                    "tactic_id": "TA0001",
                    "description": "Phishing is a technique used to steal credentials."
                }
            },
            "tactics": {
                "TA0001": {
                    "name": "Initial Access",
                    "description": "Techniques that use various entry points to gain access."
                }
            }
        }

    def test_generate_copilot_response_valid_query(self):
        query = "What is T1566?"
        iocs = {}
        ttps = ["T1566"]
        actors = []
        malware = []
        response = generate_copilot_response(query, iocs, ttps, actors, malware, self.knowledge_base)
        self.assertIn("Phishing", response)
        self.assertIn("Initial Access", response)

    def test_generate_copilot_response_missing_key(self):
        query = "What is T9999?"
        iocs = {}
        ttps = ["T9999"]
        actors = []
        malware = []
        response = generate_copilot_response(query, iocs, ttps, actors, malware, self.knowledge_base)
        self.assertIn("Error", response)

if __name__ == "__main__":
    unittest.main()