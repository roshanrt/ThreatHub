import unittest
from stix_taxii_integration import extract_iocs_from_stix

class TestStixTaxiiIntegration(unittest.TestCase):

    def test_extract_iocs_from_stix_valid_data(self):
        stix_objects = [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '192.168.1.1']"
            },
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'example.com']"
            }
        ]
        iocs = extract_iocs_from_stix(stix_objects)
        self.assertIn("192.168.1.1", iocs["ipv4"])
        self.assertIn("example.com", iocs["domain"])

    def test_extract_iocs_from_stix_empty_data(self):
        stix_objects = []
        iocs = extract_iocs_from_stix(stix_objects)
        self.assertEqual(iocs, {
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
        })

if __name__ == "__main__":
    unittest.main()