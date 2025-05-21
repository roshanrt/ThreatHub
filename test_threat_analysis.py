import unittest
from threat_analysis import process_pdf_threat_report

class TestThreatAnalysis(unittest.TestCase):

    def test_process_pdf_threat_report_valid_pdf(self):
        # Simulate a valid PDF file content
        pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
        result = process_pdf_threat_report(pdf_content)
        self.assertIsNotNone(result)
        self.assertIn("report_type", result)
        self.assertEqual(result["report_type"], "pdf")

    def test_process_pdf_threat_report_invalid_pdf(self):
        # Simulate an invalid PDF file content
        pdf_content = b"This is not a valid PDF file."
        result = process_pdf_threat_report(pdf_content)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()