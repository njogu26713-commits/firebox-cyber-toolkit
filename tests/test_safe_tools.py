import tempfile
import unittest
from pathlib import Path

from firebox.modules import safe_tools


class SafeToolsTests(unittest.TestCase):
    def test_phone_is_format_only(self):
        result = safe_tools.phone_validate("+254 700-000-000")
        self.assertTrue(result["valid_format"])
        self.assertIn("no identity", result["scope"])

    def test_pdf_info(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf") as handle:
            handle.write(b"%PDF-1.7\nsynthetic")
            handle.flush()
            result = safe_tools.pdf_info(handle.name)
            self.assertTrue(result["is_pdf"])
            self.assertEqual(result["pdf_version"], "1.7")

    def test_vpn_audit_does_not_print_secrets(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as handle:
            handle.write("remote vpn.example.test 1194\nauth-user-pass\ncipher AES-256-GCM\n")
            path = handle.name
        result = safe_tools.vpn_audit(path)
        self.assertFalse(result["secrets_printed"])
        self.assertEqual(result["findings"], [])

    def test_process_inventory(self):
        result = safe_tools.process_audit()
        self.assertGreaterEqual(result["process_count"], 1)
        self.assertIn("scope", result)


if __name__ == "__main__":
    unittest.main()
