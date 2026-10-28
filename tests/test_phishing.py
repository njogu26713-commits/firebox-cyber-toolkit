import tempfile
import unittest
from pathlib import Path

from firebox.modules import phishing


class PhishingTests(unittest.TestCase):
    def test_analyze_static_message(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.eml"
            path.write_text(
                "From: sender@example.test\nReply-To: other@example.test\n"
                "Subject: Urgent account alert\nAuthentication-Results: dmarc=fail\n"
                "Content-Type: text/plain\n\nAct now: http://example.test/login\n",
                encoding="utf-8",
            )
            result = phishing.analyze(str(path))
            titles = {item["title"] for item in result["findings"]}
            self.assertIn("From and Reply-To differ", titles)
            self.assertIn("Urgency language detected", titles)
            self.assertIn("Link is not HTTPS", titles)
            self.assertEqual(result["scope"].split(";")[0], "Static analysis only")

    def test_template_is_synthetic_and_non_deliverable(self):
        content = phishing.template("account-alert")
        self.assertIn("TRAINING ONLY", content)
        self.assertIn("no real brand", content)
        self.assertNotIn("http://", content)
        self.assertNotIn("https://", content)

    def test_invalid_template_scenario_rejected(self):
        with self.assertRaises(ValueError):
            phishing.template("real-brand")


if __name__ == "__main__":
    unittest.main()
