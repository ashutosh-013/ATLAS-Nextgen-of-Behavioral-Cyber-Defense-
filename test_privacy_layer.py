"""
Unit Test Suite for ATLAS Privacy Layer Engine.
"""

import unittest
from privacy.sanitizer import PrivacyLayerEngine, get_privacy_engine


class TestPrivacyLayer(unittest.TestCase):

    def setUp(self):
        self.privacy = get_privacy_engine()

    def test_1_password_redaction(self):
        """Verify command line password redaction."""
        cmd = "mysql -u admin -pSuperSecret123! --host localhost"
        res = self.privacy.sanitize_text(cmd)
        self.assertNotIn("SuperSecret123!", res.sanitized_text)
        self.assertIn("[REDACTED_PASSWORD]", res.sanitized_text)

    def test_2_api_key_redaction(self):
        """Verify API key and bearer token redaction."""
        cmd = "curl -H 'Authorization: Bearer sk-proj-1234567890qwertyuiopasdfghjklzxcvbnm' http://api.example.com"
        res = self.privacy.sanitize_text(cmd)
        self.assertNotIn("sk-proj-1234567890qwertyuiopasdfghjklzxcvbnm", res.sanitized_text)
        self.assertIn("[REDACTED_TOKEN]", res.sanitized_text)

    def test_3_pii_redaction(self):
        """Verify Credit Card, SSN, and Email redaction."""
        text = "Contact user john.doe@company.com with SSN 123-45-6789 and CC 4532-1234-5678-9012"
        res = self.privacy.sanitize_text(text)
        self.assertNotIn("john.doe@company.com", res.sanitized_text)
        self.assertNotIn("123-45-6789", res.sanitized_text)
        self.assertIn("[REDACTED_EMAIL]", res.sanitized_text)
        self.assertIn("[REDACTED_SSN]", res.sanitized_text)
        self.assertIn("[REDACTED_CC]", res.sanitized_text)

    def test_4_user_path_anonymization(self):
        """Verify user profile home path anonymization."""
        path = "C:\\Users\\JaneDoe\\Documents\\ConfidentialPlan.pdf"
        res = self.privacy.sanitize_text(path)
        self.assertNotIn("JaneDoe", res.sanitized_text)
        self.assertIn("[REDACTED_USER]", res.sanitized_text)

    def test_5_recursive_dict_sanitization(self):
        """Verify recursive dictionary event payload sanitization."""
        event_data = {
            "cmd": "powershell -enc AAAA -pass MySecretPass123",
            "metadata": {
                "user_email": "admin@atlas.sec",
                "path": "C:\\Users\\Alice\\Secrets\\key.pem"
            }
        }
        sanitized = self.privacy.sanitize_event_dict(event_data)
        self.assertNotIn("MySecretPass123", sanitized["cmd"])
        self.assertNotIn("admin@atlas.sec", sanitized["metadata"]["user_email"])
        self.assertNotIn("Alice", sanitized["metadata"]["path"])


if __name__ == "__main__":
    unittest.main()
