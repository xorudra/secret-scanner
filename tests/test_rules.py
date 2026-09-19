"""Unit tests for secret_scanner.core.rules"""

import tempfile
import unittest
from pathlib import Path

from secret_scanner.core.rules import Rule, load_rules, DEFAULT_RULES_PATH


class TestRules(unittest.TestCase):

    def test_default_rules_load(self):
        rules = load_rules()
        self.assertGreaterEqual(len(rules), 30)
        rule_ids = [r.rule_id for r in rules]
        self.assertIn("aws_access_key", rule_ids)
        self.assertIn("github_token", rule_ids)
        self.assertIn("private_key", rule_ids)
        self.assertIn("openai_api_key", rule_ids)
        self.assertIn("gcp_api_key", rule_ids)
        self.assertIn("azure_connection_string", rule_ids)
        self.assertIn("slack_webhook", rule_ids)
        self.assertIn("anthropic_key", rule_ids)
        self.assertIn("huggingface_token", rule_ids)
        self.assertIn("npm_token", rule_ids)

    def test_rule_extract_secret_with_group(self):
        rule = Rule(
            rule_id="test_key",
            name="Test Key",
            pattern=r"API_KEY=([a-zA-Z0-9]{10,})",
            severity="HIGH",
        )
        match = rule.pattern.search("export API_KEY=abc123xyz999")
        self.assertIsNotNone(match)
        extracted = rule.extract_secret(match)
        self.assertEqual(extracted, "abc123xyz999")

    def test_rule_extract_secret_no_group(self):
        rule = Rule(
            rule_id="test_token",
            name="Test Token",
            pattern=r"ghp_[a-zA-Z0-9]{36}",
            severity="HIGH",
        )
        match = rule.pattern.search("my token is ghp_123456789012345678901234567890123456")
        self.assertIsNotNone(match)
        extracted = rule.extract_secret(match)
        self.assertEqual(extracted, "ghp_123456789012345678901234567890123456")

    def test_custom_yaml_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            tf_path = Path(temp_dir) / "custom_rules.yaml"
            tf_path.write_text("""rules:
  - id: custom_token
    name: "Custom Company Token"
    pattern: "CORP_[0-9A-Z]{12}"
    severity: "CRITICAL"
    description: "Internal company token"
""", encoding="utf-8")

            custom_rules = load_rules(tf_path)
            self.assertEqual(len(custom_rules), 1)
            self.assertEqual(custom_rules[0].rule_id, "custom_token")
            self.assertEqual(custom_rules[0].severity, "CRITICAL")
            self.assertEqual(custom_rules[0].description, "Internal company token")


if __name__ == "__main__":
    unittest.main()
