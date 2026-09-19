"""Unit tests for secret_scanner.core.reporter SARIF export"""

import json
import unittest

from secret_scanner.core.reporter import generate_sarif_report


class TestSarifReporter(unittest.TestCase):

    def test_sarif_structure(self):
        findings = [
            {
                "type": "aws_access_key",
                "rule_name": "AWS Access Key ID",
                "severity": "HIGH",
                "file": "config.env",
                "line": 4,
                "col": 19,
                "score": 0.85,
                "fingerprint": "abc1234567890def",
                "masked_value": "AKIAIOSFODN****PLE",
                "context": "AWS_ACCESS_KEY_ID=AKIAIOSFODN****PLE",
            },
            {
                "type": "private_key",
                "rule_name": "RSA/OPENSSH/EC Private Key",
                "severity": "CRITICAL",
                "file": "keys/id_rsa",
                "line": 1,
                "col": 1,
                "score": 0.98,
                "fingerprint": "fedcba0987654321",
                "masked_value": "-----BEGIN RSA PRIVATE KEY-----",
                "context": "-----BEGIN RSA PRIVATE KEY-----",
                "commit_hash": "a1b2c3d4",
            },
        ]

        sarif_str = generate_sarif_report(findings, target_path="my_project")
        sarif = json.loads(sarif_str)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "SecretScanner")
        self.assertEqual(len(run["results"]), 2)

        # Check result 1
        res1 = run["results"][0]
        self.assertEqual(res1["ruleId"], "aws_access_key")
        self.assertEqual(res1["level"], "error")
        self.assertEqual(res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "config.env")
        self.assertEqual(res1["locations"][0]["physicalLocation"]["region"]["startLine"], 4)

        # Check result 2
        res2 = run["results"][1]
        self.assertEqual(res2["ruleId"], "private_key")
        self.assertEqual(res2["level"], "error")
        self.assertEqual(res2["properties"]["commitHash"], "a1b2c3d4")


if __name__ == "__main__":
    unittest.main()
