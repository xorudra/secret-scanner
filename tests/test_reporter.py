"""Unit tests for secret_scanner.core.reporter and ignore"""

import unittest
import pathlib
from secret_scanner.core.reporter import generate_html_report, generate_markdown_report
from secret_scanner.core.ignore import IgnoreFilter


class TestReporterAndIgnore(unittest.TestCase):

    def test_html_report_generation(self):
        findings = [{
            "type": "aws_secret_key",
            "file": "config.py",
            "line": 10,
            "col": 5,
            "score": 0.85,
            "fingerprint": "abc123xyz"
        }]
        html_out = generate_html_report(findings, target_path=".")
        self.assertIn("SecretScanner Security Audit Report", html_out)
        self.assertIn("aws_secret_key", html_out)

    def test_markdown_report_generation(self):
        findings = [{
            "type": "aws_secret_key",
            "file": "config.py",
            "line": 10,
            "col": 5,
            "score": 0.85,
            "fingerprint": "abc123xyz"
        }]
        md_out = generate_markdown_report(findings, target_path=".")
        self.assertIn("SecretScanner Security Audit Report", md_out)
        self.assertIn("aws_secret_key", md_out)

    def test_markdown_report_low_severity(self):
        findings = [{
            "type": "custom_rule",
            "file": "config.py",
            "line": 5,
            "col": 1,
            "score": 0.3,
            "severity": "LOW",
            "fingerprint": "xyz789",
            "masked_value": "test***",
            "context": "test***"
        }]
        md_out = generate_markdown_report(findings, target_path=".")
        self.assertIn("🔵 **LOW**", md_out)
        self.assertNotIn("🟡 **MEDIUM**", md_out)

    def test_ignore_filter(self):
        filt = IgnoreFilter()
        self.assertTrue(filt.is_ignored(pathlib.Path("node_modules/package.json")))
        self.assertTrue(filt.is_ignored(pathlib.Path(".venv/lib/site.py")))
        self.assertTrue(filt.is_ignored(pathlib.Path("package-lock.json")))
        self.assertTrue(filt.is_ignored(pathlib.Path("poetry.lock")))
        self.assertTrue(filt.is_ignored(pathlib.Path("Cargo.lock")))
        self.assertTrue(filt.is_ignored(pathlib.Path(".git/objects/abc")))
        self.assertFalse(filt.is_ignored(pathlib.Path("app/main.py")))


if __name__ == "__main__":
    unittest.main()
