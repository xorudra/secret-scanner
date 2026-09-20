"""Unit tests for secret_scanner.core.engine"""

import tempfile
import unittest
from pathlib import Path

from secret_scanner.core.detectors import mask_secret, shannon_entropy
from secret_scanner.core.engine import DetectionEngine, scan_path


class TestEngine(unittest.TestCase):

    def test_shannon_entropy_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_shannon_entropy_high_vs_low(self):
        high_rand = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        low_rand = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.assertGreater(shannon_entropy(high_rand), shannon_entropy(low_rand))

    def test_mask_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        masked = mask_secret(secret)
        self.assertNotIn("NN7EX", masked)
        self.assertTrue(masked.startswith("AKIA"))
        self.assertTrue(masked.endswith("MPLE"))

    def test_detection_engine_aws_key(self):
        engine = DetectionEngine()
        sample = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        findings = engine.scan(sample, file_path="test.env")
        self.assertGreater(len(findings), 0)
        types = [f.secret_type for f in findings]
        self.assertIn("aws_secret_key", types)
        # Check severity is assigned
        f = findings[0]
        self.assertEqual(f.severity, "HIGH")
        self.assertIn("****", f.masked_value)

    def test_detection_engine_private_key(self):
        engine = DetectionEngine()
        sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        findings = engine.scan(sample, file_path="id_rsa")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_false_positive_type_annotations(self):
        """Python function signatures with `secret: str` should not trigger leaks."""
        engine = DetectionEngine()
        sample = "def calculate_hash(secret: str, salt: Optional[str] = None) -> str:\n    pass"
        findings = engine.scan(sample, file_path="utils.py")
        self.assertEqual(findings, [])

    def test_scan_file_and_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "creds.txt"
            file_path.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
            findings = scan_path(temp_dir)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["type"], "aws_access_key")
            self.assertEqual(findings[0]["severity"], "HIGH")

    def test_detection_engine_openai_key(self):
        engine = DetectionEngine()
        sample = "OPENAI_API_KEY=sk-proj-abcde12345FGHIJ67890klmno12345pqrst67890UVWX"
        findings = engine.scan(sample, file_path="config.py")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].secret_type, "openai_api_key")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_detection_engine_google_api_key(self):
        engine = DetectionEngine()
        sample = "GOOGLE_KEY=AIzaSy" + ("A" * 33)
        findings = engine.scan(sample, file_path="app.json")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].secret_type, "gcp_api_key")

    def test_scan_path_multithreading(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            for i in range(5):
                sub_file = dir_path / f"creds_{i}.env"
                sub_file.write_text(f"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMP{i:02d}\n", encoding="utf-8")
            findings = scan_path(temp_dir, max_workers=4)
            self.assertEqual(len(findings), 5)

    def test_scan_path_nonexistent(self):
        findings = scan_path("non_existent_folder_xyz_123")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
