"""Unit tests for secret_scanner.api.app"""

import asyncio
import json
import unittest

from fastapi import HTTPException

from secret_scanner.api.app import (
    ReportExportRequest,
    ScanGitRequest,
    ScanTextRequest,
    export_html_report,
    export_markdown_report,
    export_sarif_report,
    get_rules,
    health,
    scan_git,
    scan_text,
)


class TestAPI(unittest.TestCase):

    def test_health_endpoint(self):
        res = asyncio.run(health())
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["service"], "secret-scanner")

    def test_rules_endpoint(self):
        res = asyncio.run(get_rules())
        self.assertIn("rules", res)
        self.assertIn("patterns", res)
        self.assertIn("aws_access_key", res["patterns"])
        self.assertGreater(res["count"], 5)

    def test_scan_text_endpoint(self):
        req = ScanTextRequest(text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        res = asyncio.run(scan_text(req))
        self.assertGreater(res.count, 0)
        self.assertEqual(len(res.findings), res.count)
        self.assertEqual(res.findings[0]["type"], "aws_access_key")
        self.assertEqual(res.findings[0]["severity"], "HIGH")

    def test_scan_text_payload_limit(self):
        huge_payload = "A" * (2 * 1024 * 1024 + 10)
        with self.assertRaises(ValueError):
            ScanTextRequest(text=huge_payload)

    def test_report_export_endpoints(self):
        findings = [{
            "type": "aws_access_key",
            "rule_name": "AWS Access Key ID",
            "severity": "HIGH",
            "file": "env.local",
            "line": 1,
            "col": 1,
            "score": 0.85,
            "fingerprint": "abc12345",
            "masked_value": "AKIAIOSFODN****PLE",
            "context": "AKIAIOSFODN****PLE",
        }]
        req = ReportExportRequest(findings=findings, target_path="test_run")

        # HTML
        html_resp = asyncio.run(export_html_report(req))
        self.assertIn(b"SecretScanner Security Audit Report", html_resp.body)

        # Markdown
        md_resp = asyncio.run(export_markdown_report(req))
        self.assertIn(b"SecretScanner Security Audit Report", md_resp.body)

        # SARIF
        sarif_resp = asyncio.run(export_sarif_report(req))
        data = json.loads(sarif_resp.body.decode("utf-8"))
        self.assertEqual(data["version"], "2.1.0")

    def test_scan_git_endpoint(self):
        import tempfile
        from pathlib import Path

        import git
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = git.Repo.init(str(repo_path))
            try:
                secret_file = repo_path / "secret.env"
                secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
                repo.index.add(["secret.env"])
                repo.index.commit("Add secret")
            finally:
                repo.close()

            req = ScanGitRequest(repo_path=temp_dir)
            res = asyncio.run(scan_git(req))
            self.assertEqual(res.count, 1)
            self.assertEqual(res.findings[0]["type"], "aws_access_key")

    def test_scan_git_endpoint_invalid_path(self):
        req = ScanGitRequest(repo_path="this_path_does_not_exist_xyz123")
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(scan_git(req))
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()

