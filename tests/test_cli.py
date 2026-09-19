"""Unit tests for secret_scanner.core.scanner CLI"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestCLI(unittest.TestCase):

    def test_cli_json_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            f = Path(temp_dir) / "test.env"
            f.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, "-m", "secret_scanner.core.scanner", temp_dir, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
            data = json.loads(proc.stdout)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["type"], "aws_access_key")

    def test_cli_ci_flag_fails_on_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            f = Path(temp_dir) / "test.env"
            f.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, "-m", "secret_scanner.core.scanner", temp_dir, "--ci"],
                capture_output=True,
                text=True,
            )
            # Must exit with code 1 in CI mode when secret is present
            self.assertEqual(proc.returncode, 1)

    def test_cli_ci_flag_passes_on_clean(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            f = Path(temp_dir) / "clean.txt"
            f.write_text("Just regular documentation.\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, "-m", "secret_scanner.core.scanner", temp_dir, "--ci"],
                capture_output=True,
                text=True,
            )
            # Must exit with code 0 in CI mode when clean
            self.assertEqual(proc.returncode, 0)

    def test_cli_export_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = Path(temp_dir) / "src.py"
            src.write_text("TOKEN = 'ghp_123456789012345678901234567890123456'\n", encoding="utf-8")

            html_out = Path(temp_dir) / "report.html"
            md_out = Path(temp_dir) / "report.md"
            sarif_out = Path(temp_dir) / "report.sarif"

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "secret_scanner.core.scanner",
                    temp_dir,
                    "--html", str(html_out),
                    "--markdown", str(md_out),
                    "--sarif", str(sarif_out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(html_out.exists())
            self.assertTrue(md_out.exists())
            self.assertTrue(sarif_out.exists())

            # Check sarif content
            sarif = json.loads(sarif_out.read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")

    def test_cli_git_scan_success(self):
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

            proc = subprocess.run(
                [sys.executable, "-m", "secret_scanner.core.scanner", "--git", temp_dir, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
            data = json.loads(proc.stdout)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["type"], "aws_access_key")
            self.assertIn("commit_hash", data[0])

    def test_cli_git_scan_invalid_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            proc = subprocess.run(
                [sys.executable, "-m", "secret_scanner.core.scanner", "--git", temp_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("[ERROR] Git scan failed", proc.stderr)


if __name__ == "__main__":
    unittest.main()

