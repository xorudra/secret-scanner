"""Unit tests for secret_scanner.git_scanner"""

import tempfile
import unittest
from pathlib import Path

import git

from secret_scanner.git_scanner import scan_repository, iter_git_objects, is_git_url


class TestGitScanner(unittest.TestCase):

    def test_is_git_url(self):
        self.assertTrue(is_git_url("https://github.com/torvalds/linux.git"))
        self.assertTrue(is_git_url("http://gitlab.com/user/project.git"))
        self.assertTrue(is_git_url("git@github.com:user/repo.git"))
        self.assertTrue(is_git_url("ssh://git@github.com/user/repo.git"))
        self.assertTrue(is_git_url("git://github.com/user/repo.git"))
        self.assertFalse(is_git_url("."))
        self.assertFalse(is_git_url("C:\\Users\\test\\repo"))
        self.assertFalse(is_git_url("/home/user/repo"))

    def test_scan_git_repository_history(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = git.Repo.init(str(repo_path))
            try:
                # Commit 1: Clean file
                clean_file = repo_path / "readme.md"
                clean_file.write_text("# Project Docs\nNothing secret here.\n", encoding="utf-8")
                repo.index.add(["readme.md"])
                commit_1 = repo.index.commit("Initial commit (clean)")

                # Commit 2: Leaked credential
                secret_file = repo_path / "config.env"
                secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
                repo.index.add(["config.env"])
                commit_2 = repo.index.commit("Add config with credentials")

                # Scan the repo
                findings = scan_repository(repo_path)
                self.assertGreater(len(findings), 0)

                f = findings[0]
                self.assertEqual(f["type"], "aws_access_key")
                self.assertEqual(f["severity"], "HIGH")
                self.assertIn("commit_hash", f)
                self.assertEqual(f["commit_hash"], commit_2.hexsha[:8])
                self.assertIn("commit_author", f)
                self.assertEqual(f["commit_message"], "Add config with credentials")
            finally:
                repo.close()

    def test_scan_git_repository_subdirectory(self):
        """Scanning a subdirectory within a git repo should resolve to the repo root."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = git.Repo.init(str(repo_path))
            try:
                sub_dir = repo_path / "src" / "deep"
                sub_dir.mkdir(parents=True)
                secret_file = sub_dir / "keys.py"
                secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
                repo.index.add(["src/deep/keys.py"])
                repo.index.commit("Add secret in subfolder")

                # Scan from sub_dir
                findings = scan_repository(sub_dir)
                self.assertGreater(len(findings), 0)
                self.assertEqual(findings[0]["type"], "aws_access_key")
            finally:
                repo.close()

    def test_git_scanner_respects_ignore_file(self):
        """Files matched by .secretscannerignore should not produce findings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = git.Repo.init(str(repo_path))
            try:
                # Add ignore file
                ignore_file = repo_path / ".secretscannerignore"
                ignore_file.write_text("tests/*\nmock_*\n", encoding="utf-8")
                repo.index.add([".secretscannerignore"])

                # Add ignored secret file
                tests_dir = repo_path / "tests"
                tests_dir.mkdir()
                mock_file = tests_dir / "mock_secret.py"
                mock_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
                repo.index.add(["tests/mock_secret.py"])
                repo.index.commit("Commit with ignored files")

                findings = scan_repository(repo_path)
                self.assertEqual(len(findings), 0)
            finally:
                repo.close()

    def test_scan_invalid_and_nonexistent_repository(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            # Not a git repo
            with self.assertRaises(ValueError):
                scan_repository(temp_dir)

        # Nonexistent path
        with self.assertRaises(FileNotFoundError):
            scan_repository(Path(temp_dir) / "does_not_exist")

    def test_iter_git_objects_deduplication(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = git.Repo.init(str(repo_path))
            try:
                # Same file across two commits should only yield the blob once due to deduplication
                file1 = repo_path / "static.txt"
                file1.write_text("Hello World\n", encoding="utf-8")
                repo.index.add(["static.txt"])
                repo.index.commit("Commit 1")

                file2 = repo_path / "other.txt"
                file2.write_text("Another file\n", encoding="utf-8")
                repo.index.add(["other.txt"])
                repo.index.commit("Commit 2")

                objects = list(iter_git_objects(repo))
                paths = [obj[1] for obj in objects]
                self.assertEqual(paths.count("static.txt"), 1)
            finally:
                repo.close()


if __name__ == "__main__":
    unittest.main()

