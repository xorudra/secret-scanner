"""secret_scanner.core.hook
Installs and executes a Git pre-commit hook to prevent secret leaks before they reach version control.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
from typing import List

from secret_scanner.core.engine import DetectionEngine


HOOK_SHELL_SCRIPT = """#!/bin/sh
# SecretScanner Pre-Commit Hook
# Cross-platform runner invoking SecretScanner staged file analysis

if command -v python >/dev/null 2>&1; then
    python -m secret_scanner.core.hook --check
elif command -v python3 >/dev/null 2>&1; then
    python3 -m secret_scanner.core.hook --check
elif command -v py >/dev/null 2>&1; then
    py -m secret_scanner.core.hook --check
else
    echo "[WARNING] SecretScanner: Python not found on PATH. Skipping pre-commit secret check."
    exit 0
fi

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ SecretScanner: Commit aborted due to potential credential leak."
    echo "Please remove or redact sensitive credentials before committing."
    exit 1
fi

exit 0
"""


def get_staged_files(repo_path: pathlib.Path) -> List[str]:
    """Retrieve list of staged file paths from git."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in proc.stdout.splitlines() if f.strip()]
    except Exception:
        return []


def get_staged_content(repo_path: pathlib.Path, rel_path: str) -> str:
    """Retrieve the staged content of a file from Git index."""
    try:
        # Use git show :<path> to read from the staging index
        proc = subprocess.run(
            ["git", "show", f":{rel_path}"],
            cwd=str(repo_path),
            capture_output=True,
            check=True,
        )
        # Fast binary skip
        if b"\x00" in proc.stdout[:8192]:
            return ""
        return proc.stdout.decode("utf-8", errors="ignore")
    except Exception:
        # Fallback to local file if not yet committed
        local_file = repo_path / rel_path
        if local_file.is_file():
            try:
                return local_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return ""
        return ""


def run_pre_commit_check(repo_path: pathlib.Path | None = None) -> int:
    """Analyze all staged files for secrets.

    Returns 0 if clean, 1 if any secrets are detected.
    """
    target_repo = (repo_path or pathlib.Path(".")).resolve()
    staged_files = get_staged_files(target_repo)

    if not staged_files:
        return 0

    print(f"🔍 SecretScanner: Checking {len(staged_files)} staged file(s) for secrets...")
    engine = DetectionEngine()
    total_findings = []

    for rel_path in staged_files:
        content = get_staged_content(target_repo, rel_path)
        if not content:
            continue
        findings = engine.scan(content, file_path=rel_path)
        if findings:
            total_findings.extend(findings)

    if total_findings:
        print(f"\n🚨 [CRITICAL] SecretScanner detected {len(total_findings)} secret(s) in staged files!\n")
        for f in total_findings:
            d = f.to_dict()
            print(f"  • [{d['severity']}] {d['type']} at {d['file']}:{d['line']}:{d['col']}")
            print(f"    Masked:  {d['masked_value']}")
            print(f"    Context: {d['context']}\n")
        return 1

    print("✅ SecretScanner: All staged files clean. Commit authorized.")
    return 0


def install_pre_commit_hook(repo_path: pathlib.Path | None = None) -> bool:
    """Install the pre-commit hook script into target git repository."""
    target_repo = (repo_path or pathlib.Path(".")).resolve()
    git_dir = target_repo / ".git"
    git_hooks_dir = git_dir / "hooks"

    if not git_dir.exists():
        print(f"Initializing Git repository in {target_repo}...")
        try:
            subprocess.run(["git", "init", str(target_repo)], check=True, capture_output=True)
        except Exception as e:
            print(f"[ERROR] Could not initialize Git repo: {e}", file=sys.stderr)
            return False

    git_hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = git_hooks_dir / "pre-commit"

    try:
        hook_file.write_text(HOOK_SHELL_SCRIPT, encoding="utf-8")
        try:
            hook_file.chmod(0o755)
        except Exception:
            pass
        print(f"Git pre-commit hook successfully installed at: {hook_file}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to install pre-commit hook: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(run_pre_commit_check())
    elif "--install" in sys.argv:
        sys.exit(0 if install_pre_commit_hook() else 1)
    else:
        sys.exit(run_pre_commit_check())
