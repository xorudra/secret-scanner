"""secret_scanner.core.scanner
Command-line interface for SecretScanner.

Usage Examples
--------------
    # Scan working directory
    python -m secret_scanner.core.scanner .

    # Scan Git repository commit history
    python -m secret_scanner.core.scanner --git .

    # Generate SARIF, HTML, and Markdown reports
    python -m secret_scanner.core.scanner . --sarif audit.sarif --html audit.html --markdown audit.md

    # Run in CI mode (exits with code 1 if secrets are found)
    python -m secret_scanner.core.scanner . --ci

    # Use custom YAML detection rules
    python -m secret_scanner.core.scanner . --rules my_rules.yaml

    # Install automated Git pre-commit hook
    python -m secret_scanner.core.scanner --install-hook
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

from secret_scanner.core.engine import DetectionEngine, scan_path
from secret_scanner.core.hook import install_pre_commit_hook
from secret_scanner.core.reporter import (
    generate_html_report,
    generate_markdown_report,
    generate_sarif_report,
)
from secret_scanner.git_scanner import is_git_url, scan_repository


def print_cli_banner() -> None:
    """Print standard header banner."""
    print("=" * 70)
    print("  [SecretScanner] Privacy-First Credential Leak Detection")
    print("=" * 70)


def format_terminal_findings(findings: list[dict[str, Any]]) -> None:
    """Display finding records clearly on standard output."""
    if not findings:
        print("\n[CLEAN] No secrets or leaked credentials detected.\n")
        return

    print(f"\n[ALERT] Found {len(findings)} potential secret leak(s):\n")
    print("-" * 70)

    for idx, f in enumerate(findings, start=1):
        sev = f.get("severity", "MEDIUM").upper()
        rule_name = f.get("rule_name") or f.get("type", "Secret")
        loc = f"{f.get('file', '<unknown>')}:{f.get('line', 1)}:{f.get('col', 1)}"
        masked = f.get("masked_value", "****")
        score = f.get("score", 0.0)

        print(f"[{idx}] [{sev}] {rule_name} (Risk Score: {score})")
        print(f"    Location: {loc}")
        print(f"    Masked:   {masked}")
        if "commit_hash" in f:
            print(f"    Git:      Commit {f['commit_hash']} by {f.get('commit_author', 'unknown')}")
        if "context" in f and f["context"] != masked:
            print(f"    Context:  {f['context']}")
        print("-" * 70)


def main() -> None:
    """CLI entry point with comprehensive flags."""
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Privacy-first secret and credential leak detection utility.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Directory or file path to scan (default: current directory).",
    )
    parser.add_argument(
        "--git",
        nargs="?",
        const=".",
        metavar="REPO_PATH",
        help="Scan a Git repository's full commit history across all branches or a remote repository URL.",
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=None,
        metavar="N",
        help="Maximum number of historical Git commits to scan (default: all).",
    )
    parser.add_argument(
        "--rules",
        metavar="FILE",
        help="Path to custom YAML detection rules file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw scan findings formatted as JSON to stdout.",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Write an HTML security audit report to target file.",
    )
    parser.add_argument(
        "--markdown",
        metavar="FILE",
        help="Write a Markdown security audit report to target file.",
    )
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write an OASIS SARIF v2.1.0 report for CI/CD and GitHub Security.",
    )
    parser.add_argument(
        "--ci",
        "--fail-on-findings",
        dest="ci_mode",
        action="store_true",
        help="Exit with return code 1 if any secrets are detected (for CI/CD gates).",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install Git pre-commit hook into target repository.",
    )

    args = parser.parse_args()

    # Pre-commit hook installation
    if args.install_hook:
        repo_dir = pathlib.Path(args.target).resolve()
        success = install_pre_commit_hook(repo_dir)
        sys.exit(0 if success else 1)

    # Initialize detection engine with custom rules if provided
    custom_rules_path = pathlib.Path(args.rules).resolve() if args.rules else None
    if custom_rules_path and not custom_rules_path.exists():
        print(f"[ERROR] Custom rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)

    engine = DetectionEngine(custom_rules_path=custom_rules_path)

    # Determine scan mode: Git repository scan or file/directory scan
    is_git = False
    git_target_input = None

    if args.git is not None:
        is_git = True
        if args.target != "." and args.git == ".":
            git_target_input = args.target
        else:
            git_target_input = args.git
    elif is_git_url(args.target):
        is_git = True
        git_target_input = args.target

    if is_git:
        if not args.json:
            print_cli_banner()
            print(f"[SCANNING] Git commit history in: {git_target_input} ...")
        try:
            findings = scan_repository(
                git_target_input,
                max_commits=args.max_commits,
                engine=engine,
                custom_rules_path=custom_rules_path,
            )
        except (OSError, ValueError, RuntimeError) as err:
            print(f"[ERROR] Git scan failed: {err}", file=sys.stderr)
            sys.exit(1)
        scan_target_str = f"git:{git_target_input}"
    else:
        target_path = pathlib.Path(args.target).resolve()
        if not target_path.exists():
            print(f"[ERROR] Target path does not exist: {args.target}", file=sys.stderr)
            sys.exit(1)
        if not args.json:
            print_cli_banner()
            print(f"[SCANNING] Files in: {target_path} ...")
        findings = scan_path(target_path, engine=engine, custom_rules_path=custom_rules_path)
        scan_target_str = str(target_path)

    # Write report files if requested
    if args.html:
        report_html = generate_html_report(findings, target_path=scan_target_str)
        pathlib.Path(args.html).write_text(report_html, encoding="utf-8")
        if not args.json:
            print(f"[OK] HTML report saved: {args.html}")

    if args.markdown:
        report_md = generate_markdown_report(findings, target_path=scan_target_str)
        pathlib.Path(args.markdown).write_text(report_md, encoding="utf-8")
        if not args.json:
            print(f"[OK] Markdown report saved: {args.markdown}")

    if args.sarif:
        report_sarif = generate_sarif_report(findings, target_path=scan_target_str)
        pathlib.Path(args.sarif).write_text(report_sarif, encoding="utf-8")
        if not args.json:
            print(f"[OK] SARIF report saved: {args.sarif}")

    # Output to stdout
    if args.json:
        print(json.dumps(findings, indent=2))
    elif not args.html and not args.markdown and not args.sarif:
        format_terminal_findings(findings)

    # Exit code in CI mode
    if args.ci_mode and findings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
