"""Launch the SecretScanner web GUI.

Usage:
    python -m secret_scanner

Opens the dashboard at http://127.0.0.1:<port> (port 8000 by default, with
automatic fallback to the next free port if another app already occupies it).
"""
import socket
import threading
import webbrowser

import uvicorn


def _port_is_free(port: int) -> bool:
    """Return True if nothing is listening on the port.

    Uses a bind probe (authoritative) plus a connect probe. A plain connect
    test is unreliable on Windows: a timed-out connect can be mistaken for a
    free port, so the bind test is done first.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # On Windows this makes the bind strictly exclusive, so it fails
        # even if another process bound the port with SO_REUSEADDR.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.3)
        return probe.connect_ex(("127.0.0.1", port)) != 0


def _find_free_port(preferred: int = 8000, attempts: int = 10) -> int:
    """Return the preferred port, or the next free port after it."""
    for port in range(preferred, preferred + attempts):
        if _port_is_free(port):
            return port
    return preferred  # let uvicorn surface the bind error as a last resort


def _open_browser(url: str) -> None:
    """Open the browser after a short delay so the server has time to start."""
    import time

    time.sleep(1.5)
    webbrowser.open(url)


def main() -> None:
    """Unified entry point: launch Web GUI or run CLI scanner based on arguments."""
    import argparse
    import sys

    from secret_scanner.core.scanner import main as run_cli

    # Check if any CLI scanning flags or positional targets were passed
    cli_action_flags = {
        "--git", "--ci", "--fail-on-findings", "--rules", "--json",
        "--html", "--markdown", "--sarif", "--install-hook", "--uninstall-hook",
        "--max-commits",
    }
    argv = sys.argv[1:]
    has_cli_action = any(
        arg in cli_action_flags or any(arg.startswith(f"{f}=") for f in cli_action_flags)
        for arg in argv
    )
    has_gui_flag = any(arg in ("--port", "--no-browser") or arg.startswith("--port=") for arg in argv)
    positional_args = [a for a in argv if not a.startswith("-")]

    # If CLI action flag is passed, or if positional target is passed without GUI flags, run CLI
    if has_cli_action or (positional_args and not has_gui_flag and "-h" not in argv and "--help" not in argv):
        run_cli()
        return

    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Privacy-First Credential Leak Detection Platform & CLI Scanner.\n"
                    "Run with no arguments to launch the web dashboard, or pass CLI options to scan directly.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    gui_group = parser.add_argument_group("Web GUI options")
    gui_group.add_argument(
        "--port", type=int, default=None,
        help="Port to serve on (default: 8000, or the next free port if 8000 is busy)",
    )
    gui_group.add_argument(
        "--no-browser", action="store_true",
        help="Do not open the browser automatically",
    )

    cli_group = parser.add_argument_group("CLI Scanner options")
    cli_group.add_argument(
        "target", nargs="?", default=None,
        help="Directory or file path to scan",
    )
    cli_group.add_argument(
        "--git", nargs="?", const=".", metavar="REPO",
        help="Scan Git repository commit history",
    )
    cli_group.add_argument(
        "--max-commits", type=int, default=None, metavar="N",
        help="Maximum historical Git commits to scan",
    )
    cli_group.add_argument(
        "--rules", metavar="FILE",
        help="Path to custom YAML detection rules file",
    )
    cli_group.add_argument(
        "--json", action="store_true",
        help="Output raw scan findings formatted as JSON to stdout",
    )
    cli_group.add_argument(
        "--html", metavar="FILE",
        help="Write an HTML security audit report to target file",
    )
    cli_group.add_argument(
        "--markdown", metavar="FILE",
        help="Write a Markdown security audit report to target file",
    )
    cli_group.add_argument(
        "--sarif", metavar="FILE",
        help="Write an OASIS SARIF v2.1.0 report for CI/CD and GitHub Security",
    )
    cli_group.add_argument(
        "--ci", "--fail-on-findings", dest="ci_mode", action="store_true",
        help="Exit with return code 1 if any secrets are detected (for CI/CD)",
    )
    cli_group.add_argument(
        "--install-hook", action="store_true",
        help="Install Git pre-commit hook into target repository",
    )
    cli_group.add_argument(
        "--uninstall-hook", action="store_true",
        help="Uninstall Git pre-commit hook from target repository",
    )

    args = parser.parse_args()

    # If any CLI options were parsed, forward to CLI runner
    if (
        args.target is not None
        or args.git is not None
        or args.ci_mode
        or args.json
        or args.html
        or args.markdown
        or args.sarif
        or args.rules
        or args.install_hook
        or args.uninstall_hook
    ):
        run_cli()
        return

    # Otherwise launch Web GUI
    if args.port is not None:
        port = args.port
        if not _port_is_free(port):
            print(f"Error: port {port} is already in use by another application.")
            print("Pick a different port, e.g.: python -m secret_scanner --port 8010")
            raise SystemExit(1)
    else:
        port = _find_free_port(8000)

    url = f"http://127.0.0.1:{port}"
    print("=" * 60)
    print("  SecretScanner - Privacy-First Credential Leak Detection")
    print("=" * 60)
    print(f"  Dashboard : {url}")
    print(f"  API Docs  : {url}/docs")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    if args.port is None and port != 8000:
        print(f"  Note: port 8000 was busy (another app is using it), using {port} instead.")
        print(f"  Tip : use --port {port} to always serve on this port.")
    if not args.no_browser:
        threading.Thread(target=_open_browser, args=(url,), daemon=True).start()
    uvicorn.run(
        "secret_scanner.api.app:app",
        host="127.0.0.1",
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    main()

