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
    """Launch the web GUI (used as the script entry point and __main__)."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="secret_scanner",
        description="Launch the SecretScanner web dashboard.",
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Port to serve on (default: 8000, or the next free port if 8000 is busy)",
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="Do not open the browser automatically",
    )
    args = parser.parse_args()

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

