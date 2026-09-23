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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) != 0


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
    port = _find_free_port(8000)
    url = f"http://127.0.0.1:{port}"
    print("=" * 60)
    print("  SecretScanner - Privacy-First Credential Leak Detection")
    print("=" * 60)
    print(f"  Dashboard : {url}")
    print(f"  API Docs  : {url}/docs")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    if port != 8000:
        print(f"  Note: port 8000 was busy (another app is using it), using {port} instead.")
    threading.Thread(target=_open_browser, args=(url,), daemon=True).start()
    uvicorn.run(
        "secret_scanner.api.app:app",
        host="127.0.0.1",
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    main()

