"""Launch the SecretScanner web GUI.

Usage:
    python -m secret_scanner

Opens the dashboard at http://127.0.0.1:8000
"""
import threading
import webbrowser

import uvicorn


def _open_browser() -> None:
    """Open the browser after a short delay so the server has time to start."""
    import time

    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000")


def main() -> None:
    """Launch the web GUI (used as the script entry point and __main__)."""
    print("=" * 60)
    print("  SecretScanner - Privacy-First Credential Leak Detection")
    print("=" * 60)
    print("  Dashboard : http://127.0.0.1:8000")
    print("  API Docs  : http://127.0.0.1:8000/docs")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(
        "secret_scanner.api.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    main()
