"""secret_scanner.core.ignore
Ignore pattern matching for secret scanning (.secretscannerignore).
"""

from __future__ import annotations

import fnmatch
import pathlib
from typing import List


DEFAULT_IGNORE_PATTERNS = [
    "*.venv*",
    "*.git*",
    "*node_modules*",
    "*__pycache__*",
    "*.egg-info*",
    "*.min.js",
    "*.min.css",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.svg",
    "*.woff*",
    "*.zip",
    "*.tar.gz",
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib",
    "*.pyc",
    "*.lock",
]


class IgnoreFilter:
    """Filters out paths based on default and custom ignore patterns."""

    def __init__(self, ignore_file_path: pathlib.Path | None = None):
        self.patterns: List[str] = list(DEFAULT_IGNORE_PATTERNS)
        
        if ignore_file_path and ignore_file_path.exists():
            try:
                for line in ignore_file_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.patterns.append(line)
            except Exception:
                pass

    def is_ignored(self, path: pathlib.Path | str) -> bool:
        """Check if *path* matches any ignore pattern."""
        p_str = str(path).replace("\\", "/")
        name = pathlib.Path(path).name

        for pattern in self.patterns:
            pat_clean = pattern.replace("\\", "/")
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(p_str, f"*{pattern}*"):
                return True
        return False
