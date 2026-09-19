"""secret_scanner.core.ignore
Ignore pattern matching for secret scanning (.secretscannerignore).
"""

from __future__ import annotations

import fnmatch
import pathlib
from typing import List


# Default patterns applied regardless of .secretscannerignore file.
# These use fnmatch glob syntax and are matched against:
#  - the file/dir basename (e.g. "node_modules")
#  - the full normalised path string (e.g. "project/node_modules/lodash/index.js")
DEFAULT_IGNORE_PATTERNS: List[str] = [
    # Version control
    ".git",
    # Dependency directories
    "node_modules",
    "vendor",
    # Python
    ".venv",
    "venv",
    "__pycache__",
    "*.egg-info",
    "*.pyc",
    "*.pyo",
    # Build outputs
    "dist",
    "build",
    "out",
    "target",
    ".next",
    ".nuxt",
    ".output",
    # Lock files (dependency manifests, not secrets)
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    # Minified assets
    "*.min.js",
    "*.min.css",
    # Binary / media files
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.svg",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.tar.bz2",
    "*.tar.xz",
    "*.rar",
    "*.7z",
    "*.gz",
    # Executables / libraries
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib",
    "*.class",
    "*.jar",
    # Map / source-map files (often very long, no secrets)
    "*.map",
    "*.js.map",
    "*.css.map",
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
        """Check if *path* matches any ignore pattern.

        Matching strategy:
        1. Match the bare file/directory name against the pattern
           (handles patterns like ``node_modules``, ``*.pyc``).
        2. Match the full path normalised to forward-slashes against the pattern
           with ``*`` wildcards on both sides — handles sub-directory patterns.
        """
        p = pathlib.Path(path)
        name = p.name
        # Normalise to forward-slash path for consistent cross-platform matching
        p_str = str(p).replace("\\", "/")

        for pattern in self.patterns:
            pat = pattern.replace("\\", "/")
            # 1. Match the basename directly (e.g. pattern "node_modules" or "*.pyc")
            if fnmatch.fnmatch(name, pat):
                return True
            # 2. Match any path segment (e.g. pattern ".git" inside a sub-path)
            #    We split on "/" and test each component to avoid the double-glob bug.
            if "/" not in pat:
                # Segment match: test each directory component in the path
                for part in p.parts:
                    if fnmatch.fnmatch(part, pat):
                        return True
            else:
                # Pattern contains a path separator — match against full normalised path
                if fnmatch.fnmatch(p_str, pat) or fnmatch.fnmatch(p_str, f"*/{pat}"):
                    return True

        return False
