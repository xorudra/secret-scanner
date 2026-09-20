"""secret_scanner.core.engine
Core detection engine — integrates YAML rules, Shannon entropy, regex extraction,
false-positive filtering, and privacy-first masking.
"""

from __future__ import annotations

import os
import pathlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Any

from secret_scanner.core.detectors import fingerprint, mask_secret, shannon_entropy
from secret_scanner.core.ignore import IgnoreFilter
from secret_scanner.core.rules import Rule, load_rules

# Character set commonly used in base64/hex tokens for entropy filtering
ENTROPY_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_.~"
ENTROPY_CHAR_SET = frozenset(ENTROPY_CHARS)

# Common programming language type names that trigger false positives in assignments
TYPE_ANNOTATIONS = {
    "str", "int", "float", "bool", "bytes", "dict", "list", "set", "tuple",
    "any", "optional", "union", "callable", "sequence", "mapping", "iterable",
    "string", "boolean", "number", "void", "object", "array", "null", "undefined",
    "none", "true", "false",
}

# Regex IDs that require an entropy check (generic patterns produce many FPs)
_ENTROPY_CHECKED_RULES = frozenset({
    "generic_api_key", "generic_secret", "password_assignment",
})

# Maximum number of worker threads for parallel file scanning
_MAX_WORKERS = min(8, (os.cpu_count() or 1) + 2)

# Pre-compiled regex patterns for false positive detection
_TYPE_ANNOTATION_PATTERN = re.compile(
    r":\s*(?:Optional\[)?(?:str|int|bool|float|bytes|Any|dict|list|string|boolean)\]?",
    re.IGNORECASE
)
_STRING_LITERAL_PATTERN = re.compile(r"=\s*['\"][^'\"]{8,}['\"]")
_ENV_LOOKUP_PATTERN = re.compile(r"os\.(?:environ|getenv)|config\[|settings\[|env\.get", re.IGNORECASE)

# Binary file detection - additional heuristics
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".pyc", ".pyo",
    ".min.js", ".min.css", ".map", ".lock", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".bin", ".dat", ".db", ".sqlite",
})

# ---------------------------------------------------------------------------
# Lazy-loaded module-level REGEX_PATTERNS (backward compat, parsed only once)
# ---------------------------------------------------------------------------
_cached_patterns: dict[str, str] | None = None


def _get_regex_patterns() -> dict[str, str]:
    global _cached_patterns
    if _cached_patterns is None:
        _cached_patterns = {r.rule_id: r.pattern_raw for r in load_rules()}
    return _cached_patterns


# Module-level attribute for backward compat — computed lazily on first access
class _LazyPatterns(dict):
    """A dict subclass that loads rules lazily on first access."""
    _loaded = False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.update(_get_regex_patterns())
            self._loaded = True

    def __getitem__(self, key):
        self._ensure_loaded()
        return super().__getitem__(key)

    def __iter__(self):
        self._ensure_loaded()
        return super().__iter__()

    def __len__(self):
        self._ensure_loaded()
        return super().__len__()

    def items(self):
        self._ensure_loaded()
        return super().items()

    def values(self):
        self._ensure_loaded()
        return super().values()

    def keys(self):
        self._ensure_loaded()
        return super().keys()


REGEX_PATTERNS: dict[str, str] = _LazyPatterns()


class SecretFinding:
    """Represents an individual detected secret finding."""

    def __init__(
        self,
        secret_type: str,
        value: str,
        file_path: str,
        line: int,
        col: int,
        score: float,
        rule_name: str = "",
        severity: str = "MEDIUM",
        context: str = "",
        commit_info: dict[str, Any] | None = None,
    ):
        self.secret_type = secret_type
        self.value = value
        self.file_path = file_path
        self.line = line
        self.col = col
        self.score = score
        self.rule_name = rule_name or secret_type
        self.severity = severity.upper()
        self.fingerprint = fingerprint(value)
        self.masked_value = mask_secret(value)
        self.context = context or self.masked_value
        self.commit_info = commit_info or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to a dictionary without exposing raw secrets."""
        data: dict[str, Any] = {
            "type": self.secret_type,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line,
            "col": self.col,
            "score": round(self.score, 3),
            "fingerprint": self.fingerprint,
            "masked_value": self.masked_value,
            "context": self.context,
        }
        if self.commit_info:
            data.update(self.commit_info)
        return data


@lru_cache(maxsize=1024)
def _cached_shannon_entropy(value: str) -> float:
    """Cached Shannon entropy calculation."""
    filtered_chars = "".join(c for c in value if c in ENTROPY_CHAR_SET)
    return shannon_entropy(filtered_chars) if filtered_chars else 0.0


class DetectionEngine:
    """Engine that scans text using compiled rules, entropy calculation, and heuristics."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        entropy_threshold: float = 3.2,
        custom_rules_path: pathlib.Path | str | None = None,
    ):
        self.entropy_threshold = entropy_threshold
        self.rules: list[Rule] = rules if rules is not None else load_rules(custom_rules_path)
        # Expose REGEX_PATTERNS dictionary for backward compatibility
        self.patterns: dict[str, re.Pattern] = {r.rule_id: r.pattern for r in self.rules}

    @property
    def patterns_dict(self) -> dict[str, str]:
        return {r.rule_id: r.pattern_raw for r in self.rules}

    def _is_false_positive_annotation(self, line: str, matched_text: str, secret_value: str) -> bool:
        """Filter out common false positives like python/typescript type signatures:

        e.g. `def test(secret: str) -> None:`, `password: Optional[str] = None`
        Also catches env-var lookups like `token: str = os.environ[...]`
        """
        val_clean = secret_value.strip().strip("'\"").lower()
        if val_clean in TYPE_ANNOTATIONS:
            return True

        # If the match looks like a type declaration: `foo: str` or `foo: Optional[str]`
        if _TYPE_ANNOTATION_PATTERN.search(matched_text) and not _STRING_LITERAL_PATTERN.search(matched_text):
            return True

        # Catch os.environ / os.getenv / config lookups — not hardcoded secrets
        return bool(_ENV_LOOKUP_PATTERN.search(line) and not _STRING_LITERAL_PATTERN.search(matched_text))

    def _score(self, value: str, severity: str) -> float:
        """Compute risk score combining rule severity with normalized Shannon entropy."""
        entropy = _cached_shannon_entropy(value)
        normalized_entropy = min(entropy / 8.0, 1.0)

        base_weights = {
            "CRITICAL": 0.85,
            "HIGH": 0.70,
            "MEDIUM": 0.50,
            "LOW": 0.35,
        }
        base = base_weights.get(severity.upper(), 0.50)
        return min(1.0, base + (1.0 - base) * 0.6 * normalized_entropy)

    def _mask_context(self, line: str, raw_match: str, secret_value: str) -> str:
        """Mask the secret value within the original line context snippet."""
        clean_line = line.strip()
        if len(clean_line) > 160:
            clean_line = clean_line[:160] + "..."
        masked = mask_secret(secret_value)
        # Use regex-safe replacement to correctly handle special chars in secret
        try:
            clean_line = re.sub(re.escape(secret_value), masked, clean_line, count=1)
        except re.error:
            # Fallback: plain string replace if re.escape has edge-case issues
            clean_line = clean_line.replace(secret_value, masked, 1)
        return clean_line

    def scan(
        self,
        text: str,
        file_path: str = "<unknown>",
        commit_info: dict[str, Any] | None = None,
    ) -> list[SecretFinding]:
        """Scan *text* and return detected :class:`SecretFinding` objects."""
        findings: list[SecretFinding] = []
        seen_fingerprints: set[str] = set()

        for line_num, line in enumerate(text.splitlines(), start=1):
            # Skip comment-only or extremely long single-line generated assets (e.g. bundle maps)
            if len(line) > 2000:
                continue

            for rule in self.rules:
                for match in rule.pattern.finditer(line):
                    secret_val = rule.extract_secret(match)
                    if not secret_val or len(secret_val) < 6:
                        continue

                    # Filter out type annotation false positives
                    if self._is_false_positive_annotation(line, match.group(0), secret_val):
                        continue

                    # Entropy check for generic keys and passwords
                    if rule.rule_id in _ENTROPY_CHECKED_RULES:
                        entropy = _cached_shannon_entropy(secret_val)
                        if entropy < self.entropy_threshold:
                            continue

                    fp = fingerprint(secret_val)
                    # Deduplicate multiple hits of the same secret on the same file/line
                    dedup_key = f"{file_path}:{line_num}:{fp}"
                    if dedup_key in seen_fingerprints:
                        continue
                    seen_fingerprints.add(dedup_key)

                    score = self._score(secret_val, rule.severity)
                    col = match.start() + 1
                    context = self._mask_context(line, match.group(0), secret_val)

                    findings.append(
                        SecretFinding(
                            secret_type=rule.rule_id,
                            value=secret_val,
                            file_path=file_path,
                            line=line_num,
                            col=col,
                            score=score,
                            rule_name=rule.name,
                            severity=rule.severity,
                            context=context,
                            commit_info=commit_info,
                        )
                    )
        return findings


def is_binary_content(raw_bytes: bytes) -> bool:
    """Detect binary files by checking for null bytes in initial chunk."""
    return b"\x00" in raw_bytes[:8192]


def is_likely_binary(path: Path) -> bool:
    """Quick check if file is likely binary based on extension."""
    return path.suffix.lower() in _BINARY_EXTENSIONS


def scan_file(path: str, engine: DetectionEngine | None = None) -> list[dict[str, Any]]:
    """Read a single file, skip binaries, and return finding dictionaries."""
    try:
        p = Path(path)
        if not p.is_file():
            return []

        # Quick extension-based binary check before reading
        if is_likely_binary(p):
            return []

        # Read raw bytes to check for binary data
        with open(p, "rb") as fh:
            chunk = fh.read(8192)
            if is_binary_content(chunk):
                return []
            rest = fh.read()
            raw_bytes = chunk + rest
            content = raw_bytes.decode("utf-8", errors="ignore")
    except (OSError, MemoryError):
        return []

    active_engine = engine or DetectionEngine()
    return [f.to_dict() for f in active_engine.scan(content, file_path=str(p))]


def scan_path(
    target: os.PathLike | str,
    engine: DetectionEngine | None = None,
    custom_rules_path: pathlib.Path | str | None = None,
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """Recursively scan a file or directory for secrets, honoring .secretscannerignore.

    Uses a thread-pool for parallel file I/O to speed up large directory scans.
    """
    p = Path(target).resolve()
    if not p.exists():
        return []

    # Create engine once — shared across all threads (DetectionEngine is read-only after init)
    active_engine = engine or DetectionEngine(custom_rules_path=custom_rules_path)

    # Locate ignore file relative to the scan root
    ignore_root = p if p.is_dir() else p.parent
    ignore_filter = IgnoreFilter(ignore_root / ".secretscannerignore")

    if p.is_file():
        if not ignore_filter.is_ignored(p):
            return scan_file(str(p), engine=active_engine)
        return []

    # Collect all eligible file paths first (fast walk), then scan in parallel
    file_paths: list[str] = []
    for root, dirs, files in os.walk(p):
        # Prune ignored subdirectories in-place to skip entire subtrees
        dirs[:] = [
            d for d in dirs
            if not ignore_filter.is_ignored(Path(root) / d)
        ]
        for fname in files:
            file_path = Path(root) / fname
            if not ignore_filter.is_ignored(file_path):
                file_paths.append(str(file_path))

    if not file_paths:
        return []

    # Parallel scan using ThreadPoolExecutor
    workers = max_workers if (max_workers is not None and max_workers > 0) else _MAX_WORKERS
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_path = {
            executor.submit(scan_file, fp, active_engine): fp
            for fp in file_paths
        }
        for future in as_completed(future_to_path):
            try:
                results.extend(future.result())
            except (OSError, MemoryError, UnicodeDecodeError):
                # Silently skip files that error during scanning
                pass

    return results
