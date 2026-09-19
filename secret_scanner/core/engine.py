"""secret_scanner.core.engine
Core detection engine — integrates YAML rules, Shannon entropy, regex extraction,
false-positive filtering, and privacy-first masking.
"""

from __future__ import annotations

import os
import pathlib
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

from secret_scanner.core.detectors import shannon_entropy, fingerprint, mask_secret
from secret_scanner.core.ignore import IgnoreFilter
from secret_scanner.core.rules import Rule, load_rules

# Character set commonly used in base64/hex tokens for entropy filtering
ENTROPY_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_.~"

# Common programming language type names that trigger false positives in assignments
TYPE_ANNOTATIONS = {
    "str", "int", "float", "bool", "bytes", "dict", "list", "set", "tuple",
    "any", "optional", "union", "callable", "sequence", "mapping", "iterable",
    "string", "boolean", "number", "void", "object", "array", "null", "undefined",
}


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
        commit_info: Optional[Dict[str, Any]] = None,
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

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding to a dictionary without exposing raw secrets."""
        data: Dict[str, Any] = {
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


class DetectionEngine:
    """Engine that scans text using compiled rules, entropy calculation, and heuristics."""

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        entropy_threshold: float = 3.2,
        custom_rules_path: Optional[pathlib.Path | str] = None,
    ):
        self.entropy_threshold = entropy_threshold
        self.rules: List[Rule] = rules if rules is not None else load_rules(custom_rules_path)
        # Expose REGEX_PATTERNS dictionary for backward compatibility
        self.patterns: Dict[str, re.Pattern] = {r.rule_id: r.pattern for r in self.rules}

    @property
    def patterns_dict(self) -> Dict[str, str]:
        return {r.rule_id: r.pattern_raw for r in self.rules}

    def _is_false_positive_annotation(self, line: str, matched_text: str, secret_value: str) -> bool:
        """Filter out common false positives like python/typescript type signatures:

        e.g. `def test(secret: str) -> None:`, `password: Optional[str] = None`
        """
        val_clean = secret_value.strip().strip("'\"").lower()
        if val_clean in TYPE_ANNOTATIONS:
            return True

        # If the match looks like a type declaration: `foo: str` or `foo: Optional[str]`
        if re.search(r":\s*(?:Optional\[)?(?:str|int|bool|float|bytes|Any|dict|list|string|boolean)\]?", matched_text, re.IGNORECASE):
            # Check if there's no actual string literal assignment
            if not re.search(r"=\s*['\"][^'\"]{8,}['\"]", matched_text):
                return True

        return False

    def _score(self, value: str, severity: str) -> float:
        """Compute risk score combining rule severity with normalized Shannon entropy."""
        filtered_chars = "".join(c for c in value if c in ENTROPY_CHARS)
        entropy = shannon_entropy(filtered_chars) if filtered_chars else 0.0
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
        return clean_line.replace(secret_value, masked)

    def scan(
        self,
        text: str,
        file_path: str = "<unknown>",
        commit_info: Optional[Dict[str, Any]] = None,
    ) -> List[SecretFinding]:
        """Scan *text* and return detected :class:`SecretFinding` objects."""
        findings: List[SecretFinding] = []
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
                    if rule.rule_id in ("generic_api_key", "generic_secret", "password_assignment"):
                        entropy = shannon_entropy(secret_val)
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


# Provide module-level REGEX_PATTERNS dictionary for backward compatibility with imports
REGEX_PATTERNS: Dict[str, str] = {r.rule_id: r.pattern_raw for r in load_rules()}


def is_binary_content(raw_bytes: bytes) -> bool:
    """Detect binary files by checking for null bytes in initial chunk."""
    return b"\x00" in raw_bytes[:8192]


def scan_file(path: str, engine: Optional[DetectionEngine] = None) -> List[Dict[str, Any]]:
    """Read a single file, skip binaries, and return finding dictionaries."""
    try:
        p = Path(path)
        if not p.is_file():
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
    engine: Optional[DetectionEngine] = None,
    custom_rules_path: Optional[pathlib.Path | str] = None,
) -> List[Dict[str, Any]]:
    """Recursively scan a file or directory for secrets, honoring .secretscannerignore."""
    results: List[Dict[str, Any]] = []
    p = Path(target).resolve()
    if not p.exists():
        return []

    active_engine = engine or DetectionEngine(custom_rules_path=custom_rules_path)
    ignore_filter = IgnoreFilter(p / ".secretscannerignore" if p.is_dir() else None)

    if p.is_file():
        if not ignore_filter.is_ignored(p):
            results.extend(scan_file(str(p), engine=active_engine))
    elif p.is_dir():
        for root, _dirs, files in os.walk(p):
            # Prune ignored subdirectories in-place
            _dirs[:] = [d for d in _dirs if not ignore_filter.is_ignored(Path(root) / d)]
            for fname in files:
                file_path = Path(root) / fname
                if not ignore_filter.is_ignored(file_path):
                    results.extend(scan_file(str(file_path), engine=active_engine))
    return results
