"""secret_scanner.core.detectors
Low‑level detection utilities.
Provides:
- shannon_entropy(text) → float (0.0 to 8.0)
- fingerprint(secret)   → str   (SHA‑256 hex)
- mask_secret(secret)   → str   (redacted preview)
"""

from __future__ import annotations

import hashlib
import math


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for *data*.
    Returns a float between 0.0 and ~8.0.
    """
    if not data:
        return 0.0
    length = len(data)
    prob: dict[str, int] = {}
    for c in data:
        prob[c] = prob.get(c, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in prob.values())


def fingerprint(secret: str) -> str:
    """Return a SHA‑256 hex digest of *secret* (used for deduplication)."""
    return hashlib.sha256(secret.encode("utf-8", errors="ignore")).hexdigest()


def mask_secret(secret: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Produce a privacy-safe redacted representation of a secret string.

    Never exposes full credentials in logs, CLI, reports, or APIs.
    Rules:
    - <= 6 chars: fully masked
    - 7–9 chars: show first 2 + *** + last 2
    - >= 10 chars: show first 4 + ******** + last 4 (bounded by length)
    """
    if not secret:
        return ""
    length = len(secret)
    if length <= 6:
        return "*" * length
    if length <= 9:
        return secret[:2] + "***" + secret[-2:]
    prefix_len = min(keep_start, max(1, length // 5))
    suffix_len = min(keep_end, max(1, length // 5))
    return secret[:prefix_len] + ("*" * 8) + secret[-suffix_len:]
