"""secret_scanner.core.rules
Rule loader supporting custom YAML configuration files and compiled regex patterns.
"""

from __future__ import annotations

import pathlib
import re
from typing import Dict, List, Any, Optional

DEFAULT_RULES_PATH = pathlib.Path(__file__).parent.parent.parent / "rules" / "default_rules.yaml"


class Rule:
    """Represents an individual detection rule with pattern matching and metadata."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        severity: str = "MEDIUM",
        description: str = "",
    ):
        self.rule_id = rule_id
        self.name = name
        self.pattern_raw = pattern
        self.pattern = re.compile(pattern)
        self.severity = severity.upper()
        self.description = description

    def extract_secret(self, match: re.Match) -> str:
        """Extract the secret substring from a regex match.

        If the rule specifies capture groups, group 1 is returned as the secret value.
        Otherwise, group 0 (the entire match) is returned.
        """
        if match.groups():
            for g in match.groups():
                if g:
                    return g
        return match.group(0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule metadata to dictionary representation."""
        return {
            "id": self.rule_id,
            "name": self.name,
            "pattern": self.pattern_raw,
            "severity": self.severity,
            "description": self.description,
        }


# Fallback hardcoded definitions in case YAML file cannot be located
FALLBACK_RULE_DEFS = [
    ("aws_access_key", "AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "HIGH", "Identifies AWS IAM access key IDs."),
    ("aws_secret_key", "AWS Secret Access Key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "HIGH", "Identifies AWS secret access key assignments."),
    ("github_token", "GitHub Personal Access Token", r"gh[pousr]_[A-Za-z0-9_]{36,}", "HIGH", "Matches GitHub classic tokens."),
    ("github_fine_grained", "GitHub Fine-Grained Token", r"github_pat_[0-9a-zA-Z_]{82}", "HIGH", "Matches GitHub fine-grained PATs."),
    ("gitlab_token", "GitLab Personal Access Token", r"glpat-[0-9a-zA-Z_\-]{20,}", "HIGH", "Matches GitLab PATs."),
    ("slack_token", "Slack API Token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", "HIGH", "Matches Slack API tokens."),
    ("stripe_key", "Stripe API Key", r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}", "HIGH", "Matches Stripe API keys."),
    ("private_key", "RSA/OPENSSH/EC Private Key", r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL", "Matches private cryptographic keys."),
    ("generic_api_key", "Generic API Key", r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.~]{16,})['\"]?", "MEDIUM", "Matches generic API key variable assignments."),
    ("generic_secret", "Generic Secret Key", r"(?i)(?:secret[_-]?key|client[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.~]{16,})['\"]?", "MEDIUM", "Matches secret key or client secret variable assignments."),
    ("password_assignment", "Hardcoded Password", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]", "MEDIUM", "Matches hardcoded password assignments."),
    ("database_url", "Database Connection String", r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/\S+:\S+@\S+", "HIGH", "Matches database connection URIs."),
    ("jwt_token", "JSON Web Token (JWT)", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "MEDIUM", "Matches JSON Web Tokens."),
]


def load_rules(custom_rules_path: pathlib.Path | str | None = None) -> List[Rule]:
    """Load detection rules from a YAML file or use the embedded fallback definitions."""
    target_path = pathlib.Path(custom_rules_path) if custom_rules_path else DEFAULT_RULES_PATH
    rules: List[Rule] = []

    if target_path.exists() and target_path.is_file():
        try:
            import yaml
            data = yaml.safe_load(target_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], list):
                for item in data["rules"]:
                    if not isinstance(item, dict) or "pattern" not in item:
                        continue
                    rules.append(Rule(
                        rule_id=str(item.get("id", "custom")),
                        name=str(item.get("name", "Custom Rule")),
                        pattern=item["pattern"],
                        severity=str(item.get("severity", "MEDIUM")),
                        description=str(item.get("description", "")),
                    ))
                if rules:
                    return rules
        except Exception:
            pass

    # Fallback to defaults
    for r_id, name, pat, sev, desc in FALLBACK_RULE_DEFS:
        rules.append(Rule(rule_id=r_id, name=name, pattern=pat, severity=sev, description=desc))

    return rules
