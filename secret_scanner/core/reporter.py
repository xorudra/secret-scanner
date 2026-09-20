"""secret_scanner.core.reporter
Generates HTML, Markdown, and SARIF v2.1.0 security audit reports from scan findings.
"""

from __future__ import annotations

import datetime
import html
import json
from typing import Any

NOW = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecretScanner Audit Report</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #121a2b;
      --card-border: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #6366f1;
      --danger: #ef4444;
      --warning: #f59e0b;
      --info: #3b82f6;
      --critical: #dc2626;
      --success: #10b981;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 2rem;
    }
    .container { max-width: 1300px; margin: 0 auto; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.75rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    h1 { margin: 0 0 0.5rem 0; color: var(--primary); display: flex; align-items: center; gap: 0.5rem; }
    h2 { margin-top: 0; }
    .meta-bar { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 1rem; }
    .stats-row { display: flex; gap: 1.5rem; margin-top: 1rem; flex-wrap: wrap; }
    .stat-pill {
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--card-border);
      padding: 0.5rem 1rem;
      border-radius: 8px;
      font-size: 0.9rem;
    }
    .stat-pill strong { font-size: 1.1rem; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.88rem; }
    th, td { text-align: left; padding: 0.85rem; border-bottom: 1px solid var(--card-border); }
    th { background: #0b111d; color: var(--text-muted); font-weight: 600; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(220, 38, 38, 0.25); color: #f87171; border: 1px solid #dc2626; }
    .badge-high { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
    code { font-family: 'Fira Code', Consolas, Monaco, monospace; background: #080c14; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8; }
    .context-box { font-family: 'Fira Code', Consolas, Monaco, monospace; font-size: 0.8rem; color: #cbd5e1; background: #080c14; padding: 0.4rem 0.6rem; border-radius: 4px; max-width: 400px; word-break: break-all; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>🛡️ SecretScanner Security Audit Report</h1>
      <div class="meta-bar">
        Generated on <strong>__DATE__</strong> | Target: <code>__TARGET__</code>
      </div>
      <div class="stats-row">
        <div class="stat-pill">Total Findings: <strong style="color: __STAT_COLOR__;">__COUNT__</strong></div>
        <div class="stat-pill">Critical: <strong style="color: #f87171;">__CRITICAL_COUNT__</strong></div>
        <div class="stat-pill">High: <strong style="color: #ef4444;">__HIGH_COUNT__</strong></div>
        <div class="stat-pill">Medium: <strong style="color: #f59e0b;">__MED_COUNT__</strong></div>
      </div>
    </div>

    <div class="card">
      <h2>Detected Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type / Rule</th>
            <th>File Location</th>
            <th>Line : Col</th>
            <th>Masked Secret</th>
            <th>Code Context / Commit</th>
          </tr>
        </thead>
        <tbody>
          __ROWS__
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""


def _get_severity_badge(severity: str) -> str:
    s = (severity or "MEDIUM").upper()
    cls_map = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
    }
    badge_cls = cls_map.get(s, "badge-medium")
    return f'<span class="badge {badge_cls}">{html.escape(s)}</span>'


def generate_html_report(findings: list[dict[str, Any]], target_path: str = ".") -> str:
    """Generate a responsive HTML security audit report string."""
    now_str = NOW.strftime("%Y-%m-%d %H:%M:%S")

    critical_count = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity", "").upper() in ("MEDIUM", "LOW"))
    stat_color = "#10b981" if not findings else ("#ef4444" if (critical_count + high_count) > 0 else "#f59e0b")

    rows = []
    if not findings:
        rows.append('<tr><td colspan="6" style="text-align: center; color: #10b981; padding: 2rem;">✅ Clean scan! No leaked credentials detected.</td></tr>')
    else:
        for f in findings:
            badge = _get_severity_badge(f.get("severity", "MEDIUM"))
            rule_name = html.escape(str(f.get("rule_name") or f.get("type", "Unknown")))
            file_loc = html.escape(str(f.get("file", "<unknown>")))
            line_col = f"L{f.get('line', 1)} : C{f.get('col', 1)}"
            masked = html.escape(str(f.get("masked_value") or ""))
            context = html.escape(str(f.get("context") or ""))
            
            commit_meta = ""
            if "commit_hash" in f:
                commit_meta = f'<br><span style="color: #64748b; font-size: 0.75rem;">Commit: <code>{f["commit_hash"]}</code> by {html.escape(str(f.get("commit_author", "")))}</span>'

            rows.append(f"""
              <tr>
                <td>{badge}</td>
                <td><strong>{rule_name}</strong><br><span style="color: #64748b; font-size: 0.75rem;"><code>{html.escape(str(f.get("type", "")))}</code></span></td>
                <td><code>{file_loc}</code></td>
                <td>{line_col}</td>
                <td><code>{masked}</code></td>
                <td><div class="context-box">{context}</div>{commit_meta}</td>
              </tr>
            """)

    report = HTML_REPORT_TEMPLATE.replace("__DATE__", now_str)
    report = report.replace("__TARGET__", html.escape(target_path))
    report = report.replace("__COUNT__", str(len(findings)))
    report = report.replace("__CRITICAL_COUNT__", str(critical_count))
    report = report.replace("__HIGH_COUNT__", str(high_count))
    report = report.replace("__MED_COUNT__", str(med_count))
    report = report.replace("__STAT_COLOR__", stat_color)
    report = report.replace("__ROWS__", "\n".join(rows))
    return report


def generate_markdown_report(findings: list[dict[str, Any]], target_path: str = ".") -> str:
    """Generate Markdown format security audit report string."""
    now_str = NOW.strftime("%Y-%m-%d %H:%M:%S")

    critical_count = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")

    md = [
        "# 🛡️ SecretScanner Security Audit Report",
        f"- **Generated:** `{now_str}`",
        f"- **Target Path:** `{target_path}`",
        f"- **Total Secrets Detected:** `{len(findings)}` (Critical: `{critical_count}`, High: `{high_count}`)",
        "",
        "## Findings Summary",
        "",
        "| Severity | Rule / Type | File Location | Line:Col | Masked Secret | Context / Commit |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    if not findings:
        md.append("| ✅ **CLEAN** | N/A | No secrets detected | N/A | N/A | Clean scan |")
    else:
        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            sev_icon = (
                "🟣 **CRITICAL**" if sev == "CRITICAL"
                else "🔴 **HIGH**" if sev == "HIGH"
                else "🟡 **MEDIUM**" if sev == "MEDIUM"
                else "🔵 **LOW**"
            )
            rule_name = f.get("rule_name") or f.get("type")
            file_loc = f.get("file", "")
            loc = f"L{f.get('line', 1)}:C{f.get('col', 1)}"
            masked = f"`{f.get('masked_value', '')}`"
            context = f.get("context", "").replace("|", "\\|")
            if "commit_hash" in f:
                context += f" (Commit: `{f['commit_hash']}`)"
            md.append(f"| {sev_icon} | `{rule_name}` | `{file_loc}` | {loc} | {masked} | `{context}` |")

    return "\n".join(md)


def generate_sarif_report(findings: list[dict[str, Any]], target_path: str = ".") -> str:
    """Generate OASIS SARIF v2.1.0 standard report for CI/CD and GitHub Security tab."""
    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results = []

    for f in findings:
        rule_id = f.get("type", "generic_secret")
        rule_name = f.get("rule_name", rule_id)
        severity = f.get("severity", "MEDIUM").upper()

        if rule_id not in rules_dict:
            level = "error" if severity in ("CRITICAL", "HIGH") else "warning"
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": f"Potential {rule_name} credential leak"},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "precision": "high",
                    "security-severity": "8.0" if severity == "CRITICAL" else ("7.0" if severity == "HIGH" else "5.0"),
                },
            }

        level = "error" if severity in ("CRITICAL", "HIGH") else "warning"
        file_uri = str(f.get("file", "unknown")).replace("\\", "/")
        line = int(f.get("line", 1))
        col = int(f.get("col", 1))

        result_item: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"Detected potential {rule_name}: {f.get('masked_value', '')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_uri,
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": col,
                            "snippet": {
                                "text": f.get("context", "")
                            }
                        }
                    }
                }
            ],
            "properties": {
                "fingerprint": f.get("fingerprint", ""),
                "score": f.get("score", 0.0),
                "severity": severity,
            }
        }
        if "commit_hash" in f:
            result_item["properties"]["commitHash"] = f["commit_hash"]
        sarif_results.append(result_item)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecretScanner",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/secret-scanner/secret-scanner",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
