"""secret_scanner.api.app
FastAPI application exposing the secret scanning engine via REST API and a
premium, feature-rich Web GUI dashboard.
"""

from __future__ import annotations

import functools
import pathlib
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, field_validator

from secret_scanner.core.engine import DetectionEngine, scan_path
from secret_scanner.core.reporter import (
    generate_html_report,
    generate_markdown_report,
    generate_sarif_report,
)
from secret_scanner.core.rules import load_rules
from secret_scanner.git_scanner import scan_repository

app = FastAPI(
    title="SecretScanner Platform",
    version="2.1.0",
    description="Privacy-first secret & credential leak detection platform",
)

TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
DASHBOARD_FILE = TEMPLATE_DIR / "index.html"


@functools.lru_cache(maxsize=1)
def load_dashboard_html() -> str:
    """Load the Web GUI dashboard HTML template."""
    if DASHBOARD_FILE.is_file():
        return DASHBOARD_FILE.read_text(encoding="utf-8")
    # Fallback minimal message if template file was deleted or moved
    return "<html><body><h2>SecretScanner: dashboard template not found.</h2></body></html>"


# Module-level variable for backward compatibility with existing imports/tests
HTML_DASHBOARD = load_dashboard_html()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    path: str = "."


class ScanTextRequest(BaseModel):
    text: str
    filename: str = "<inline>"

    @field_validator("text")
    @classmethod
    def check_text_size(cls, v: str) -> str:
        # Limit to 2 MB to protect the async event loop from huge pastes
        max_bytes = 2 * 1024 * 1024
        if len(v.encode("utf-8", errors="ignore")) > max_bytes:
            raise ValueError(
                "Text payload exceeds the 2 MB limit. Please use the directory scan for large files."
            )
        return v


class ScanGitRequest(BaseModel):
    repo_path: str
    max_commits: int | None = None


class ScanResponse(BaseModel):
    count: int
    findings: list[dict[str, Any]]


class ReportExportRequest(BaseModel):
    findings: list[dict[str, Any]]
    target_path: str = "SecretScanner Web"


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Health-check endpoint."""
    return {"status": "ok", "service": "secret-scanner", "version": "2.1.0"}


@app.get("/rules")
async def get_rules():
    """Get active detection patterns, metadata, and severity definitions."""
    rules = load_rules()
    return {
        "count": len(rules),
        "rules": [r.to_dict() for r in rules],
        "patterns": {r.rule_id: r.pattern_raw for r in rules},
        "default_entropy_threshold": 3.2,
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_directory(req: ScanRequest):
    """Scan a file or directory for secrets."""
    path_str = req.path.strip() if req.path else "."
    if not path_str:
        path_str = "."
    target = pathlib.Path(path_str).resolve()
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Target path does not exist: '{req.path}'")

    findings = scan_path(target)
    return ScanResponse(count=len(findings), findings=findings)


@app.post("/scan/text", response_model=ScanResponse)
async def scan_text(req: ScanTextRequest):
    """Scan raw text or code snippets for secrets."""
    engine = DetectionEngine()
    raw = engine.scan(req.text, file_path=req.filename)
    findings = [f.to_dict() for f in raw]
    return ScanResponse(count=len(findings), findings=findings)


@app.post("/scan/git", response_model=ScanResponse)
async def scan_git(req: ScanGitRequest):
    """Scan Git repository commit history for local or remote repositories."""
    repo_input = req.repo_path.strip() if req.repo_path else "."
    if not repo_input:
        repo_input = "."
    try:
        findings = scan_repository(repo_input, max_commits=req.max_commits)
        return ScanResponse(count=len(findings), findings=findings)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Failed to scan git repository: {e!s}")


@app.post("/report/html")
async def export_html_report(req: ReportExportRequest):
    """Generate HTML audit report string."""
    html_content = generate_html_report(req.findings, target_path=req.target_path)
    return Response(content=html_content, media_type="text/html")


@app.post("/report/markdown")
async def export_markdown_report(req: ReportExportRequest):
    """Generate Markdown audit report string."""
    md_content = generate_markdown_report(req.findings, target_path=req.target_path)
    return Response(content=md_content, media_type="text/markdown")


@app.post("/report/sarif")
async def export_sarif_report(req: ReportExportRequest):
    """Generate OASIS SARIF v2.1.0 audit report JSON string."""
    sarif_content = generate_sarif_report(req.findings, target_path=req.target_path)
    return Response(content=sarif_content, media_type="application/json")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the premium Web GUI dashboard (v2.1)."""
    return HTMLResponse(content=load_dashboard_html())
