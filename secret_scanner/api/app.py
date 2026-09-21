"""secret_scanner.api.app
FastAPI application exposing the secret scanning engine via REST API and a
premium, feature-rich Web GUI dashboard.
"""

from __future__ import annotations

import asyncio
import functools
import pathlib
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, field_validator

from secret_scanner.core.engine import DetectionEngine, scan_path
from secret_scanner.core.reporter import (
    generate_html_report,
    generate_markdown_report,
    generate_sarif_report,
    generate_pdf_report,
)
from secret_scanner.core.rules import load_rules
from secret_scanner.git_scanner import scan_repository


# --- WebSocket Progress Manager ----------------------------------------------
class ProgressManager:
    """Manages WebSocket connections for real-time scan progress."""
    
    def __init__(self):
        self.connections: dict[str, WebSocket] = {}
        self.progress_data: dict[str, dict] = {}
    
    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        self.connections[scan_id] = websocket
        self.progress_data[scan_id] = {
            "status": "starting",
            "current_file": "",
            "files_scanned": 0,
            "total_files": 0,
            "findings_count": 0,
            "errors": []
        }
    
    def disconnect(self, scan_id: str):
        self.connections.pop(scan_id, None)
        self.progress_data.pop(scan_id, None)
    
    async def send_progress(self, scan_id: str, data: dict):
        if scan_id in self.connections:
            try:
                await self.connections[scan_id].send_json(data)
            except Exception:
                pass  # Connection closed
    
    async def update_progress(self, scan_id: str, **kwargs):
        if scan_id in self.progress_data:
            self.progress_data[scan_id].update(kwargs)
            await self.send_progress(scan_id, self.progress_data[scan_id])
    
    def get_progress(self, scan_id: str) -> dict:
        return self.progress_data.get(scan_id, {})


progress_manager = ProgressManager()


app = FastAPI(
    title="SecretScanner Platform",
    version="2.2.0",
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
    scan_id: str | None = None


class ScanTextRequest(BaseModel):
    text: str
    filename: str = "<inline>"
    scan_id: str | None = None

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
    scan_id: str | None = None


class ScanUrlRequest(BaseModel):
    url: str
    follow_redirects: bool = True
    max_size_mb: int = 5
    scan_id: str | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class RuleCreateRequest(BaseModel):
    id: str
    name: str
    pattern: str
    severity: str
    description: str = ""


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



@app.post("/rules")
async def create_rule(req: RuleCreateRequest):
    """Add a new detection rule to the rules file."""
    import re
    import yaml
    from pathlib import Path
    
    # Validate regex
    try:
        re.compile(req.pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex: {e}")
    
    # Validate severity
    if req.severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        raise HTTPException(status_code=400, detail="Severity must be CRITICAL, HIGH, MEDIUM, or LOW")
    
    # Validate ID format
    if not re.match(r'^[a-z_][a-z0-9_]*$', req.id):
        raise HTTPException(status_code=400, detail="ID must be lowercase with underscores only")
    
    rules_file = Path(__file__).parent.parent.parent / "rules" / "default_rules.yaml"
    
    # Load existing
    with open(rules_file, 'r') as f:
        data = yaml.safe_load(f) or {"rules": []}
    
    # Check for duplicate ID
    if any(r.get('id') == req.id for r in data.get('rules', [])):
        raise HTTPException(status_code=409, detail=f"Rule with ID '{req.id}' already exists")
    
    # Add new rule
    new_rule = {
        "id": req.id,
        "name": req.name,
        "pattern": req.pattern,
        "severity": req.severity.upper(),
        "description": req.description
    }
    data.setdefault("rules", []).append(new_rule)
    
    # Write back
    with open(rules_file, 'w') as f:
        yaml.dump(data, f, sort_keys=False, allow_unicode=True)
    
    # Clear rules cache so next load picks up new rule
    from secret_scanner.core.rules import load_rules
    load_rules.cache_clear()
    
    return {"success": True, "rule": new_rule}


# ─── WebSocket Endpoint ─────────────────────────────────────────────────────
@app.websocket("/ws/progress/{scan_id}")
async def websocket_progress(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress updates."""
    await progress_manager.connect(scan_id, websocket)
    try:
        # Keep connection alive, send initial progress
        await progress_manager.send_progress(scan_id, progress_manager.get_progress(scan_id))
        while True:
            # Wait for client messages (ping/pong) or close
            await websocket.receive_text()
    except WebSocketDisconnect:
        progress_manager.disconnect(scan_id)
    except Exception:
        progress_manager.disconnect(scan_id)


# ─── Scan Endpoints with Progress ────────────────────────────────────────────
@app.post("/scan", response_model=ScanResponse)
async def scan_directory(req: ScanRequest):
    """Scan a file or directory for secrets."""
    path_str = req.path.strip() if req.path else "."
    if not path_str:
        path_str = "."
    target = pathlib.Path(path_str).resolve()
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Target path does not exist: '{req.path}'")

    scan_id = req.scan_id
    if scan_id:
        await progress_manager.update_progress(scan_id, status="scanning", current_file="Starting scan...")
    
    findings = scan_path(target)
    
    if scan_id:
        await progress_manager.update_progress(scan_id, status="complete", findings_count=len(findings))
    
    return ScanResponse(count=len(findings), findings=findings)


@app.post("/scan/text", response_model=ScanResponse)
async def scan_text(req: ScanTextRequest):
    """Scan raw text or code snippets for secrets."""
    scan_id = req.scan_id
    if scan_id:
        await progress_manager.update_progress(
            scan_id,
            status="scanning",
            current_file=f"Scanning text: {req.filename}",
        )

    engine = DetectionEngine()
    raw = engine.scan(req.text, file_path=req.filename)
    findings = [f.to_dict() for f in raw]

    if scan_id:
        await progress_manager.update_progress(
            scan_id,
            status="complete",
            findings_count=len(findings),
        )

    return ScanResponse(count=len(findings), findings=findings)


@app.post("/scan/git", response_model=ScanResponse)
async def scan_git(req: ScanGitRequest):
    """Scan Git repository commit history for local or remote repositories."""
    repo_input = req.repo_path.strip() if req.repo_path else "."
    if not repo_input:
        repo_input = "."

    scan_id = req.scan_id
    if scan_id:
        await progress_manager.update_progress(
            scan_id,
            status="scanning",
            current_file=f"Scanning Git repository: {repo_input}",
        )

    try:
        findings = scan_repository(repo_input, max_commits=req.max_commits)

        if scan_id:
            await progress_manager.update_progress(
                scan_id,
                status="complete",
                findings_count=len(findings),
            )

        return ScanResponse(count=len(findings), findings=findings)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Failed to scan git repository: {e!s}")


@app.post("/scan/url", response_model=ScanResponse)
async def scan_url(req: ScanUrlRequest):
    """Scan a website URL for secrets by fetching and analyzing its content."""
    import httpx

    scan_id = req.scan_id
    if scan_id:
        await progress_manager.update_progress(
            scan_id,
            status="scanning",
            current_file=f"Fetching URL: {req.url}",
        )

    engine = DetectionEngine()
    all_findings = []
    target = req.url

    try:
        async with httpx.AsyncClient(
            follow_redirects=req.follow_redirects,
            timeout=httpx.Timeout(30.0),
            headers={"User-Agent": "SecretScanner/2.2.0 (+https://github.com/secret-scanner)"},
        ) as client:
            resp = await client.get(target)
            resp.raise_for_status()

            # Check content size
            content = resp.text
            max_bytes = req.max_size_mb * 1024 * 1024
            if len(content.encode("utf-8", errors="ignore")) > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"Response exceeds {req.max_size_mb} MB limit. Use max_size_mb parameter to increase.",
                )

            # Scan the content
            raw = engine.scan(content, file_path=target)
            findings = [f.to_dict() for f in raw]
            all_findings.extend(findings)

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=400, detail=f"HTTP {e.response.status_code}: {e.response.reason_phrase}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Request failed: {e!s}")
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Failed to scan URL: {e!s}")

    if scan_id:
        await progress_manager.update_progress(
            scan_id,
            status="complete",
            findings_count=len(all_findings),
        )

    return ScanResponse(count=len(all_findings), findings=all_findings)


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


@app.post("/report/pdf")
async def export_pdf_report(req: ReportExportRequest):
    """Generate PDF audit report bytes."""
    try:
        pdf_content = generate_pdf_report(req.findings, target_path=req.target_path)
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e!s}")

    filename = f"secret_scanner_report_{req.target_path.replace('/', '_').replace('\\', '_')}.pdf"
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the premium Web GUI dashboard (v2.1)."""
    return HTMLResponse(content=load_dashboard_html())


