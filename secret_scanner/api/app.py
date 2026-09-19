"""secret_scanner.api.app
FastAPI application exposing the secret scanning engine via REST API and Web GUI.
"""

from __future__ import annotations

import pathlib
from typing import Any, List, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from secret_scanner.core.engine import scan_path, DetectionEngine, REGEX_PATTERNS
from secret_scanner.core.rules import load_rules
from secret_scanner.core.reporter import (
    generate_html_report,
    generate_markdown_report,
    generate_sarif_report,
)
from secret_scanner.git_scanner import scan_repository

app = FastAPI(
    title="SecretScanner Platform",
    version="0.1.0",
    description="Privacy-first secret & credential leak detection platform",
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    path: str = "."


class ScanTextRequest(BaseModel):
    text: str
    filename: str = "<inline>"


class ScanGitRequest(BaseModel):
    repo_path: str
    max_commits: Optional[int] = None


class ScanResponse(BaseModel):
    count: int
    findings: List[Dict[str, Any]]


class ReportExportRequest(BaseModel):
    findings: List[Dict[str, Any]]
    target_path: str = "SecretScanner Web"


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Health-check endpoint."""
    return {"status": "ok", "service": "secret-scanner", "version": "0.1.0"}


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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan git repository: {str(e)}")


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


# ---------------------------------------------------------------------------
# Web Dashboard GUI
# ---------------------------------------------------------------------------
HTML_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecretScanner — Privacy-First Credential Leak Detection</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-card: rgba(18, 26, 43, 0.75);
      --bg-card-border: rgba(255, 255, 255, 0.08);
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --accent-cyan: #06b6d4;
      --danger: #ef4444;
      --danger-crit: #dc2626;
      --warning: #f59e0b;
      --success: #10b981;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }

    body {
      background: var(--bg-dark);
      color: var(--text-main);
      min-height: 100vh;
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(6, 182, 212, 0.12) 0px, transparent 50%);
      background-attachment: fixed;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1.25rem 2rem;
      border-bottom: 1px solid var(--bg-card-border);
      backdrop-filter: blur(12px);
      background: rgba(9, 13, 22, 0.85);
      position: sticky; top: 0; z-index: 100;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-weight: 700;
      font-size: 1.35rem;
      letter-spacing: -0.02em;
    }

    .brand-icon {
      width: 40px; height: 40px;
      background: linear-gradient(135deg, var(--primary), var(--accent-cyan));
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.4rem 0.9rem;
      border-radius: 9999px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--success);
      font-size: 0.85rem; font-weight: 500;
    }

    .status-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
    }

    .container {
      max-width: 1250px;
      margin: 2rem auto;
      padding: 0 1.5rem;
    }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
      border-bottom: 1px solid var(--bg-card-border);
      padding-bottom: 0.75rem;
      flex-wrap: wrap;
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.65rem 1.25rem;
      border-radius: 8px;
      font-weight: 500;
      cursor: pointer;
      display: flex; align-items: center; gap: 0.5rem;
      transition: all 0.2s ease;
    }

    .tab-btn:hover { color: var(--text-main); background: rgba(255, 255, 255, 0.05); }

    .tab-btn.active {
      color: white;
      background: var(--primary);
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
    }

    /* Card Panels */
    .panel {
      background: var(--bg-card);
      border: 1px solid var(--bg-card-border);
      border-radius: 16px;
      padding: 1.75rem;
      backdrop-filter: blur(16px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      margin-bottom: 2rem;
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .input-group {
      display: flex;
      gap: 0.75rem;
      margin-top: 1rem;
    }

    input[type="text"], textarea {
      flex: 1;
      background: rgba(9, 13, 22, 0.6);
      border: 1px solid var(--bg-card-border);
      border-radius: 10px;
      padding: 0.85rem 1.1rem;
      color: var(--text-main);
      font-size: 0.95rem;
      outline: none;
      transition: border 0.2s;
    }

    input[type="text"]:focus, textarea:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
    }

    textarea {
      width: 100%;
      height: 140px;
      font-family: 'Fira Code', monospace;
      font-size: 0.9rem;
      resize: vertical;
    }

    .btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 0.85rem 1.6rem;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex; align-items: center; gap: 0.5rem;
      transition: all 0.2s ease;
    }

    .btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-main);
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.15);
      transform: none; box-shadow: none;
    }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--bg-card-border);
      border-radius: 14px;
      padding: 1.25rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .stat-icon {
      width: 46px; height: 46px;
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.2rem;
    }

    .stat-val { font-size: 1.6rem; font-weight: 700; }
    .stat-lbl { font-size: 0.85rem; color: var(--text-muted); }

    /* Results Table */
    .table-container {
      overflow-x: auto;
      border-radius: 12px;
      border: 1px solid var(--bg-card-border);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.88rem;
    }

    th {
      background: rgba(9, 13, 22, 0.7);
      padding: 0.9rem 1.2rem;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--bg-card-border);
    }

    td {
      padding: 0.9rem 1.2rem;
      border-bottom: 1px solid var(--bg-card-border);
      background: rgba(18, 26, 43, 0.4);
    }

    tr:hover td { background: rgba(99, 102, 241, 0.05); }

    .badge {
      display: inline-block;
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .badge-critical { background: rgba(220, 38, 38, 0.25); color: #f87171; border: 1px solid #dc2626; }
    .badge-high { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }

    .code-text {
      font-family: 'Fira Code', monospace;
      color: var(--accent-cyan);
      background: rgba(0, 0, 0, 0.3);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.85rem;
    }

    .empty-state {
      text-align: center;
      padding: 3rem 1rem;
      color: var(--text-muted);
    }

    .empty-icon {
      font-size: 2.5rem;
      margin-bottom: 1rem;
      color: var(--primary);
    }

    .actions-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 0.75rem;
    }

    .loading-spinner {
      display: inline-block;
      width: 16px; height: 16px;
      border: 2px solid rgba(255,255,255,0.3);
      border-radius: 50%;
      border-top-color: white;
      animation: spin 0.8s linear infinite;
      margin-right: 0.5rem;
    }

    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>

  <!-- Header -->
  <header class="header">
    <div class="brand">
      <div class="brand-icon"><i class="fa-solid fa-shield-halved"></i></div>
      <span>SecretScanner</span>
    </div>
    <div style="display: flex; gap: 1rem; align-items: center;">
      <div class="status-badge"><span class="status-dot"></span> Engine Online</div>
      <a href="/docs" target="_blank" class="btn btn-secondary" style="padding: 0.5rem 1rem; font-size: 0.85rem;">
        <i class="fa-solid fa-code"></i> API Docs
      </a>
    </div>
  </header>

  <!-- Container -->
  <main class="container">

    <!-- Tabs -->
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('path', event)"><i class="fa-solid fa-folder-open"></i> Directory / File Scanner</button>
      <button class="tab-btn" onclick="switchTab('text', event)"><i class="fa-solid fa-file-code"></i> Code Snippet Scanner</button>
      <button class="tab-btn" onclick="switchTab('git', event)"><i class="fa-brands fa-git-alt"></i> Git Repo Scanner</button>
    </div>

    <!-- Tab 1: Path Scanner -->
    <div id="tab-path" class="tab-content active panel">
      <h2>Scan Directory or File</h2>
      <p style="color: var(--text-muted); margin-top: 0.25rem; font-size: 0.9rem;">
        Recursively scans local filesystem targets using high-entropy calculation and YAML-configured regex patterns.
      </p>
      <div class="input-group">
        <input type="text" id="target-path" placeholder="e.g. C:\Users\RUDRA SINGH\OneDrive\Desktop\Project">
        <button class="btn" id="btn-path" onclick="scanPath()"><i class="fa-solid fa-magnifying-glass"></i> Scan Target</button>
      </div>
    </div>

    <!-- Tab 2: Text Snippet Scanner -->
    <div id="tab-text" class="tab-content panel">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2>Scan Text / Code Snippet</h2>
        <button class="btn btn-secondary" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;" onclick="loadSampleText()">
          Load Sample Leak
        </button>
      </div>
      <p style="color: var(--text-muted); margin-top: 0.25rem; font-size: 0.9rem; margin-bottom: 0.75rem;">
        Paste raw code, config files, or logs below to instantly test for leaked credentials.
      </p>
      <textarea id="text-snippet" placeholder="Paste code or config text here..."></textarea>
      <div style="margin-top: 0.75rem; text-align: right;">
        <button class="btn" id="btn-text" onclick="scanText()"><i class="fa-solid fa-bolt"></i> Scan Snippet</button>
      </div>
    </div>

    <!-- Tab 3: Git Scanner -->
    <div id="tab-git" class="tab-content panel">
      <h2>Scan Git Repository History</h2>
      <p style="color: var(--text-muted); margin-top: 0.25rem; font-size: 0.9rem;">
        Traverses historical commits and git blobs with visited SHA deduplication. Supports local folders and remote URLs (e.g. GitHub/GitLab).
      </p>
      <div class="input-group">
        <input type="text" id="git-path" placeholder="e.g. . or C:\path\to\repo or https://github.com/owner/repo.git" style="flex: 2;">
        <input type="number" id="git-max-commits" placeholder="Max commits (optional)" min="1" style="max-width: 180px;">
        <button class="btn" id="btn-git" onclick="scanGit()"><i class="fa-brands fa-git-alt"></i> Scan Git History</button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(239, 68, 68, 0.15); color: var(--danger);">
          <i class="fa-solid fa-triangle-exclamation"></i>
        </div>
        <div>
          <div class="stat-val" id="stat-total">0</div>
          <div class="stat-lbl">Total Secrets Found</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(220, 38, 38, 0.2); color: #f87171;">
          <i class="fa-solid fa-radiation"></i>
        </div>
        <div>
          <div class="stat-val" id="stat-crit">0</div>
          <div class="stat-lbl">Critical / High Severity</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(245, 158, 11, 0.15); color: var(--warning);">
          <i class="fa-solid fa-key"></i>
        </div>
        <div>
          <div class="stat-val" id="stat-medium">0</div>
          <div class="stat-lbl">Medium / Low Severity</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(99, 102, 241, 0.15); color: var(--primary);">
          <i class="fa-solid fa-file"></i>
        </div>
        <div>
          <div class="stat-val" id="stat-files">0</div>
          <div class="stat-lbl">Files / Blobs Affected</div>
        </div>
      </div>
    </div>

    <!-- Results Table -->
    <div class="panel">
      <div class="actions-bar">
        <h3>Detection Results</h3>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <button class="btn btn-secondary" style="padding: 0.45rem 0.85rem; font-size: 0.82rem;" onclick="exportHTML()">
            <i class="fa-solid fa-file-code"></i> HTML Report
          </button>
          <button class="btn btn-secondary" style="padding: 0.45rem 0.85rem; font-size: 0.82rem;" onclick="exportMarkdown()">
            <i class="fa-solid fa-file-lines"></i> Markdown
          </button>
          <button class="btn btn-secondary" style="padding: 0.45rem 0.85rem; font-size: 0.82rem;" onclick="exportSARIF()">
            <i class="fa-solid fa-shield-virus"></i> SARIF 2.1
          </button>
          <button class="btn btn-secondary" style="padding: 0.45rem 0.85rem; font-size: 0.82rem;" onclick="exportJSON()">
            <i class="fa-solid fa-download"></i> JSON
          </button>
          <button class="btn btn-secondary" style="padding: 0.45rem 0.85rem; font-size: 0.82rem;" onclick="exportCSV()">
            <i class="fa-solid fa-file-csv"></i> CSV
          </button>
        </div>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule / Type</th>
              <th>Location</th>
              <th>Line : Col</th>
              <th>Masked Secret</th>
              <th>Context / Commit</th>
            </tr>
          </thead>
          <tbody id="results-body">
            <tr>
              <td colspan="6">
                <div class="empty-state">
                  <div class="empty-icon"><i class="fa-solid fa-shield-check"></i></div>
                  <p style="font-weight: 500; color: var(--text-main);">No scans performed yet</p>
                  <p style="font-size: 0.85rem; margin-top: 0.25rem;">Enter a directory path above, scan a snippet, or run a git history scan.</p>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

  </main>

  <script>
    let currentFindings = [];
    let lastScanTarget = "SecretScanner Web";

    function switchTab(tabId, ev) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      ev.currentTarget.classList.add('active');
      document.getElementById('tab-' + tabId).classList.add('active');
    }

    function loadSampleText() {
      document.getElementById('text-snippet').value = 
        `# Cloud configuration demo\n` +
        `AWS_ACCESS_KEY_ID=FAKE_AWS_KEY_FOR_DEMO_ONLY\n` +
        `AWS_SECRET_ACCESS_KEY=FAKE_AWS_SECRET_FOR_DEMO_ONLY\n` +
        `STRIPE_KEY=FAKE_STRIPE_KEY_FOR_DEMO_ONLY\n` +
        `GITHUB_TOKEN=FAKE_GITHUB_TOKEN_FOR_DEMO_ONLY\n` +
        `SLACK_TOKEN=FAKE_SLACK_TOKEN_FOR_DEMO_ONLY`;
    }

    async function scanPath() {
      const path = document.getElementById('target-path').value.trim() || ".";
      lastScanTarget = path;
      const btn = document.getElementById('btn-path');
      btn.innerHTML = '<span class="loading-spinner"></span> Scanning...';
      btn.disabled = true;

      try {
        const res = await fetch('/scan', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ path: path })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Scan failed');
        renderFindings(data.findings);
      } catch (err) {
        alert('Scan Error: ' + err.message);
      } finally {
        btn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Scan Target';
        btn.disabled = false;
      }
    }

    async function scanText() {
      const text = document.getElementById('text-snippet').value;
      if (!text) return alert('Please paste text snippet.');
      lastScanTarget = "Inline Code Snippet";
      const btn = document.getElementById('btn-text');
      btn.innerHTML = '<span class="loading-spinner"></span> Scanning...';
      btn.disabled = true;

      try {
        const res = await fetch('/scan/text', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ text: text })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Scan failed');
        renderFindings(data.findings);
      } catch (err) {
        alert('Scan Error: ' + err.message);
      } finally {
        btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Scan Snippet';
        btn.disabled = false;
      }
    }

    async function scanGit() {
      const path = document.getElementById('git-path').value.trim() || ".";
      const maxCommitsVal = document.getElementById('git-max-commits')?.value.trim();
      const maxCommits = maxCommitsVal ? parseInt(maxCommitsVal, 10) : null;

      lastScanTarget = "Git: " + path;
      const btn = document.getElementById('btn-git');
      const isRemote = path.startsWith('http://') || path.startsWith('https://') || path.startsWith('git@') || path.startsWith('ssh://');
      btn.innerHTML = isRemote ? '<span class="loading-spinner"></span> Cloning & Scanning...' : '<span class="loading-spinner"></span> Scanning Git...';
      btn.disabled = true;

      try {
        const payload = { repo_path: path };
        if (maxCommits && maxCommits > 0) {
          payload.max_commits = maxCommits;
        }
        const res = await fetch('/scan/git', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Git scan failed');
        renderFindings(data.findings);
      } catch (err) {
        alert('Git Scan Error: ' + err.message);
      } finally {
        btn.innerHTML = '<i class="fa-brands fa-git-alt"></i> Scan Git History';
        btn.disabled = false;
      }
    }

    function renderFindings(findings) {
      currentFindings = findings;
      const tbody = document.getElementById('results-body');
      
      const critCount = findings.filter(f => ['CRITICAL', 'HIGH'].includes((f.severity || '').toUpperCase())).length;
      const medCount = findings.filter(f => !['CRITICAL', 'HIGH'].includes((f.severity || '').toUpperCase())).length;
      const uniqueFiles = new Set(findings.map(f => f.file));

      document.getElementById('stat-total').innerText = findings.length;
      document.getElementById('stat-crit').innerText = critCount;
      document.getElementById('stat-medium').innerText = medCount;
      document.getElementById('stat-files').innerText = uniqueFiles.size;

      if (findings.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6">
              <div class="empty-state">
                <div class="empty-icon" style="color: var(--success);"><i class="fa-solid fa-circle-check"></i></div>
                <p style="font-weight: 500; color: var(--text-main);">Clean scan! No secrets detected.</p>
              </div>
            </td>
          </tr>`;
        return;
      }

      tbody.innerHTML = findings.map(f => {
        const sev = (f.severity || 'MEDIUM').toUpperCase();
        let badgeClass = 'badge-medium';
        if (sev === 'CRITICAL') badgeClass = 'badge-critical';
        else if (sev === 'HIGH') badgeClass = 'badge-high';
        else if (sev === 'LOW') badgeClass = 'badge-low';

        const commitHtml = f.commit_hash ? 
          `<br><span style="color: #64748b; font-size: 0.75rem;">Commit: <code>${f.commit_hash}</code> (${f.commit_author || ''})</span>` : '';

        return `
          <tr>
            <td><span class="badge ${badgeClass}">${sev}</span></td>
            <td><strong>${f.rule_name || f.type}</strong><br><span style="color: #64748b; font-size: 0.75rem;"><code>${f.type}</code></span></td>
            <td style="word-break: break-all; max-width: 250px;"><code>${f.file}</code></td>
            <td>L${f.line} : C${f.col}</td>
            <td><span class="code-text">${f.masked_value || '****'}</span></td>
            <td style="max-width: 320px; word-break: break-all;"><span style="font-family: monospace; font-size: 0.8rem; color: #cbd5e1;">${f.context || ''}</span>${commitHtml}</td>
          </tr>
        `;
      }).join('');
    }

    async function exportHTML() {
      if (!currentFindings.length) return alert('No findings to export.');
      const res = await fetch('/report/html', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ findings: currentFindings, target_path: lastScanTarget })
      });
      const text = await res.text();
      downloadBlob(text, 'secret_audit_report.html', 'text/html');
    }

    async function exportMarkdown() {
      if (!currentFindings.length) return alert('No findings to export.');
      const res = await fetch('/report/markdown', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ findings: currentFindings, target_path: lastScanTarget })
      });
      const text = await res.text();
      downloadBlob(text, 'secret_audit_report.md', 'text/markdown');
    }

    async function exportSARIF() {
      if (!currentFindings.length) return alert('No findings to export.');
      const res = await fetch('/report/sarif', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ findings: currentFindings, target_path: lastScanTarget })
      });
      const text = await res.text();
      downloadBlob(text, 'secret_audit_report.sarif', 'application/json');
    }

    function exportJSON() {
      if (!currentFindings.length) return alert('No findings to export.');
      downloadBlob(JSON.stringify(currentFindings, null, 2), 'secret_scan_results.json', 'application/json');
    }

    function exportCSV() {
      if (!currentFindings.length) return alert('No findings to export.');
      let csv = 'Severity,Rule,Type,File,Line,Column,Score,MaskedSecret,Fingerprint,CommitHash\n';
      currentFindings.forEach(f => {
        csv += `"${f.severity || ''}","${f.rule_name || ''}","${f.type}","${f.file}",${f.line},${f.col},${f.score},"${f.masked_value || ''}","${f.fingerprint}","${f.commit_hash || ''}"\n`;
      });
      downloadBlob(csv, 'secret_scan_results.csv', 'text/csv');
    }

    function downloadBlob(content, filename, contentType) {
      const blob = new Blob([content], {type: contentType});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the privacy-first Web GUI dashboard."""
    return HTML_DASHBOARD
