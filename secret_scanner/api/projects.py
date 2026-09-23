"""secret_scanner.api.projects
Team projects API with CRUD, member management, repository scanning, and dashboard.
"""

from __future__ import annotations

import pathlib
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from secret_scanner.core.engine import DetectionEngine
from secret_scanner.git_scanner import scan_repository

from .app import scan_path

router = APIRouter(prefix="/projects", tags=["projects"])

_projects: dict[str, dict[str, Any]] = {}
_project_members: dict[str, list[dict[str, Any]]] = {}


class RepoConfig(BaseModel):
    """A single repository configured inside a team project."""

    name: str
    url: str = ""  # local filesystem path or remote URL
    scan_type: str = "path"

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ("path", "git", "url"):
            raise ValueError("scan_type must be path, git, or url")
        return v


class ProjectCreateRequest(BaseModel):
    name: str
    description: str = ""
    repo_path: str = ""
    scan_config: dict[str, Any] = {}
    default_scan_type: str = "path"
    repositories: list[RepoConfig] = []

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Project name cannot be empty")
        return v.strip()


class ProjectUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    repo_path: str | None = None
    scan_config: dict[str, Any] | None = None
    default_scan_type: str | None = None
    repositories: list[RepoConfig] | None = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    repo_path: str = ""
    scan_config: dict[str, Any] = {}
    default_scan_type: str = "path"
    repositories: list[RepoConfig] = []
    created_at: str
    updated_at: str
    scan_count: int


class MemberAddRequest(BaseModel):
    user_id: str
    email: str
    role: str = "member"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("owner", "admin", "member", "viewer"):
            raise ValueError("Role must be owner, admin, member, or viewer")
        return v


class MemberResponse(BaseModel):
    user_id: str
    email: str
    role: str
    joined_at: str


class ScanRequest(BaseModel):
    repo_path: str | None = None
    scan_type: str = "path"

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ("path", "git", "url"):
            raise ValueError("scan_type must be path, git, or url")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    findings_count: int
    findings: list[dict[str, Any]]


def _get_project_or_404(project_id: str) -> dict[str, Any]:
    if project_id not in _projects:
        raise HTTPException(status_code=404, detail="Project not found")
    return _projects[project_id]


def _get_member(project_id: str, user_id: str) -> dict[str, Any] | None:
    members = _project_members.get(project_id, [])
    for m in members:
        if m["user_id"] == user_id:
            return m
    return None


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(req: ProjectCreateRequest):
    """Create a new team project."""
    project_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    project = {
        "id": project_id,
        "name": req.name,
        "description": req.description,
        "repo_path": req.repo_path,
        "scan_config": req.scan_config,
        "default_scan_type": req.default_scan_type,
        "repositories": [r.model_dump() for r in req.repositories],
        "created_at": now,
        "updated_at": now,
        "scan_count": 0,
    }
    _projects[project_id] = project
    _project_members[project_id] = []

    return ProjectResponse(**project)


@router.get("", response_model=list[ProjectResponse])
async def list_projects():
    """List all team projects."""
    return [ProjectResponse(**p) for p in _projects.values()]


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str):
    """Get a specific project."""
    project = _get_project_or_404(project_id)
    return ProjectResponse(**project)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: str, req: ProjectUpdateRequest):
    """Update a project."""
    project = _get_project_or_404(project_id)
    update_data = req.model_dump(exclude_unset=True)

    project.update(update_data)
    project["updated_at"] = datetime.now(timezone.utc).isoformat()

    return ProjectResponse(**project)


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: str):
    """Delete a project."""
    if project_id not in _projects:
        raise HTTPException(status_code=404, detail="Project not found")
    _projects.pop(project_id, None)
    _project_members.pop(project_id, None)


@router.post("/{project_id}/members", response_model=MemberResponse, status_code=201)
async def add_member(project_id: str, req: MemberAddRequest):
    """Add a member to a project."""
    _get_project_or_404(project_id)

    if _get_member(project_id, req.user_id):
        raise HTTPException(status_code=409, detail="Member already exists")

    member = {
        "user_id": req.user_id,
        "email": req.email,
        "role": req.role,
        "joined_at": datetime.now(timezone.utc).isoformat(),
    }
    _project_members.setdefault(project_id, []).append(member)

    return MemberResponse(**member)


@router.get("/{project_id}/members", response_model=list[MemberResponse])
async def list_members(project_id: str):
    """List all members of a project."""
    _get_project_or_404(project_id)
    return [MemberResponse(**m) for m in _project_members.get(project_id, [])]


@router.delete("/{project_id}/members/{user_id}", status_code=204)
async def remove_member(project_id: str, user_id: str):
    """Remove a member from a project."""
    _get_project_or_404(project_id)
    member = _get_member(project_id, user_id)
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")
    _project_members[project_id] = [m for m in _project_members[project_id] if m["user_id"] != user_id]


@router.post("/{project_id}/scan", response_model=ScanResponse, status_code=201)
async def scan_project(project_id: str, req: ScanRequest):
    """Scan a project's repository for secrets."""
    project = _get_project_or_404(project_id)

    repo_path = req.repo_path or project.get("repo_path", ".")
    scan_type = req.scan_type
    scan_id = f"proj-{project_id}-{uuid.uuid4().hex[:8]}"
    findings: list[dict[str, Any]] = []

    try:
        if scan_type == "path":
            findings = scan_path(repo_path)
        elif scan_type == "git":
            findings = scan_repository(repo_path)
        elif scan_type == "url":
            engine = DetectionEngine()
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(repo_path)
                resp.raise_for_status()
                raw = engine.scan(resp.text, file_path=repo_path)
                findings = [f.to_dict() for f in raw]

        project["scan_count"] = project.get("scan_count", 0) + 1
        project["updated_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Scan failed: {e!s}")

    return ScanResponse(scan_id=scan_id, findings_count=len(findings), findings=findings)


@router.post("/{project_id}/scan-all")
async def scan_all_project_repos(project_id: str):
    """Scan every repository configured in a project and aggregate the results."""
    project = _get_project_or_404(project_id)
    repos = project.get("repositories", [])
    if not repos:
        raise HTTPException(status_code=400, detail="Project has no repositories configured")

    engine = DetectionEngine()
    repo_results: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []

    for repo in repos:
        name = repo.get("name") or repo.get("url") or repo.get("path") or "repository"
        target = repo.get("url") or repo.get("path") or ""
        scan_type = repo.get("scan_type", "path")
        entry: dict[str, Any] = {
            "repo": name,
            "target": target,
            "scan_type": scan_type,
            "findings_count": 0,
            "findings": [],
            "error": None,
        }
        if not target:
            entry["error"] = "No target configured for this repository"
            repo_results.append(entry)
            continue
        try:
            if scan_type == "path":
                if not pathlib.Path(target).exists():
                    raise FileNotFoundError(f"Target path does not exist: {target}")
                findings = scan_path(target)
            elif scan_type == "git":
                findings = scan_repository(target)
            elif scan_type == "url":
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(target)
                    resp.raise_for_status()
                    raw = engine.scan(resp.text, file_path=target)
                    findings = [f.to_dict() for f in raw]
            else:
                findings = []
            entry["findings_count"] = len(findings)
            entry["findings"] = findings[:100]
            all_findings.extend(findings)
        except Exception as e:  # noqa: BLE001 - report per-repo failure, keep scanning
            entry["error"] = str(e)
        repo_results.append(entry)

    project["scan_count"] = project.get("scan_count", 0) + 1
    project["updated_at"] = datetime.now(timezone.utc).isoformat()
    history = project.setdefault("_scan_history", [])
    history.append({
        "ts": project["updated_at"],
        "findings_count": len(all_findings),
        "findings": all_findings[:500],
    })

    return {
        "project_id": project_id,
        "repo_results": repo_results,
        "total_findings": len(all_findings),
    }


@router.get("/{project_id}/dashboard")
async def project_dashboard(project_id: str):
    """Get project dashboard data."""
    project = _get_project_or_404(project_id)
    members = _project_members.get(project_id, [])

    total_scans = project.get("scan_count", 0)
    total_findings = 0
    by_severity: dict[str, int] = {}

    for scan_record in _projects.get(project_id, {}).get("_scan_history", []):
        for f in scan_record.get("findings", []):
            severity = f.get("severity", "unknown").lower()
            by_severity[severity] = by_severity.get(severity, 0) + 1
            total_findings += 1

    return {
        "project": project,
        "members": [MemberResponse(**m) for m in members],
        "stats": {
            "total_repos": len(project.get("repositories", [])),
            "total_scans": total_scans,
            "total_findings": total_findings,
            "by_severity": by_severity,
            "member_count": len(members),
        },
    }

