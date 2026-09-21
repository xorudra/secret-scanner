"""secret_scanner.api.projects
Team projects API with CRUD, member management, repository scanning, and dashboard.
"""

from __future__ import annotations

import uuid
from datetime import datetime
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


class ProjectCreateRequest(BaseModel):
    name: str
    description: str = ""
    repo_path: str = ""
    scan_config: dict[str, Any] = {}

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


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    repo_path: str
    scan_config: dict[str, Any]
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
    now = datetime.utcnow().isoformat()

    project = {
        "id": project_id,
        "name": req.name,
        "description": req.description,
        "repo_path": req.repo_path,
        "scan_config": req.scan_config,
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
    project["updated_at"] = datetime.utcnow().isoformat()

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
        "joined_at": datetime.utcnow().isoformat(),
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
        project["updated_at"] = datetime.utcnow().isoformat()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Scan failed: {e!s}")

    return ScanResponse(scan_id=scan_id, findings_count=len(findings), findings=findings)


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
            "total_scans": total_scans,
            "total_findings": total_findings,
            "by_severity": by_severity,
            "member_count": len(members),
        },
    }

