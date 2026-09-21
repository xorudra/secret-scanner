"""secret_scanner.api.scheduler
Scan scheduling with APScheduler and webhook notifications.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from secret_scanner.core.engine import DetectionEngine
from secret_scanner.git_scanner import scan_repository

from .app import scan_path


router = APIRouter(prefix="/schedule", tags=["scheduling"])


# ─── In-Memory Schedule Store ──────────────────────────────────────────────────
# In production, use a database (PostgreSQL, SQLite, etc.)
_schedules: dict[str, dict[str, Any]] = {}
_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
        _scheduler.start()
    return _scheduler


def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown()
        _scheduler = None


# ─── Models ────────────────────────────────────────────────────────────────────
class ScheduleCreateRequest(BaseModel):
    name: str
    cron_expression: str
    scan_type: str  # "path", "git", "url"
    scan_config: dict[str, Any]  # path, repo_path, url, etc.
    webhook_url: str | None = None
    webhook_secret: str | None = None
    enabled: bool = True

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        try:
            CronTrigger.from_crontab(v)
        except Exception as e:
            raise ValueError(f"Invalid cron expression: {e}")
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ("path", "git", "url"):
            raise ValueError("scan_type must be 'path', 'git', or 'url'")
        return v


class ScheduleUpdateRequest(BaseModel):
    name: str | None = None
    cron_expression: str | None = None
    scan_config: dict[str, Any] | None = None
    webhook_url: str | None = None
    webhook_secret: str | None = None
    enabled: bool | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                CronTrigger.from_crontab(v)
            except Exception as e:
                raise ValueError(f"Invalid cron expression: {e}")
        return v


class ScheduleResponse(BaseModel):
    id: str
    name: str
    cron_expression: str
    scan_type: str
    scan_config: dict[str, Any]
    webhook_url: str | None
    enabled: bool
    created_at: str
    updated_at: str
    last_run: str | None
    next_run: str | None
    run_count: int


# ─── Scan Execution ────────────────────────────────────────────────────────────
async def run_scheduled_scan(schedule_id: str):
    """Execute a scheduled scan and send webhook notification."""
    schedule = _schedules.get(schedule_id)
    if not schedule or not schedule.get("enabled"):
        return

    scan_type = schedule["scan_type"]
    config = schedule["scan_config"]
    webhook_url = schedule.get("webhook_url")
    webhook_secret = schedule.get("webhook_secret")

    scan_id = f"sched-{schedule_id}-{uuid.uuid4().hex[:8]}"
    findings = []
    error = None

    try:
        if scan_type == "path":
            path = config.get("path", ".")
            findings = scan_path(path)
        elif scan_type == "git":
            repo_path = config.get("repo_path", ".")
            max_commits = config.get("max_commits")
            findings = scan_repository(repo_path, max_commits=max_commits)
        elif scan_type == "url":
            url = config.get("url")
            if url:
                engine = DetectionEngine()
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    raw = engine.scan(resp.text, file_path=url)
                    findings = [f.to_dict() for f in raw]

        schedule["last_run"] = datetime.utcnow().isoformat()
        schedule["run_count"] = schedule.get("run_count", 0) + 1

        scheduler = get_scheduler()
        job = scheduler.get_job(schedule_id)
        if job:
            schedule["next_run"] = job.next_run_time.isoformat() if job.next_run_time else None

    except Exception as e:  # noqa: BLE001
        error = str(e)
        schedule["last_error"] = error
        schedule["last_run"] = datetime.utcnow().isoformat()

    if webhook_url:
        await send_webhook(webhook_url, webhook_secret, {
            "schedule_id": schedule_id,
            "schedule_name": schedule["name"],
            "scan_type": scan_type,
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "findings_count": len(findings),
            "error": error,
            "findings": findings[:10] if findings else [],
        })

    return findings


async def send_webhook(url: str, secret: str | None, payload: dict):
    """Send webhook notification with optional HMAC signature."""
    headers = {"Content-Type": "application/json"}
    body = json.dumps(payload)

    if secret:
        import hmac
        import hashlib
        signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-SecretScanner-Signature"] = f"sha256={signature}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:  # noqa: BLE001
        pass


# ─── API Endpoints ─────────────────────────────────────────────────────────────
@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(req: ScheduleCreateRequest):
    """Create a new scheduled scan."""
    schedule_id = uuid.uuid4().hex
    now = datetime.utcnow().isoformat()

    schedule = {
        "id": schedule_id,
        "name": req.name,
        "cron_expression": req.cron_expression,
        "scan_type": req.scan_type,
        "scan_config": req.scan_config,
        "webhook_url": req.webhook_url,
        "webhook_secret": req.webhook_secret,
        "enabled": req.enabled,
        "created_at": now,
        "updated_at": now,
        "last_run": None,
        "next_run": None,
        "run_count": 0,
    }

    _schedules[schedule_id] = schedule

    if req.enabled:
        await _add_job(schedule_id, req.cron_expression)

    return ScheduleResponse(**schedule)


async def _add_job(schedule_id: str, cron_expr: str):
    """Add a job to the scheduler."""
    scheduler = get_scheduler()
    trigger = CronTrigger.from_crontab(cron_expr)
    scheduler.add_job(
        run_scheduled_scan,
        trigger=trigger,
        args=[schedule_id],
        id=schedule_id,
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules():
    """List all scheduled scans."""
    return [ScheduleResponse(**s) for s in _schedules.values()]


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(schedule_id: str):
    """Get a specific schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return ScheduleResponse(**_schedules[schedule_id])


@router.patch("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(schedule_id: str, req: ScheduleUpdateRequest):
    """Update a schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule = _schedules[schedule_id]
    update_data = req.model_dump(exclude_unset=True)

    if "cron_expression" in update_data and update_data["cron_expression"] != schedule["cron_expression"]:
        await _add_job(schedule_id, update_data["cron_expression"])

    schedule.update(update_data)
    schedule["updated_at"] = datetime.utcnow().isoformat()

    return ScheduleResponse(**schedule)


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str):
    """Delete a schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")

    scheduler = get_scheduler()
    scheduler.remove_job(schedule_id)

    del _schedules[schedule_id]


@router.post("/{schedule_id}/run", response_model=dict)
async def run_schedule_now(schedule_id: str):
    """Manually trigger a scheduled scan."""
    if schedule_id not in _schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule = _schedules[schedule_id]
    findings = await run_scheduled_scan(schedule_id)

    return {
        "message": "Scan triggered",
        "findings_count": len(findings) if findings else 0,
        "scan_id": f"sched-{schedule_id}-{uuid.uuid4().hex[:8]}"
    }


@router.post("/{schedule_id}/toggle", response_model=ScheduleResponse)
async def toggle_schedule(schedule_id: str):
    """Enable/disable a schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule = _schedules[schedule_id]
    schedule["enabled"] = not schedule["enabled"]
    schedule["updated_at"] = datetime.utcnow().isoformat()

    if schedule["enabled"]:
        await _add_job(schedule_id, schedule["cron_expression"])
    else:
        scheduler = get_scheduler()
        scheduler.remove_job(schedule_id)
        schedule["next_run"] = None

    return ScheduleResponse(**schedule)
