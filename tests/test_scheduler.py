"""Unit tests for secret_scanner.api.scheduler"""

import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

from secret_scanner.api import scheduler as scheduler_mod
from secret_scanner.api.scheduler import (
    ScheduleCreateRequest,
    create_schedule,
    delete_schedule,
    get_schedule,
    list_schedules,
    run_schedule_now,
    toggle_schedule,
    update_schedule,
)


class _StubScheduler:
    """Minimal APScheduler stand-in so tests don't need a live event loop.

    AsyncIOScheduler binds to the event loop it was started on; since each
    asyncio.run() call creates (and closes) a fresh loop, tests stub the
    scheduler out instead.
    """

    def __init__(self):
        self.jobs: dict[str, dict] = {}

    def add_job(self, fn, trigger=None, args=None, id=None, **kwargs):
        self.jobs[id] = {"fn": fn, "args": args, "trigger": trigger}

    def remove_job(self, job_id):
        self.jobs.pop(job_id, None)

    def get_job(self, job_id):
        return None  # next_run tracking not needed in tests

    def shutdown(self, *args, **kwargs):
        self.jobs.clear()


class TestScheduler(unittest.TestCase):

    def setUp(self):
        self.name = f"test-schedule-{id(self)}"
        self._orig_get_scheduler = scheduler_mod.get_scheduler
        self.stub = _StubScheduler()
        scheduler_mod.get_scheduler = lambda: self.stub
        scheduler_mod._schedules.clear()

    def tearDown(self):
        scheduler_mod.get_scheduler = self._orig_get_scheduler
        scheduler_mod._schedules.clear()

    def _make_request(self, **overrides):
        data = {
            "name": self.name,
            "cron_expression": "0 2 * * *",
            "scan_type": "path",
            "scan_config": {"path": "."},
        }
        data.update(overrides)
        return ScheduleCreateRequest(**data)

    def test_cron_validation(self):
        with self.assertRaises(ValidationError):
            self._make_request(cron_expression="not a cron")

    def test_scan_type_validation(self):
        with self.assertRaises(ValidationError):
            self._make_request(scan_type="bogus")

    def test_create_list_get_delete(self):
        created = asyncio.run(create_schedule(self._make_request()))
        self.assertEqual(created.name, self.name)
        self.assertTrue(created.enabled)
        self.assertEqual(created.run_count, 0)

        listed = asyncio.run(list_schedules())
        self.assertTrue(any(s.id == created.id for s in listed))

        got = asyncio.run(get_schedule(created.id))
        self.assertEqual(got.id, created.id)

        asyncio.run(delete_schedule(created.id))
        with self.assertRaises(HTTPException):
            asyncio.run(get_schedule(created.id))

    def test_toggle_schedule(self):
        created = asyncio.run(create_schedule(self._make_request()))
        self.assertTrue(created.enabled)

        toggled = asyncio.run(toggle_schedule(created.id))
        self.assertFalse(toggled.enabled)

        toggled_back = asyncio.run(toggle_schedule(created.id))
        self.assertTrue(toggled_back.enabled)
        asyncio.run(delete_schedule(created.id))

    def test_update_schedule(self):
        from secret_scanner.api.scheduler import ScheduleUpdateRequest
        created = asyncio.run(create_schedule(self._make_request()))
        upd = ScheduleUpdateRequest(cron_expression="0 */6 * * *", name="renamed")
        updated = asyncio.run(update_schedule(created.id, upd))
        self.assertEqual(updated.cron_expression, "0 */6 * * *")
        self.assertEqual(updated.name, "renamed")
        asyncio.run(delete_schedule(created.id))

    def test_run_schedule_now_executes_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            secret_file = Path(temp_dir) / "config.env"
            secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

            created = asyncio.run(create_schedule(
                self._make_request(scan_config={"path": temp_dir})
            ))
            result = asyncio.run(run_schedule_now(created.id))
            self.assertGreaterEqual(result["findings_count"], 1)

            after = asyncio.run(get_schedule(created.id))
            self.assertGreaterEqual(after.run_count, 1)
            self.assertIsNotNone(after.last_run)
            asyncio.run(delete_schedule(created.id))

    def test_run_missing_schedule_404(self):
        with self.assertRaises(HTTPException):
            asyncio.run(run_schedule_now("nonexistent-id"))


if __name__ == "__main__":
    unittest.main()
