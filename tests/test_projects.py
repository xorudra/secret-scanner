"""Unit tests for secret_scanner.api.projects"""

import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

from secret_scanner.api.projects import (
    ProjectCreateRequest,
    RepoConfig,
    create_project,
    delete_project,
    get_project,
    list_projects,
    project_dashboard,
    scan_all_project_repos,
    update_project,
)


class TestProjects(unittest.TestCase):

    def setUp(self):
        # Each test gets a unique project name so the in-memory store stays isolated
        self.name = f"test-project-{id(self)}"

    def test_repo_config_validation(self):
        with self.assertRaises(ValidationError):
            RepoConfig(name="x", url=".", scan_type="bogus")
        repo = RepoConfig(name="x", url=".", scan_type="path")
        self.assertEqual(repo.scan_type, "path")

    def test_create_and_get_project(self):
        req = ProjectCreateRequest(
            name=self.name,
            description="desc",
            default_scan_type="path",
            repositories=[RepoConfig(name="repo1", url=".", scan_type="path")],
        )
        res = asyncio.run(create_project(req))
        self.assertEqual(res.name, self.name)
        self.assertEqual(res.default_scan_type, "path")
        self.assertEqual(len(res.repositories), 1)
        self.assertEqual(res.repositories[0].name, "repo1")

        pid = res.id
        got = asyncio.run(get_project(pid))
        self.assertEqual(got.id, pid)
        self.assertEqual(len(got.repositories), 1)

        listed = asyncio.run(list_projects())
        self.assertTrue(any(p.id == pid for p in listed))

        asyncio.run(delete_project(pid))
        with self.assertRaises(HTTPException):
            asyncio.run(get_project(pid))

    def test_update_project_repositories(self):
        req = ProjectCreateRequest(name=self.name)
        res = asyncio.run(create_project(req))

        from secret_scanner.api.projects import ProjectUpdateRequest
        upd = ProjectUpdateRequest(
            repositories=[RepoConfig(name="r1", url="/tmp/x", scan_type="git")],
            default_scan_type="git",
        )
        updated = asyncio.run(update_project(res.id, upd))
        self.assertEqual(updated.default_scan_type, "git")
        self.assertEqual(len(updated.repositories), 1)
        self.assertEqual(updated.repositories[0].url, "/tmp/x")
        asyncio.run(delete_project(res.id))

    def test_scan_all_aggregates_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            secret_file = Path(temp_dir) / "config.env"
            secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

            req = ProjectCreateRequest(
                name=self.name,
                repositories=[
                    RepoConfig(name="secrets-repo", url=temp_dir, scan_type="path"),
                    RepoConfig(name="bad-target", url="Z:/does/not/exist", scan_type="path"),
                ],
            )
            created = asyncio.run(create_project(req))
            result = asyncio.run(scan_all_project_repos(created.id))

            self.assertEqual(len(result["repo_results"]), 2)
            self.assertIsNone(result["repo_results"][0]["error"])
            self.assertGreaterEqual(result["repo_results"][0]["findings_count"], 1)
            self.assertIsNotNone(result["repo_results"][1]["error"])
            self.assertGreaterEqual(result["total_findings"], 1)

            # Dashboard should now reflect the repos and the aggregated scan
            dash = asyncio.run(project_dashboard(created.id))
            self.assertEqual(dash["stats"]["total_repos"], 2)
            self.assertGreaterEqual(dash["stats"]["total_findings"], 1)
            self.assertGreaterEqual(dash["project"]["scan_count"], 1)

            asyncio.run(delete_project(created.id))

    def test_scan_all_requires_repositories(self):
        req = ProjectCreateRequest(name=self.name)
        created = asyncio.run(create_project(req))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(scan_all_project_repos(created.id))
        self.assertEqual(ctx.exception.status_code, 400)
        asyncio.run(delete_project(created.id))


if __name__ == "__main__":
    unittest.main()
