"""secret_scanner.git_scanner
Scan a Git repository's full commit history for leaked secrets with commit metadata
and visited blob deduplication. Supports both local paths and remote Git URLs.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import tempfile
from typing import List, Dict, Any, Optional, Generator, Tuple

import git

from secret_scanner.core.engine import DetectionEngine
from secret_scanner.core.rules import load_rules
from secret_scanner.core.ignore import IgnoreFilter


def is_git_url(path_or_url: str | Path) -> bool:
    """Check if the string/path represents a remote Git repository URL."""
    s = str(path_or_url).strip()
    if s.startswith(("http://", "https://", "git@", "ssh://", "git://")):
        return True
    if s.endswith(".git") and (":" in s or "/" in s):
        return True
    return False


def clone_repository(
    repo_url: str,
    dest_dir: Path | str,
    depth: Optional[int] = None,
) -> git.Repo:
    """Clone a remote Git repository to *dest_dir* with optional shallow clone depth."""
    kwargs: Dict[str, Any] = {}
    if depth is not None and depth > 0:
        kwargs["depth"] = depth
    return git.Repo.clone_from(repo_url, str(dest_dir), **kwargs)


def iter_git_objects(
    repo: git.Repo,
    max_commits: Optional[int] = None,
    ignore_filter: Optional[IgnoreFilter] = None,
) -> Generator[Tuple[git.Commit, str, str], None, None]:
    """Traverse commits and yield (commit, blob_path, content_text).

    Maintains a set of visited blob object IDs to prevent re-scanning identical
    blobs that exist across multiple commits.
    """
    seen_blob_shas: set[str] = set()

    commit_kwargs: Dict[str, Any] = {}
    if max_commits is not None and max_commits > 0:
        commit_kwargs["max_count"] = max_commits

    # Retrieve commits with fallbacks for shallow clones, unborn branches, etc.
    commits: List[git.Commit] = []
    try:
        commits = list(repo.iter_commits("--all", **commit_kwargs))
    except Exception:
        try:
            commits = list(repo.iter_commits(**commit_kwargs))
        except Exception:
            try:
                commits = [repo.head.commit]
            except Exception:
                commits = []

    for commit in commits:
        try:
            tree = commit.tree
            items = list(tree.traverse())
        except Exception:
            continue

        for item in items:
            if item.type != "blob":
                continue

            # Check ignore filter if provided
            if ignore_filter is not None and ignore_filter.is_ignored(item.path):
                continue

            if item.hexsha in seen_blob_shas:
                continue
            seen_blob_shas.add(item.hexsha)

            try:
                raw_bytes = item.data_stream.read()
                # Skip binary blobs containing null bytes
                if b"\x00" in raw_bytes[:8192]:
                    continue
                content = raw_bytes.decode("utf-8", errors="ignore")
                yield commit, item.path, content
            except Exception:
                continue


def _scan_repo_instance(
    repo: git.Repo,
    base_display_path: str,
    max_commits: Optional[int] = None,
    engine: Optional[DetectionEngine] = None,
    custom_rules_path: Optional[Path | str] = None,
    use_ignore: bool = True,
) -> List[Dict[str, Any]]:
    """Internal helper to scan an open git.Repo instance."""
    active_engine = engine or DetectionEngine(custom_rules_path=custom_rules_path)
    detections: List[Dict[str, Any]] = []

    ignore_filter = None
    if use_ignore:
        try:
            ignore_path = Path(repo.working_dir) / ".secretscannerignore"
            ignore_filter = IgnoreFilter(ignore_path if ignore_path.exists() else None)
        except Exception:
            ignore_filter = IgnoreFilter()

    for commit, blob_path, content in iter_git_objects(
        repo,
        max_commits=max_commits,
        ignore_filter=ignore_filter,
    ):
        if is_git_url(base_display_path):
            full_path = f"{base_display_path.rstrip('/')}/{blob_path}"
        else:
            full_path = str(Path(base_display_path) / blob_path)

        commit_date_str = ""
        try:
            commit_date_str = commit.committed_datetime.isoformat()
        except Exception:
            pass

        commit_info: Dict[str, Any] = {
            "commit_hash": commit.hexsha[:8],
            "commit_full_hash": commit.hexsha,
            "commit_author": str(commit.author),
            "commit_date": commit_date_str,
            "commit_message": commit.message.strip().splitlines()[0] if commit.message else "",
        }

        findings = active_engine.scan(content, file_path=full_path, commit_info=commit_info)
        for f in findings:
            detections.append(f.to_dict())

    return detections


def scan_repository(
    repo_path: Path | str,
    max_commits: Optional[int] = None,
    engine: Optional[DetectionEngine] = None,
    custom_rules_path: Optional[Path | str] = None,
    use_ignore: bool = True,
) -> List[Dict[str, Any]]:
    """Scan a local Git repository or remote Git URL across commits for potential secrets.

    Returns a list of finding dictionaries enriched with commit metadata.

    Note: For remote URLs, the repository is cloned fully (no shallow clone) so that
    the complete commit history is available. ``max_commits`` controls how many commits
    are *scanned*, not the clone depth.
    """
    repo_str = str(repo_path).strip()

    # Case 1: Remote repository URL
    if is_git_url(repo_str):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            try:
                # Always do a full clone so that all commits are available for scanning.
                # max_commits limits how many are processed, not clone depth.
                repo = clone_repository(repo_str, temp_path, depth=None)
            except Exception as e:
                raise RuntimeError(f"Failed to clone remote repository '{repo_str}': {e}") from e

            try:
                return _scan_repo_instance(
                    repo,
                    base_display_path=repo_str,
                    max_commits=max_commits,
                    engine=engine,
                    custom_rules_path=custom_rules_path,
                    use_ignore=use_ignore,
                )
            finally:
                repo.close()

    # Case 2: Local repository path
    path_obj = Path(repo_str).resolve()
    if not path_obj.exists():
        raise FileNotFoundError(f"Repository path does not exist: '{repo_str}'")

    try:
        repo = git.Repo(str(path_obj), search_parent_directories=True)
    except (git.exc.InvalidGitRepositoryError, git.exc.NoSuchPathError) as e:
        raise ValueError(f"'{repo_str}' is not a valid Git repository.") from e

    try:
        return _scan_repo_instance(
            repo,
            base_display_path=str(path_obj),
            max_commits=max_commits,
            engine=engine,
            custom_rules_path=custom_rules_path,
            use_ignore=use_ignore,
        )
    finally:
        repo.close()
