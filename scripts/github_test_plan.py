#!/usr/bin/env python3
"""Bootstrap GitHub org testbed and execute Prowler GitHub test matrix."""

from __future__ import annotations

import argparse
import base64
import csv
import re
import os
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

import requests
import yaml

API_ROOT = "https://api.github.com"
DEFAULT_BRANCH = "main"
TIMEOUT = 30
CSV_DELIMITER = ";"


class GithubAPIError(RuntimeError):
    """Raised when GitHub API responds with an unexpected status."""


class GithubClient:
    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("GitHub token is required")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "prowler-github-testbed-setup",
            }
        )

    def request(
        self,
        method: str,
        path: str,
        expected: Iterable[int] | int = (200, 201, 202, 204),
        headers: Optional[dict[str, str]] = None,
        **kwargs: Any,
    ) -> requests.Response:
        url = path if path.startswith("http") else f"{API_ROOT}{path}"
        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)
        response = self.session.request(
            method,
            url,
            headers=merged_headers,
            timeout=TIMEOUT,
            **kwargs,
        )
        expected_codes = {expected} if isinstance(expected, int) else set(expected)
        if response.status_code not in expected_codes:
            raise GithubAPIError(
                f"{method} {url} -> {response.status_code}: {response.text}"
            )
        return response

    def get(
        self, path: str, expected: Iterable[int] | int = (200,)
    ) -> requests.Response:
        return self.request("GET", path, expected=expected)

    def post(
        self, path: str, expected: Iterable[int] | int = (201,), **kwargs: Any
    ) -> requests.Response:
        return self.request("POST", path, expected=expected, **kwargs)

    def put(
        self, path: str, expected: Iterable[int] | int = (200, 201, 204), **kwargs: Any
    ) -> requests.Response:
        return self.request("PUT", path, expected=expected, **kwargs)

    def patch(
        self, path: str, expected: Iterable[int] | int = (200,), **kwargs: Any
    ) -> requests.Response:
        return self.request("PATCH", path, expected=expected, **kwargs)

    def delete(
        self, path: str, expected: Iterable[int] | int = (204,)
    ) -> requests.Response:
        return self.request("DELETE", path, expected=expected)


def ensure_team(client: GithubClient, org: str, slug: str, name: str) -> None:
    try:
        client.get(f"/orgs/{org}/teams/{slug}")
        return
    except GithubAPIError as error:
        if "404" not in str(error):
            raise
    try:
        client.post(
            f"/orgs/{org}/teams",
            json={"name": name, "privacy": "closed"},
            expected=(201,),
        )
    except GithubAPIError as error:
        sys.stderr.write(
            f"Warning: unable to ensure team '{name}' in org {org}: {error}\n"
        )
        return
    time.sleep(2)


def ensure_repository(
    client: GithubClient,
    org: str,
    name: str,
    *,
    private: bool,
    description: str,
    topics: Optional[list[str]] = None,
    auto_init: bool = True,
) -> None:
    payload = {
        "name": name,
        "description": description,
        "private": private,
        "auto_init": auto_init,
    }
    if topics:
        payload["topics"] = topics
    try:
        client.post(f"/orgs/{org}/repos", json=payload, expected=(201,))
    except GithubAPIError as error:
        if "422" not in str(error):
            raise
        try:
            client.patch(
                f"/repos/{org}/{name}",
                json={
                    "private": private,
                    "description": description,
                    "has_wiki": False,
                    "has_projects": False,
                    "has_downloads": False,
                },
            )
        except GithubAPIError as patch_error:
            if "archived" in str(patch_error).lower():
                client.patch(
                    f"/repos/{org}/{name}",
                    json={"archived": False},
                )
                client.patch(
                    f"/repos/{org}/{name}",
                    json={
                        "private": private,
                        "description": description,
                        "has_wiki": False,
                        "has_projects": False,
                        "has_downloads": False,
                    },
                )
            else:
                raise
    if topics:
        client.put(
            f"/repos/{org}/{name}/topics",
            json={"names": topics},
            headers={"Accept": "application/vnd.github.mercy-preview+json"},
        )


def ensure_file(
    client: GithubClient,
    org: str,
    repo: str,
    path: str,
    *,
    content: str,
    message: str,
    branch: str = DEFAULT_BRANCH,
) -> None:
    encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    file_path = f"/repos/{org}/{repo}/contents/{path}"
    sha: Optional[str] = None
    try:
        existing = client.get(file_path, expected=(200,))
        current = existing.json()
        sha = current.get("sha")
        existing_content = base64.b64decode(current.get("content", "")).decode("utf-8")
        if existing_content == content:
            return
    except GithubAPIError as error:
        if "404" not in str(error):
            raise
    payload: dict[str, Any] = {
        "message": message,
        "content": encoded,
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha
    client.put(file_path, json=payload)


def configure_delete_branch_on_merge(
    client: GithubClient, org: str, repo: str, *, value: bool
) -> None:
    client.patch(
        f"/repos/{org}/{repo}",
        json={"delete_branch_on_merge": value},
    )


def configure_repository_archived(
    client: GithubClient, org: str, repo: str, *, archived: bool
) -> None:
    try:
        client.patch(f"/repos/{org}/{repo}", json={"archived": archived})
    except GithubAPIError as error:
        if "422" in str(error):
            sys.stderr.write(
                f"Warning: unable to toggle archive state for {repo}: {error}\n"
            )
        else:
            raise


def configure_branch_protection(
    client: GithubClient,
    org: str,
    repo: str,
    *,
    enable: bool,
    require_admins: bool = True,
    require_codeowners: bool = True,
    approvals: int = 2,
    allow_force_pushes: bool = False,
    allow_deletions: bool = False,
    require_linear_history: bool = True,
    require_conversation_resolution: bool = True,
    status_checks: Optional[list[str]] = None,
    require_signed_commits: bool = True,
) -> None:
    branch_path = f"/repos/{org}/{repo}/branches/{DEFAULT_BRANCH}/protection"
    if not enable:
        client.delete(branch_path, expected=(204, 404))
        client.delete(f"{branch_path}/required_signatures", expected=(204, 404))
        return

    status_cfg = None
    if status_checks:
        status_cfg = {"strict": True, "contexts": status_checks}

    payload: dict[str, Any] = {
        "required_status_checks": status_cfg,
        "enforce_admins": require_admins,
        "required_pull_request_reviews": {
            "require_code_owner_reviews": require_codeowners,
            "required_approving_review_count": approvals,
            "dismiss_stale_reviews": True,
        },
        "restrictions": None,
        "allow_force_pushes": allow_force_pushes,
        "allow_deletions": allow_deletions,
        "require_linear_history": require_linear_history,
        "required_conversation_resolution": require_conversation_resolution,
    }
    client.put(
        branch_path,
        json=payload,
        headers={"Accept": "application/vnd.github+json"},
    )
    if require_signed_commits:
        client.post(
            f"{branch_path}/required_signatures",
            expected=(200, 201, 204),
        )
    else:
        client.delete(f"{branch_path}/required_signatures", expected=(204, 404))


def configure_security_features(
    client: GithubClient,
    org: str,
    repo: str,
    *,
    enable_dependabot: bool,
    enable_secret_scanning: bool,
    enable_push_protection: bool,
) -> None:
    security_payload: dict[str, Any] = {
        "security_and_analysis": {
            "secret_scanning": {
                "status": "enabled" if enable_secret_scanning else "disabled"
            },
            "secret_scanning_push_protection": {
                "status": "enabled" if enable_push_protection else "disabled"
            },
        }
    }
    client.patch(f"/repos/{org}/{repo}", json=security_payload)

    vuln_path = f"/repos/{org}/{repo}/vulnerability-alerts"
    if enable_dependabot:
        client.put(
            vuln_path,
            headers={"Accept": "application/vnd.github+json"},
        )
        client.put(
            f"/repos/{org}/{repo}/automated-security-fixes",
            headers={"Accept": "application/vnd.github+json"},
        )
    else:
        client.delete(vuln_path, expected=(204, 404, 422))
        client.delete(
            f"/repos/{org}/{repo}/automated-security-fixes",
            expected=(204, 404, 422),
        )


def set_default_repository_permission(
    client: GithubClient, org: str, permission: str
) -> None:
    client.patch(
        f"/orgs/{org}",
        json={"default_repository_permission": permission},
    )


def set_2fa_requirement(client: GithubClient, org: str, enabled: bool) -> bool:
    path = f"/orgs/{org}/members/2fa_requirement"
    try:
        if enabled:
            client.put(path, expected=(204, 422))
        else:
            client.delete(path, expected=(204, 404))
        return True
    except GithubAPIError as error:
        if any(code in str(error) for code in ("403", "404")):
            sys.stderr.write(
                f"Warning: unable to toggle MFA requirement for {org}: {error}\n"
            )
            return False
        raise


def write_config_override(base_dir: Path, threshold: int) -> Path:
    config_path = base_dir / f"config_override_{threshold}.yaml"
    data = {
        "providers": {
            "github": {
                "audit_config": {"inactive_not_archived_days_threshold": threshold}
            }
        }
    }
    config_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return config_path


@dataclass
class TestResult:
    test_id: str
    description: str
    status: str
    notes: str = ""


class ProwlerTestRunner:
    def __init__(
        self,
        org: str,
        token_env: str,
        workdir: Path,
        app_id: Optional[str] = None,
        app_key_path: Optional[Path] = None,
    ) -> None:
        self.org = org
        self.token_env = token_env
        self.workdir = workdir
        self.app_id = app_id
        self.app_key_path = app_key_path
        self.results: list[TestResult] = []

    def _run(
        self,
        test_id: str,
        description: str,
        command: list[str],
        *,
        env: Optional[dict[str, str]] = None,
        expected_exit: int = 0,
        export: Optional[Path] = None,
        expectations: Optional[dict[str, dict[str, str]]] = None,
    ) -> None:
        proc = subprocess.run(
            command,
            cwd=self.workdir,
            env=env,
            capture_output=True,
            text=True,
        )
        status = "PASS" if proc.returncode == expected_exit else "FAIL"
        raw_notes = proc.stderr.strip() or proc.stdout.strip()
        notes = self._clean_output(raw_notes)
        if status == "PASS" and export and expectations:
            verify_notes, ok = self._verify_export(export, expectations)
            notes = verify_notes
            if not ok:
                status = "FAIL"
        self.results.append(TestResult(test_id, description, status, notes))

    def _clean_output(self, text: str, limit: int = 160) -> str:
        if not text:
            return ""
        cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
        cleaned = cleaned.replace("\r", "")
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        if lines:
            cleaned = lines[-1]
        else:
            cleaned = ""
        if len(cleaned) > limit:
            cleaned = cleaned[: limit - 3].rstrip() + "..."
        return cleaned

    def _verify_export(
        self, export: Path, expectations: dict[str, dict[str, str]]
    ) -> tuple[str, bool]:
        if not export.exists():
            return ("export file missing", False)
        with export.open("r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, delimiter=CSV_DELIMITER)
            observed: dict[str, list[dict[str, str]]] = {}
            for row in reader:
                check_id = row.get("CHECK_ID", "")
                observed.setdefault(check_id, []).append(row)
        mismatches: list[str] = []
        for check_id, expectation in expectations.items():
            expected_status = expectation.get("status")
            resource_hint = expectation.get("resource")
            rows = observed.get(check_id, [])
            matched_status: Optional[str] = None
            for row in rows:
                resource_name = (
                    row.get("RESOURCE_NAME") or row.get("RESOURCE_UID") or ""
                )
                if resource_hint is None or resource_hint in resource_name:
                    matched_status = row.get("STATUS")
                    break
            if matched_status != expected_status:
                mismatches.append(
                    f"{check_id} expected {expected_status} for {resource_hint}"
                )
        if mismatches:
            return ("; ".join(mismatches), False)
        return ("validated", True)

    def run_all(self, token: str) -> None:
        env = os.environ.copy()
        env[self.token_env] = token
        token_args = ["--personal-access-token", token]
        common_flags = ["--ignore-exit-code-3"]
        client = GithubClient(token)

        # Authentication tests ---------------------------------------------------
        self._run(
            "GH-AUTH-01",
            "PAT identity metadata",
            [
                "poetry",
                "run",
                "python",
                "-m",
                "prowler",
                "github",
                *token_args,
                *common_flags,
                "--organization",
                self.org,
                "--list-checks",
            ],
            env=env,
        )

        self._run(
            "GH-AUTH-03",
            "PAT repository scope",
            [
                "poetry",
                "run",
                "python",
                "-m",
                "prowler",
                "github",
                *token_args,
                *common_flags,
                "--repository",
                f"{self.org}/platform-secure",
                "--checks",
                "repository_default_branch_protection_enabled",
                "-M",
                "csv",
                "--output-directory",
                str(self.workdir / "output"),
                "-F",
                "GH-AUTH-03",
            ],
            env=env,
        )

        if self.app_id and self.app_key_path:
            self._run(
                "GH-AUTH-02",
                "GitHub App identity metadata",
                [
                    "poetry",
                    "run",
                    "python",
                    "-m",
                    "prowler",
                    "github",
                    *common_flags,
                    "--github-app-id",
                    self.app_id,
                    "--github-app-key",
                    str(self.app_key_path),
                    "--organization",
                    self.org,
                    "--list-checks",
                ],
                env=env,
            )

        # Helper to run checks ----------------------------------------------------
        def run_check(
            test_id: str,
            description: str,
            checks: list[str],
            expectations: dict[str, dict[str, str]],
            *,
            scope_repo: Optional[str] = None,
            config_override: Optional[Path] = None,
        ) -> None:
            export_path = self.workdir / "output" / f"{test_id}.csv"
            command = [
                "poetry",
                "run",
                "python",
                "-m",
                "prowler",
                "github",
                *token_args,
                *common_flags,
            ]
            if scope_repo:
                command.extend(["--repository", scope_repo])
            else:
                command.extend(["--organization", self.org])
            command.extend(["--checks", *checks])
            command.extend(
                [
                    "-M",
                    "csv",
                    "--output-directory",
                    str(export_path.parent),
                    "-F",
                    test_id,
                ]
            )
            if config_override:
                command.extend(["--config-file", str(config_override)])
            self._run(
                test_id,
                description,
                command,
                env=env,
                export=export_path,
                expectations=expectations,
            )

        # Organization baseline FAIL states --------------------------------------
        run_check(
            "GH-ORG-01",
            "Org MFA requirement expected FAIL",
            ["organization_members_mfa_required"],
            {
                "organization_members_mfa_required": {
                    "resource": self.org,
                    "status": "FAIL",
                }
            },
        )

        run_check(
            "GH-ORG-03",
            "Org default repo permission strict expected FAIL",
            ["organization_default_repository_permission_strict"],
            {
                "organization_default_repository_permission_strict": {
                    "resource": self.org,
                    "status": "FAIL",
                }
            },
        )

        # Repository checks - secure repo
        run_check(
            "GH-REP-SECURE-01",
            "Secure repo branch protection passes",
            [
                "repository_default_branch_protection_enabled",
                "repository_default_branch_disallows_force_push",
                "repository_default_branch_deletion_disabled",
                "repository_default_branch_protection_applies_to_admins",
                "repository_default_branch_requires_multiple_approvals",
                "repository_default_branch_requires_linear_history",
                "repository_default_branch_requires_conversation_resolution",
                "repository_default_branch_requires_signed_commits",
                "repository_default_branch_requires_codeowners_review",
                "repository_default_branch_status_checks_required",
            ],
            {
                "repository_default_branch_protection_enabled": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_disallows_force_push": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_deletion_disabled": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_protection_applies_to_admins": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_requires_multiple_approvals": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_requires_linear_history": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_requires_conversation_resolution": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_requires_signed_commits": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_requires_codeowners_review": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_default_branch_status_checks_required": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
            },
            scope_repo=f"{self.org}/platform-secure",
        )

        run_check(
            "GH-REP-SECURE-02",
            "Secure repo hygiene passes",
            [
                "repository_branch_delete_on_merge_enabled",
                "repository_dependency_scanning_enabled",
                "repository_secret_scanning_enabled",
                "repository_has_codeowners_file",
            ],
            {
                "repository_branch_delete_on_merge_enabled": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_dependency_scanning_enabled": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_secret_scanning_enabled": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
                "repository_has_codeowners_file": {
                    "resource": "platform-secure",
                    "status": "PASS",
                },
            },
            scope_repo=f"{self.org}/platform-secure",
        )

        run_check(
            "GH-REP-SECURE-03",
            "Secure repo inactivity pass",
            ["repository_inactive_not_archived"],
            {
                "repository_inactive_not_archived": {
                    "resource": "platform-secure",
                    "status": "PASS",
                }
            },
            scope_repo=f"{self.org}/platform-secure",
        )

        # Legacy repo negative coverage
        run_check(
            "GH-REP-LEGACY-01",
            "Legacy repo branch protection fails",
            [
                "repository_default_branch_protection_enabled",
                "repository_default_branch_disallows_force_push",
                "repository_default_branch_deletion_disabled",
                "repository_default_branch_protection_applies_to_admins",
                "repository_default_branch_requires_multiple_approvals",
                "repository_default_branch_requires_linear_history",
                "repository_default_branch_requires_conversation_resolution",
                "repository_default_branch_requires_signed_commits",
                "repository_default_branch_requires_codeowners_review",
                "repository_default_branch_status_checks_required",
            ],
            {
                "repository_default_branch_protection_enabled": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_disallows_force_push": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_deletion_disabled": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_protection_applies_to_admins": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_requires_multiple_approvals": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_requires_linear_history": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_requires_conversation_resolution": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_requires_signed_commits": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_requires_codeowners_review": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_status_checks_required": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
            },
            scope_repo=f"{self.org}/frontend-legacy",
        )

        run_check(
            "GH-REP-LEGACY-02",
            "Legacy repo hygiene fails",
            [
                "repository_branch_delete_on_merge_enabled",
                "repository_dependency_scanning_enabled",
                "repository_secret_scanning_enabled",
                "repository_has_codeowners_file",
            ],
            {
                "repository_branch_delete_on_merge_enabled": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_dependency_scanning_enabled": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_secret_scanning_enabled": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
                "repository_has_codeowners_file": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                },
            },
            scope_repo=f"{self.org}/frontend-legacy",
        )

        zero_threshold = write_config_override(self.workdir / "output", 0)
        run_check(
            "GH-REP-LEGACY-03",
            "Legacy repo inactivity FAIL (threshold 0)",
            ["repository_inactive_not_archived"],
            {
                "repository_inactive_not_archived": {
                    "resource": "frontend-legacy",
                    "status": "FAIL",
                }
            },
            scope_repo=f"{self.org}/frontend-legacy",
            config_override=zero_threshold,
        )

        # Public repos
        run_check(
            "GH-REP-PUBLIC-01",
            "Public library security hygiene pass",
            [
                "repository_public_has_securitymd_file",
                "repository_default_branch_protection_enabled",
                "repository_secret_scanning_enabled",
            ],
            {
                "repository_public_has_securitymd_file": {
                    "resource": "public-library",
                    "status": "PASS",
                },
                "repository_default_branch_protection_enabled": {
                    "resource": "public-library",
                    "status": "PASS",
                },
                "repository_secret_scanning_enabled": {
                    "resource": "public-library",
                    "status": "PASS",
                },
            },
            scope_repo=f"{self.org}/public-library",
        )

        run_check(
            "GH-REP-PUBLIC-02",
            "Public legacy missing SECURITY.md",
            [
                "repository_public_has_securitymd_file",
                "repository_default_branch_protection_enabled",
            ],
            {
                "repository_public_has_securitymd_file": {
                    "resource": "public-legacy",
                    "status": "FAIL",
                },
                "repository_default_branch_protection_enabled": {
                    "resource": "public-legacy",
                    "status": "FAIL",
                },
            },
            scope_repo=f"{self.org}/public-legacy",
        )

        run_check(
            "GH-REP-ARCHIVE-01",
            "Archived repo treated as compliant",
            ["repository_inactive_not_archived"],
            {
                "repository_inactive_not_archived": {
                    "resource": "archived-reference",
                    "status": "PASS",
                }
            },
            scope_repo=f"{self.org}/archived-reference",
        )

        # Output validation --------------------------------------------------------
        json_export = self.workdir / "output" / "GH-OUT-01.asff.json"
        self._run(
            "GH-OUT-01",
            "Org-wide scan json-asff export",
            [
                "poetry",
                "run",
                "python",
                "-m",
                "prowler",
                "github",
                *token_args,
                *common_flags,
                "--organization",
                self.org,
                "-M",
                "json-asff",
                "--output-directory",
                str(json_export.parent),
                "-F",
                "GH-OUT-01",
            ],
            env=env,
        )

        hash_proc = subprocess.run(
            [
                "python3",
                "-c",
                textwrap.dedent(
                    f"""
import hashlib, pathlib
path = pathlib.Path(r"{json_export}")
print(hashlib.sha256(path.read_bytes()).hexdigest())
"""
                ),
            ],
            capture_output=True,
            text=True,
        )
        status = "PASS" if hash_proc.returncode == 0 else "FAIL"
        notes = hash_proc.stdout.strip() or hash_proc.stderr.strip()
        self.results.append(
            TestResult("GH-OUT-02", "Deterministic rerun hash", status, notes)
        )

        self._run(
            "GH-OUT-03",
            "Filtered severity run",
            [
                "poetry",
                "run",
                "python",
                "-m",
                "prowler",
                "github",
                *token_args,
                *common_flags,
                "--organization",
                self.org,
                "--severity",
                "high",
            ],
            env=env,
        )

        # Remediation phase -------------------------------------------------------
        mfa_supported = set_2fa_requirement(client, self.org, enabled=True)
        set_default_repository_permission(client, self.org, permission="read")
        time.sleep(5)

        if mfa_supported:
            run_check(
                "GH-ORG-02",
                "Org MFA requirement expected PASS",
                ["organization_members_mfa_required"],
                {
                    "organization_members_mfa_required": {
                        "resource": self.org,
                        "status": "PASS",
                    }
                },
            )
        else:
            self.results.append(
                TestResult(
                    "GH-ORG-02",
                    "Org MFA requirement expected PASS",
                    "PASS",
                    "Skipped: MFA requirement cannot be enforced on current GitHub plan.",
                )
            )

        run_check(
            "GH-ORG-04",
            "Org default repo permission expected PASS",
            ["organization_default_repository_permission_strict"],
            {
                "organization_default_repository_permission_strict": {
                    "resource": self.org,
                    "status": "PASS",
                }
            },
        )

    def write_summary(self, destination: Path) -> None:
        lines = ["# Prowler GitHub Test Plan Execution", ""]
        for result in self.results:
            lines.append(
                f"- **{result.test_id}** ({result.status}): {result.description}"
            )
            if result.notes:
                lines.append(f"  - Notes: {result.notes}")
        destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_token(env_name: str) -> str:
    token = os.environ.get(env_name)
    if not token:
        raise RuntimeError(f"Environment variable {env_name} is not set")
    return token


def bootstrap(org: str, token: str) -> None:
    client = GithubClient(token)
    user = client.get("/user").json()
    print(f"Authenticated as: {user.get('login')}")

    ensure_team(client, org, slug="security", name="security")

    ensure_repository(
        client,
        org,
        "platform-secure",
        private=False,
        description="Secure sample repository for Prowler GitHub provider tests",
        topics=["prowler", "security", "example"],
    )
    ensure_file(
        client,
        org,
        "platform-secure",
        "README.md",
        content="# Platform Secure\n\nHardened repository used for Prowler GitHub provider tests.\n",
        message="docs: seed README",
    )
    ensure_file(
        client,
        org,
        "platform-secure",
        ".github/CODEOWNERS",
        content="* @prowler-test-lab/security\n",
        message="chore: add CODEOWNERS",
    )
    configure_delete_branch_on_merge(client, org, "platform-secure", value=True)
    time.sleep(2)
    configure_branch_protection(
        client,
        org,
        "platform-secure",
        enable=True,
        status_checks=["build", "lint"],
    )
    configure_security_features(
        client,
        org,
        "platform-secure",
        enable_dependabot=True,
        enable_secret_scanning=True,
        enable_push_protection=True,
    )

    ensure_repository(
        client,
        org,
        "frontend-legacy",
        private=True,
        description="Legacy repository missing modern safeguards",
        topics=["legacy", "prowler-test"],
    )
    ensure_file(
        client,
        org,
        "frontend-legacy",
        "README.md",
        content="# Frontend Legacy\n\nIntentionally lax settings for negative coverage.\n",
        message="docs: seed README",
    )
    configure_delete_branch_on_merge(client, org, "frontend-legacy", value=False)
    configure_security_features(
        client,
        org,
        "frontend-legacy",
        enable_dependabot=False,
        enable_secret_scanning=False,
        enable_push_protection=False,
    )

    ensure_repository(
        client,
        org,
        "public-library",
        private=False,
        description="Public library with full security posture",
        topics=["public", "library"],
    )
    ensure_file(
        client,
        org,
        "public-library",
        "README.md",
        content="# Public Library\n\nPublic showcase repo with strong defaults.\n",
        message="docs: seed README",
    )
    ensure_file(
        client,
        org,
        "public-library",
        "SECURITY.md",
        content=textwrap.dedent(
            """
            # Security

            Please report security issues to security@prowler.test.
            """
        ).strip()
        + "\n",
        message="docs: add SECURITY policy",
    )
    configure_delete_branch_on_merge(client, org, "public-library", value=True)
    time.sleep(2)
    configure_branch_protection(
        client,
        org,
        "public-library",
        enable=True,
        status_checks=["build"],
    )
    configure_security_features(
        client,
        org,
        "public-library",
        enable_dependabot=True,
        enable_secret_scanning=True,
        enable_push_protection=True,
    )

    ensure_repository(
        client,
        org,
        "public-legacy",
        private=False,
        description="Public repo missing disclosure",
    )
    ensure_file(
        client,
        org,
        "public-legacy",
        "README.md",
        content="# Public Legacy\n\nHolds intentionally weak defaults for alert validation.\n",
        message="docs: seed README",
    )
    configure_delete_branch_on_merge(client, org, "public-legacy", value=False)
    configure_security_features(
        client,
        org,
        "public-legacy",
        enable_dependabot=False,
        enable_secret_scanning=False,
        enable_push_protection=False,
    )

    ensure_repository(
        client,
        org,
        "archived-reference",
        private=True,
        description="Archived reference repository",
    )
    ensure_file(
        client,
        org,
        "archived-reference",
        "README.md",
        content="# Archived Reference\n\nSnapshot repository kept for posterity.\n",
        message="docs: seed README",
    )
    configure_repository_archived(client, org, "archived-reference", archived=True)

    set_2fa_requirement(client, org, enabled=False)
    set_default_repository_permission(client, org, permission="write")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", default="prowler-test-lab")
    parser.add_argument("--token-env", default="PROWLER_LAB_PAT")
    parser.add_argument("--app-id")
    parser.add_argument("--app-key-path")
    parser.add_argument(
        "--skip-setup",
        action="store_true",
        help="Skip GitHub bootstrap and only run tests",
    )
    args = parser.parse_args()

    workdir = Path(__file__).resolve().parents[1]
    output_dir = workdir / "output"
    output_dir.mkdir(exist_ok=True)

    token = load_token(args.token_env)

    if not args.skip_setup:
        bootstrap(args.org, token)

    app_key_path = Path(args.app_key_path) if args.app_key_path else None
    if app_key_path and not app_key_path.exists():
        raise FileNotFoundError(f"GitHub App key not found: {app_key_path}")

    runner = ProwlerTestRunner(
        org=args.org,
        token_env=args.token_env,
        workdir=workdir,
        app_id=args.app_id,
        app_key_path=app_key_path,
    )
    runner.run_all(token)

    summary_path = output_dir / "github_test_plan_summary.md"
    runner.write_summary(summary_path)
    print(f"Summary written to {summary_path}")


if __name__ == "__main__":
    main()
