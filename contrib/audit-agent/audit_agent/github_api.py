"""GitHub API helpers for zero-touch reporting into the target repository."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from audit_agent.render import COMMENT_MARKER, group_findings_by_control, render_issue_body, render_pr_comment


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl._create_unverified_context()


class GitHubClient:
    def __init__(self, token: str, api_base: str = "https://api.github.com"):
        self.token = token
        self.api_base = api_base.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        accept: str = "application/vnd.github+json",
    ) -> Any:
        url = f"{self.api_base}{path}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "prowler-audit-agent",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60, context=_ssl_context()) as resp:
                raw = resp.read()
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {method} {path} failed: {exc.code} {detail}") from exc

    def list_pr_files(self, owner: str, repo: str, pr_number: int) -> set[str]:
        files: set[str] = set()
        page = 1
        while True:
            data = self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pr_number}/files?per_page=100&page={page}",
            )
            if not data:
                break
            for item in data:
                if item.get("filename"):
                    files.add(item["filename"])
            if len(data) < 100:
                break
            page += 1
        return files

    def upsert_pr_comment(self, owner: str, repo: str, pr_number: int, body: str) -> None:
        comments = self._request(
            "GET",
            f"/repos/{owner}/{repo}/issues/{pr_number}/comments?per_page=100",
        ) or []
        existing = next(
            (c for c in comments if COMMENT_MARKER in (c.get("body") or "")),
            None,
        )
        if existing:
            self._request(
                "PATCH",
                f"/repos/{owner}/{repo}/issues/comments/{existing['id']}",
                body={"body": body},
            )
        else:
            self._request(
                "POST",
                f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
                body={"body": body},
            )

    def create_check_run(
        self,
        owner: str,
        repo: str,
        *,
        head_sha: str,
        conclusion: str,
        summary: str,
        title: str = "Prowler Compliance Audit",
    ) -> None:
        self._request(
            "POST",
            f"/repos/{owner}/{repo}/check-runs",
            body={
                "name": title,
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": title,
                    "summary": summary,
                },
            },
            accept="application/vnd.github+json",
        )

    def get_pr(self, owner: str, repo: str, pr_number: int) -> dict[str, Any]:
        return self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}")

    def sync_control_issues(
        self,
        owner: str,
        repo: str,
        findings: list[dict[str, Any]],
        labels: list[str],
    ) -> None:
        groups = group_findings_by_control(findings)
        open_issues = self._list_agent_issues(owner, repo)

        active_keys = set(groups.keys())
        for key, group in groups.items():
            title = self._issue_title(group)
            body = render_issue_body(group)
            existing = open_issues.get(key)
            if existing:
                self._request(
                    "PATCH",
                    f"/repos/{owner}/{repo}/issues/{existing['number']}",
                    body={"body": body, "state": "open"},
                )
            else:
                self._request(
                    "POST",
                    f"/repos/{owner}/{repo}/issues",
                    body={
                        "title": title[:250],
                        "body": body,
                        "labels": labels,
                    },
                )

        for key, issue in open_issues.items():
            if key not in active_keys:
                self._request(
                    "PATCH",
                    f"/repos/{owner}/{repo}/issues/{issue['number']}",
                    body={"state": "closed"},
                )

    def upload_sarif(
        self,
        owner: str,
        repo: str,
        sarif_path: str,
        *,
        ref: str,
        commit_sha: str,
    ) -> None:
        with open(sarif_path, "rb") as fh:
            encoded = base64.b64encode(fh.read()).decode("ascii")
        self._request(
            "POST",
            f"/repos/{owner}/{repo}/code-scanning/sarifs",
            body={
                "commit_sha": commit_sha,
                "ref": ref if ref.startswith("refs/") else f"refs/heads/{ref}",
                "sarif": encoded,
                "tool_name": "Prowler Audit Agent",
            },
        )

    def default_branch(self, owner: str, repo: str) -> str:
        data = self._request("GET", f"/repos/{owner}/{repo}")
        return data.get("default_branch") or "main"

    def head_sha_for_ref(self, owner: str, repo: str, ref: str) -> str:
        encoded = urllib.parse.quote(ref, safe="")
        data = self._request("GET", f"/repos/{owner}/{repo}/commits/{encoded}")
        return data["sha"]

    def _list_agent_issues(self, owner: str, repo: str) -> dict[str, dict[str, Any]]:
        issues = (
            self._request(
                "GET",
                f"/repos/{owner}/{repo}/issues?state=open&per_page=100&labels=prowler-audit",
            )
            or []
        )
        result: dict[str, dict[str, Any]] = {}
        for issue in issues:
            if "pull_request" in issue:
                continue
            body = issue.get("body") or ""
            if "prowler-audit-agent-issue" not in body:
                continue
            # Recover key from title tags
            title = issue.get("title") or ""
            key = title.split("]")[0].replace("[", "") if title.startswith("[") else title
            # Prefer control key from body frameworks line is fragile; use title
            result[_key_from_issue_title(title)] = issue
        return result

    def _issue_title(self, group: dict[str, Any]) -> str:
        soc2 = group.get("soc2") or []
        iso = group.get("iso27001") or []
        tags = " ".join([f"[SOC2/{c}]" for c in soc2] + [f"[ISO27001/{c}]" for c in iso])
        finding = (group.get("findings") or [{}])[0]
        return f"{tags} {finding.get('title', 'Compliance gap')}".strip()


def _key_from_issue_title(title: str) -> str:
    controls: list[str] = []
    parts = title.split("]")
    for part in parts[:-1]:
        token = part.strip()
        if token.startswith("["):
            token = token[1:]
        if "/" in token:
            controls.append(token.split("/", 1)[1])
    return "+".join(sorted(controls)) or "unmapped"


def report_to_github(
    *,
    token: str,
    repo_full_name: str,
    findings: list[dict[str, Any]],
    pr_number: int | None,
    sync_issues: bool,
    config: dict[str, Any],
    sarif_path: str | None = None,
    ref: str | None = None,
) -> dict[str, Any]:
    owner, repo = repo_full_name.split("/", 1)
    client = GitHubClient(token)
    reporting = config.get("reporting", {})
    result: dict[str, Any] = {"comments": False, "issues": False, "check": False}

    if pr_number and reporting.get("pr_comment", True):
        body = render_pr_comment(findings, repo_full_name)
        client.upsert_pr_comment(owner, repo, pr_number, body)
        result["comments"] = True

        pr = client.get_pr(owner, repo, pr_number)
        head_sha = pr["head"]["sha"]
        fail_cfg = config.get("fail_pr_on", {})
        threshold = fail_cfg.get("severity", "high")
        from audit_agent.config import meets_severity_threshold

        failing = [
            f
            for f in findings
            if meets_severity_threshold(f.get("severity", ""), threshold)
        ]
        conclusion = "failure" if failing else "success"
        client.create_check_run(
            owner,
            repo,
            head_sha=head_sha,
            conclusion=conclusion,
            summary=f"{len(findings)} mapped FAIL finding(s); "
            f"{len(failing)} at or above `{threshold}`.",
        )
        result["check"] = True
        result["conclusion"] = conclusion

    if sync_issues and reporting.get("issues", True):
        labels = reporting.get("issue_labels") or ["compliance", "prowler-audit"]
        client.sync_control_issues(owner, repo, findings, labels)
        result["issues"] = True

    if sarif_path and reporting.get("sarif", True):
        branch = ref or client.default_branch(owner, repo)
        sha = client.head_sha_for_ref(owner, repo, branch)
        try:
            client.upload_sarif(
                owner, repo, sarif_path, ref=branch, commit_sha=sha
            )
            result["sarif"] = True
        except RuntimeError as exc:
            # Code Scanning may be disabled on the target repo
            result["sarif"] = False
            result["sarif_error"] = str(exc)

    return result
