"""Audit orchestration — scan, map, report (CLI stays thin)."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from audit_agent.config import (
    enabled_security_aspects,
    fetch_remote_config,
    load_local_config,
    meets_severity_threshold,
    scanners_for_trivy,
)
from audit_agent.enums import Framework, Provider, Scanner
from audit_agent.github_api import GitHubClient, report_to_github
from audit_agent.map_controls import filter_by_files, map_findings
from audit_agent.render import render_pr_comment
from audit_agent.report_files import save_audit_report
from audit_agent.scan import run_prowler_audit


@dataclass
class AuditRequest:
    repo: str
    token: str
    pr: int | None = None
    sync_issues: bool = False
    dry_run: bool = False
    config_path: Path | None = None
    output_dir: Path | None = None
    report_file: Path | None = None


@dataclass
class AuditResult:
    findings: list[dict[str, Any]]
    out_dir: Path
    gate_hits: list[dict[str, Any]]
    threshold: str
    github_report: dict[str, Any] = field(default_factory=dict)
    saved: dict[str, Path] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return 1 if self.gate_hits else 0


def run_audit(request: AuditRequest) -> AuditResult:
    owner, _, name = request.repo.partition("/")
    config = load_local_config(request.config_path)
    try:
        remote = fetch_remote_config(owner, name, request.token)
        if remote is not None:
            config = remote
    except Exception as exc:  # noqa: BLE001
        print(
            f"warning: could not fetch remote config ({exc}); using defaults",
            file=sys.stderr,
        )

    providers = config.get("providers") or Provider.defaults()
    frameworks = config.get("frameworks") or Framework.defaults()
    scanners = scanners_for_trivy(config)
    github_actions = bool(
        config.get("scanners", {}).get(Scanner.GITHUB_ACTIONS.value, True)
    )
    print(
        f"Scanning {request.repo} with Prowler providers={providers} "
        f"frameworks={frameworks} scanners={scanners} …",
        file=sys.stderr,
    )

    raw_findings, out_dir = run_prowler_audit(
        request.repo,
        request.token,
        providers=providers,
        frameworks=frameworks,
        scanners=scanners,
        github_actions=github_actions,
        output_dir=request.output_dir,
    )
    mapped = map_findings(raw_findings)
    sources: dict[str, int] = {}
    for finding in mapped:
        src = finding.get("mapping_source", "unknown")
        sources[src] = sources.get(src, 0) + 1
    print(
        f"Mapped {len(mapped)} FAIL findings (from {len(raw_findings)} raw) "
        f"via {sources} → {out_dir}",
        file=sys.stderr,
    )

    if request.pr:
        client = GitHubClient(request.token)
        changed = client.list_pr_files(owner, name, request.pr)
        if config.get("fail_pr_on", {}).get("new_findings_only", True):
            before = len(mapped)
            mapped = filter_by_files(mapped, changed)
            print(
                f"PR #{request.pr}: filtered {before} → {len(mapped)} "
                "findings on changed files",
                file=sys.stderr,
            )

    comment = render_pr_comment(
        mapped,
        request.repo,
        enabled_aspects=enabled_security_aspects(config),
    )
    write_github = not request.dry_run and (request.pr or request.sync_issues)
    if request.dry_run or not write_github:
        print(comment)

    threshold = config.get("fail_pr_on", {}).get("severity", "high")
    gate_hits = [
        f
        for f in mapped
        if meets_severity_threshold(f.get("severity", ""), threshold)
    ]

    github_report: dict[str, Any] = {}
    if write_github:
        sarif_files = list(out_dir.glob("**/*.sarif"))
        github_report = report_to_github(
            token=request.token,
            repo_full_name=request.repo,
            findings=mapped,
            pr_number=request.pr,
            sync_issues=request.sync_issues,
            config=config,
            sarif_path=str(sarif_files[0]) if sarif_files else None,
        )
        print(f"Reported to GitHub: {github_report}", file=sys.stderr)

    saved = save_audit_report(
        out_dir=out_dir,
        repo=request.repo,
        comment_markdown=comment,
        findings=mapped,
        report_file=request.report_file,
        meta={
            "providers": providers,
            "frameworks": frameworks,
            "gate_hits": len(gate_hits),
            "threshold": threshold,
            "mapping_sources": sources,
            "github_report": github_report,
        },
    )
    for kind, path in saved.items():
        print(f"Saved {kind} report → {path}", file=sys.stderr)

    return AuditResult(
        findings=mapped,
        out_dir=out_dir,
        gate_hits=gate_hits,
        threshold=threshold,
        github_report=github_report,
        saved=saved,
    )
