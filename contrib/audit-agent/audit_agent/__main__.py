"""CLI entrypoint for the zero-touch Prowler Audit Agent."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from audit_agent.config import (
    enabled_security_aspects,
    fetch_remote_config,
    load_local_config,
    meets_severity_threshold,
    scanners_for_trivy,
)
from audit_agent.github_api import GitHubClient, report_to_github
from audit_agent.map_controls import filter_by_files, map_findings
from audit_agent.render import render_pr_comment
from audit_agent.report_files import save_audit_report
from audit_agent.scan import run_prowler_audit


def _resolve_token(explicit: str | None) -> str | None:
    """Resolve a GitHub token from CLI, env, or `gh auth token`."""
    if explicit:
        return explicit
    for key in ("AUDIT_AGENT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(key)
        if value:
            return value
    # Fall back to GitHub CLI (same auth as `gh repo clone`)
    try:
        gh = shutil.which("gh")
        if not gh:
            return None
        result = subprocess.run(
            [gh, "auth", "token"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        token = (result.stdout or "").strip()
        return token or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zero-touch SOC 2 / ISO 27001 audit for any GitHub repository"
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Target repository as owner/name (nothing is committed there)",
    )
    parser.add_argument(
        "--pr",
        type=int,
        default=None,
        help="Optional PR number — filter to changed files and post a sticky comment",
    )
    parser.add_argument(
        "--sync-issues",
        action="store_true",
        help="Open/close control-gap issues on the target repo via API",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="GitHub token (default: AUDIT_AGENT_TOKEN / GH_TOKEN / GITHUB_TOKEN / `gh auth token`)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional local config override (JSON). Target-repo config is fetched if present.",
    )
    parser.add_argument(
        "--image-tag",
        default=os.environ.get("PROWLER_IMAGE_TAG", "stable"),
        help="prowlercloud/prowler Docker tag",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for scan artifacts and audit-report.md / audit-findings.json",
    )
    parser.add_argument(
        "--report-file",
        type=Path,
        default=None,
        help="Write the markdown audit report to this path (also saved under --output-dir)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and print the PR comment; do not call write APIs",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print a JSON summary to stdout",
    )

    args = parser.parse_args(argv)
    args.token = _resolve_token(args.token)
    if not args.token:
        print(
            "error: provide --token, set AUDIT_AGENT_TOKEN / GH_TOKEN, "
            "or run `gh auth login` so `gh auth token` works",
            file=sys.stderr,
        )
        return 2

    owner, _, name = args.repo.partition("/")
    if not owner or not name:
        print("error: --repo must be owner/name", file=sys.stderr)
        return 2

    config = load_local_config(args.config)
    try:
        remote = fetch_remote_config(owner, name, args.token)
        # Remote overrides local defaults when present
        config = remote
    except Exception as exc:  # noqa: BLE001 — fall back to defaults/local
        print(f"warning: could not fetch remote config ({exc}); using defaults", file=sys.stderr)

    providers = config.get("providers") or ["iac", "github"]
    frameworks = config.get("frameworks") or ["soc2", "iso27001_2022"]
    scanners = scanners_for_trivy(config)
    github_actions = bool(config.get("scanners", {}).get("github_actions", True))
    print(
        f"Scanning {args.repo} with Prowler providers={providers} "
        f"frameworks={frameworks} scanners={scanners} …",
        file=sys.stderr,
    )

    try:
        raw_findings, out_dir = run_prowler_audit(
            args.repo,
            args.token,
            providers=providers,
            frameworks=frameworks,
            scanners=scanners,
            github_actions=github_actions,
            image_tag=args.image_tag,
            output_dir=args.output_dir,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    mapped = map_findings(raw_findings)
    sources = {}
    for finding in mapped:
        src = finding.get("mapping_source", "unknown")
        sources[src] = sources.get(src, 0) + 1
    print(
        f"Mapped {len(mapped)} FAIL findings (from {len(raw_findings)} raw) "
        f"via {sources} → {out_dir}",
        file=sys.stderr,
    )

    if args.pr:
        client = GitHubClient(args.token)
        changed = client.list_pr_files(owner, name, args.pr)
        if config.get("fail_pr_on", {}).get("new_findings_only", True):
            before = len(mapped)
            mapped = filter_by_files(mapped, changed)
            print(
                f"PR #{args.pr}: filtered {before} → {len(mapped)} findings on changed files",
                file=sys.stderr,
            )

    comment = render_pr_comment(
        mapped,
        args.repo,
        enabled_aspects=enabled_security_aspects(config),
    )
    if args.dry_run or not (args.pr or args.sync_issues):
        print(comment)

    threshold = config.get("fail_pr_on", {}).get("severity", "high")
    gate_hits = [
        f for f in mapped if meets_severity_threshold(f.get("severity", ""), threshold)
    ]

    report_meta: dict = {}
    if not args.dry_run and (args.pr or args.sync_issues):
        sarif_files = list(out_dir.glob("**/*.sarif"))
        report_meta = report_to_github(
            token=args.token,
            repo_full_name=args.repo,
            findings=mapped,
            pr_number=args.pr,
            sync_issues=args.sync_issues,
            config=config,
            sarif_path=str(sarif_files[0]) if sarif_files else None,
        )
        print(f"Reported to GitHub: {report_meta}", file=sys.stderr)

    saved = save_audit_report(
        out_dir=out_dir,
        repo=args.repo,
        comment_markdown=comment,
        findings=mapped,
        report_file=args.report_file,
        meta={
            "providers": providers,
            "frameworks": frameworks,
            "gate_hits": len(gate_hits),
            "threshold": threshold,
            "mapping_sources": sources,
            "github_report": report_meta,
        },
    )
    for kind, path in saved.items():
        print(f"Saved {kind} report → {path}", file=sys.stderr)

    if args.json_summary:
        print(
            json.dumps(
                {
                    "repo": args.repo,
                    "findings": len(mapped),
                    "gate_hits": len(gate_hits),
                    "threshold": threshold,
                    "report": report_meta,
                    "output_dir": str(out_dir),
                    "files": {k: str(v) for k, v in saved.items()},
                },
                indent=2,
            )
        )

    if gate_hits:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
