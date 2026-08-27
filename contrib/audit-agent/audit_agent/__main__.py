"""CLI entrypoint for the Prowler Audit Agent."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from audit_agent.application.pipeline import AuditRequest, run_audit


def _resolve_token(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    for key in ("AUDIT_AGENT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(key)
        if value:
            return value
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
        return (result.stdout or "").strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SOC 2 / ISO 27001 audit for any GitHub repository"
    )
    parser.add_argument("--repo", required=True, help="Target repository as owner/name")
    parser.add_argument("--pr", type=int, default=None, help="Optional PR number")
    parser.add_argument(
        "--sync-issues",
        action="store_true",
        help="Open/close control-gap issues on the target via API",
    )
    parser.add_argument("--token", default=None, help="GitHub token")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--report-file", type=Path, default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and print the report; skip GitHub write APIs",
    )
    parser.add_argument("--json-summary", action="store_true")
    args = parser.parse_args(argv)

    token = _resolve_token(args.token)
    if not token:
        print(
            "error: provide --token, set AUDIT_AGENT_TOKEN / GH_TOKEN, "
            "or run `gh auth login`",
            file=sys.stderr,
        )
        return 2

    owner, _, name = args.repo.partition("/")
    if not owner or not name:
        print("error: --repo must be owner/name", file=sys.stderr)
        return 2

    request = AuditRequest(
        repo=args.repo,
        token=token,
        pr=args.pr,
        sync_issues=args.sync_issues,
        dry_run=args.dry_run,
        config_path=args.config,
        output_dir=args.output_dir,
        report_file=args.report_file,
    )
    try:
        result = run_audit(request)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json_summary:
        print(
            json.dumps(
                {
                    "repo": request.repo,
                    "findings": len(result.findings),
                    "gate_hits": len(result.gate_hits),
                    "threshold": result.threshold,
                    "report": result.github_report,
                    "output_dir": str(result.out_dir),
                    "files": {k: str(v) for k, v in result.saved.items()},
                },
                indent=2,
            )
        )
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
