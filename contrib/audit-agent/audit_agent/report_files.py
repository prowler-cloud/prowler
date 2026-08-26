"""Persist audit reports to disk."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def save_audit_report(
    *,
    out_dir: Path,
    repo: str,
    comment_markdown: str,
    findings: list[dict[str, Any]],
    report_file: Path | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Path]:
    """Write markdown + JSON audit artifacts. Returns paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    md_path = report_file or (out_dir / "audit-report.md")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(comment_markdown + "\n", encoding="utf-8")
    written["markdown"] = md_path

    # Also keep a copy under out_dir when --report-file points elsewhere
    if report_file is not None:
        bundled = out_dir / "audit-report.md"
        if bundled.resolve() != md_path.resolve():
            bundled.write_text(comment_markdown + "\n", encoding="utf-8")
            written["markdown_bundled"] = bundled

    serializable = []
    for finding in findings:
        serializable.append(
            {
                "check_id": finding.get("check_id"),
                "title": finding.get("title"),
                "description": finding.get("description"),
                "severity": finding.get("severity"),
                "status": finding.get("status"),
                "file": finding.get("file"),
                "service": finding.get("service"),
                "provider": finding.get("provider"),
                "soc2": list(finding.get("soc2") or []),
                "iso27001": list(finding.get("iso27001") or []),
                "controls_label": finding.get("controls_label"),
                "mapping_source": finding.get("mapping_source"),
            }
        )

    payload = {
        "repo": repo,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(serializable),
        "findings": serializable,
        "meta": meta or {},
    }
    json_path = out_dir / "audit-findings.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    written["json"] = json_path

    return written
