"""Render compliance PR comments and issue bodies."""

from __future__ import annotations

from typing import Any

from audit_agent.map_controls import load_mapping, summarize_by_section

COMMENT_MARKER = "<!-- prowler-audit-agent -->"

ASPECT_ORDER = [
    "iac",
    "secrets",
    "dependencies",
    "licenses",
    "containers",
    "github",
    "github_actions",
    "aws",
    "azure",
    "gcp",
    "kubernetes",
    "m365",
]


def render_pr_comment(
    findings: list[dict[str, Any]],
    repo: str,
    *,
    mapping: dict[str, Any] | None = None,
    enabled_aspects: list[dict[str, str]] | None = None,
) -> str:
    mapping = mapping or load_mapping()
    summary = summarize_by_section(findings, mapping)

    soc2_rows = [
        (section, data)
        for section, data in summary.items()
        if data["framework"] == "soc2"
    ]
    iso_rows = [
        (section, data)
        for section, data in summary.items()
        if data["framework"] == "iso27001"
    ]

    lines = [
        COMMENT_MARKER,
        "## Compliance Audit — SOC 2 + ISO 27001",
        "",
        f"_Prowler Audit Agent · `{repo}`_",
        "",
    ]

    aspect_rows = _aspect_table(findings, enabled_aspects or [])
    if aspect_rows:
        lines.append("### Security Aspects")
        lines.append("| Aspect | Status | Findings | Coverage |")
        lines.append("|--------|--------|----------|----------|")
        for row in aspect_rows:
            lines.append(
                f"| {row['label']} | {row['status']} | {row['count']} | {row['detail']} |"
            )
        lines.append("")

    lines.append("### SOC 2")
    lines.append("| Section | Status | Findings | Controls |")
    lines.append("|---------|--------|----------|----------|")
    if soc2_rows:
        for section, data in sorted(soc2_rows):
            status = "⚠️" if data["findings"] else "✅"
            controls = ", ".join(data["controls"]) or "—"
            lines.append(
                f"| {section} | {status} | {data['findings']} | {controls} |"
            )
    else:
        lines.append("| — | ✅ | 0 | — |")

    lines.append("")
    lines.append("### ISO 27001:2022")
    lines.append("| Category | Status | Findings | Controls |")
    lines.append("|----------|--------|----------|----------|")
    if iso_rows:
        for section, data in sorted(iso_rows):
            status = "⚠️" if data["findings"] else "✅"
            controls = ", ".join(data["controls"]) or "—"
            lines.append(
                f"| {section} | {status} | {data['findings']} | {controls} |"
            )
    else:
        lines.append("| — | ✅ | 0 | — |")

    lines.append("")
    if findings:
        lines.append("### New gaps")
        for finding in sorted(
            findings, key=lambda f: _sev_rank(f.get("severity", "")), reverse=True
        )[:25]:
            sev = (finding.get("severity") or "unknown").upper()
            label = finding.get("controls_label") or "unmapped"
            title = finding.get("title") or finding.get("check_id")
            file_path = finding.get("file") or ""
            provider = finding.get("provider") or ""
            aspect = classify_aspect(finding)
            prefix = f"`{provider}` " if provider else ""
            aspect_tag = f" _{aspect}_" if aspect else ""
            loc = f" — `{file_path}`" if file_path else ""
            lines.append(
                f"- **{sev}** {prefix}[{label}]{aspect_tag} {title}{loc}"
            )
        if len(findings) > 25:
            lines.append(f"- _…and {len(findings) - 25} more_")
    else:
        lines.append("### No compliance gaps detected")
        lines.append("")
        lines.append("No FAIL findings mapped to SOC 2 / ISO 27001 for this scan.")

    lines.append("")
    lines.append(
        "<sub>Zero-touch Audit Agent · frameworks SOC 2 + ISO 27001 · no product UI</sub>"
    )
    return "\n".join(lines)


def classify_aspect(finding: dict[str, Any]) -> str:
    """Map a finding to a security-aspect id."""
    provider = (finding.get("provider") or "").lower()
    service = (finding.get("service") or "").lower()
    check = (finding.get("check_id") or "").lower()
    title = (finding.get("title") or "").lower()
    blob = f"{check} {title} {service}"

    if check.startswith("githubactions_") or "workflow" in blob and provider == "github":
        return "github_actions"
    if provider == "github" or check.startswith(("repository_", "organization_")):
        return "github"
    if provider in ("aws", "azure", "gcp", "kubernetes", "m365"):
        return provider
    if service == "secret" or "secret" in blob:
        return "secrets"
    if service in ("vuln", "vulnerability") or check.startswith("cve-"):
        return "dependencies"
    if service == "license" or "license" in blob:
        return "licenses"
    if any(x in blob for x in ("dockerfile", "container", "image", "docker-compose")):
        return "containers"
    if provider == "iac" or service == "misconfig":
        return "iac"
    return "iac"


def render_issue_body(finding_group: dict[str, Any]) -> str:
    """finding_group: control ids + list of findings."""
    soc2 = finding_group.get("soc2", [])
    iso = finding_group.get("iso27001", [])
    findings = finding_group.get("findings", [])
    title_finding = findings[0] if findings else {}

    tags = " ".join(
        [f"[SOC2/{c}]" for c in soc2] + [f"[ISO27001/{c}]" for c in iso]
    )
    lines = [
        f"## {tags} {title_finding.get('title', 'Compliance gap')}",
        "",
        f"**Frameworks:** {', '.join(soc2 + iso) or 'unmapped'}",
        f"**Severity:** {(title_finding.get('severity') or 'unknown').title()}",
        "",
        "### Evidence",
    ]
    for finding in findings[:20]:
        file_path = finding.get("file") or "(no file)"
        lines.append(f"- `{finding.get('check_id')}` — `{file_path}`")
    lines.append("")
    lines.append("### Remediation")
    lines.append(
        title_finding.get("description")
        or "Review the failing check and apply the recommended hardening."
    )
    lines.append("")
    lines.append("<!-- prowler-audit-agent-issue -->")
    return "\n".join(lines)


def group_findings_by_control(
    findings: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for finding in findings:
        soc2 = finding.get("soc2") or []
        iso = finding.get("iso27001") or []
        key = "+".join(sorted(soc2 + iso)) or "unmapped"
        group = groups.setdefault(
            key, {"soc2": list(soc2), "iso27001": list(iso), "findings": []}
        )
        group["findings"].append(finding)
    return groups


def _sev_rank(severity: str) -> int:
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
        "info": 0,
    }
    return order.get(severity.lower(), 0)


def _aspect_table(
    findings: list[dict[str, Any]],
    enabled: list[dict[str, str]],
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for finding in findings:
        aspect = classify_aspect(finding)
        counts[aspect] = counts.get(aspect, 0) + 1

    if not enabled:
        # Fall back to aspects that produced findings
        enabled = [
            {"id": aid, "label": aid, "detail": ""}
            for aid in ASPECT_ORDER
            if aid in counts
        ]

    rows: list[dict[str, Any]] = []
    for aspect in enabled:
        aid = aspect["id"]
        count = counts.get(aid, 0)
        if count:
            status = "⚠️"
        else:
            status = "✅"
        rows.append(
            {
                "label": aspect.get("label") or aid,
                "status": status,
                "count": count,
                "detail": aspect.get("detail") or "—",
            }
        )
    return rows
