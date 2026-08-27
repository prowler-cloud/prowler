"""Render compliance PR comments and issue bodies."""

from __future__ import annotations

from typing import Any

from audit_agent.domain.enums import (
    SEVERITY_RANK,
    FrameworkFamily,
    Provider,
    SecurityAspect,
    TrivyScanner,
)
from audit_agent.application.map_controls import load_mapping, summarize_by_section

COMMENT_MARKER = "<!-- prowler-audit-agent -->"

ASPECT_ORDER = [aspect.value for aspect in SecurityAspect]


def render_pr_comment(
    findings: list[dict[str, Any]],
    repo: str,
    *,
    mapping: dict[str, Any] | None = None,
    enabled_aspects: list[dict[str, str]] | None = None,
) -> str:
    mapping = mapping or load_mapping()
    findings = _dedupe_findings(findings)
    summary = summarize_by_section(findings, mapping)

    soc2_rows = [
        (section, data)
        for section, data in summary.items()
        if data["framework"] == FrameworkFamily.SOC2.value
    ]
    iso_rows = [
        (section, data)
        for section, data in summary.items()
        if data["framework"] == FrameworkFamily.ISO27001.value
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
        lines.extend(
            _control_findings_section(
                "SOC 2 — All findings", findings, FrameworkFamily.SOC2.value
            )
        )
        lines.append("")
        lines.extend(
            _control_findings_section(
                "ISO 27001:2022 — All findings",
                findings,
                FrameworkFamily.ISO27001.value,
            )
        )
    else:
        lines.append("### No compliance gaps detected")
        lines.append("")
        lines.append("No FAIL findings mapped to SOC 2 / ISO 27001 for this scan.")

    lines.append("")
    lines.append(
        "<sub>Zero-touch Audit Agent · frameworks SOC 2 + ISO 27001 · no product UI</sub>"
    )
    return "\n".join(lines)


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one finding per check_id (highest severity wins)."""
    best: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = str(finding.get("check_id") or finding.get("title") or id(finding))
        current = best.get(key)
        if current is None or _sev_rank(finding.get("severity", "")) > _sev_rank(
            current.get("severity", "")
        ):
            best[key] = finding
    return list(best.values())


def _control_findings_section(
    title: str, findings: list[dict[str, Any]], framework_key: str
) -> list[str]:
    """List every finding under each control id for soc2 or iso27001."""
    by_control: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        for control in finding.get(framework_key) or []:
            by_control.setdefault(str(control), []).append(finding)

    lines = [f"### {title}"]
    if not by_control:
        lines.append("")
        lines.append("_No findings mapped to this framework._")
        return lines

    for control in sorted(by_control):
        lines.append("")
        lines.append(f"#### {control}")
        ordered = sorted(
            by_control[control],
            key=lambda f: _sev_rank(f.get("severity", "")),
            reverse=True,
        )
        for finding in ordered:
            lines.append(f"- {_format_finding_line(finding)}")
    return lines


def _format_finding_line(finding: dict[str, Any]) -> str:
    sev = (finding.get("severity") or "unknown").upper()
    title = finding.get("title") or finding.get("check_id")
    check_id = finding.get("check_id") or ""
    file_path = finding.get("file") or ""
    provider = finding.get("provider") or ""
    aspect = classify_aspect(finding)
    parts = [f"**{sev}**"]
    if provider:
        parts.append(f"`{provider}`")
    if aspect:
        parts.append(f"_{aspect}_")
    if check_id:
        parts.append(f"`{check_id}`")
    parts.append(str(title))
    if file_path:
        parts.append(f"— `{file_path}`")
    return " ".join(parts)


def classify_aspect(finding: dict[str, Any]) -> str:
    """Map a finding to a security-aspect id."""
    provider = (finding.get("provider") or "").lower()
    service = (finding.get("service") or "").lower()
    check = (finding.get("check_id") or "").lower()
    title = (finding.get("title") or "").lower()
    blob = f"{check} {title} {service}"
    cloud_values = {p.value for p in Provider.clouds()}

    if check.startswith("githubactions_") or (
        "workflow" in blob and provider == Provider.GITHUB.value
    ):
        return SecurityAspect.GITHUB_ACTIONS.value
    if provider == Provider.GITHUB.value or check.startswith(
        ("repository_", "organization_")
    ):
        return SecurityAspect.GITHUB.value
    if provider in cloud_values:
        return provider
    if service == TrivyScanner.SECRET.value or "secret" in blob:
        return SecurityAspect.SECRETS.value
    if service in (TrivyScanner.VULN.value, "vulnerability") or check.startswith("cve-"):
        return SecurityAspect.DEPENDENCIES.value
    if service == TrivyScanner.LICENSE.value or "license" in blob:
        return SecurityAspect.LICENSES.value
    if any(x in blob for x in ("dockerfile", "container", "image", "docker-compose")):
        return SecurityAspect.CONTAINERS.value
    if provider == Provider.IAC.value or service == TrivyScanner.MISCONFIG.value:
        return SecurityAspect.IAC.value
    return SecurityAspect.IAC.value


def render_issue_body(finding_group: dict[str, Any]) -> str:
    """finding_group: control ids + list of findings."""
    soc2 = finding_group.get(FrameworkFamily.SOC2.value, [])
    iso = finding_group.get(FrameworkFamily.ISO27001.value, [])
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
        soc2 = finding.get(FrameworkFamily.SOC2.value) or []
        iso = finding.get(FrameworkFamily.ISO27001.value) or []
        key = "+".join(sorted(soc2 + iso)) or "unmapped"
        group = groups.setdefault(
            key,
            {
                FrameworkFamily.SOC2.value: list(soc2),
                FrameworkFamily.ISO27001.value: list(iso),
                "findings": [],
            },
        )
        group["findings"].append(finding)
    return groups


def _sev_rank(severity: str) -> int:
    return SEVERITY_RANK.get((severity or "").lower(), 0)


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
