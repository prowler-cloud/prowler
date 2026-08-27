"""Map findings to SOC 2 / ISO 27001 using Prowler compliance first, heuristics last."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from audit_agent.infrastructure.prowler_compliance import (
    controls_for_check,
    extract_compliance_from_ocsf,
)

DEFAULT_MAPPING_PATH = (
    Path(__file__).resolve().parents[2] / "mappings" / "soc2_iso27001.json"
)


def _as_mapping(value: Any) -> dict[str, Any]:
    """Coerce non-dict metadata values to an empty mapping before nested gets."""
    return value if isinstance(value, dict) else {}


def load_mapping(path: Path | None = None) -> dict[str, Any]:
    mapping_path = path or DEFAULT_MAPPING_PATH
    with mapping_path.open(encoding="utf-8") as fh:
        return json.load(fh)


def normalize_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize an OCSF or simplified finding dict into a common shape."""
    # Already normalized
    if "check_id" in raw and "severity" in raw and "status" in raw:
        out = dict(raw)
        out.setdefault("provider", "iac")
        out.setdefault("service", "")
        return out

    status = (
        raw.get("status_code")
        or raw.get("status")
        or (raw.get("status_id") and str(raw.get("status_id")))
        or ""
    )
    if isinstance(status, str):
        status = status.upper()
    else:
        status = "FAIL" if status else "UNKNOWN"

    severity = (
        raw.get("severity")
        or (raw.get("severity_id") and str(raw.get("severity_id")))
        or "unknown"
    )
    if isinstance(severity, str):
        severity = severity.lower()
    else:
        severity = "unknown"

    finding_info = raw.get("finding_info") or {}
    resources = raw.get("resources") or []
    resource = resources[0] if resources else {}

    check_id = (
        finding_info.get("uid")
        or finding_info.get("title")
        or raw.get("CheckID")
        or raw.get("check_id")
        or "unknown"
    )
    # Prefer short check id from metadata when present
    unmapped = raw.get("unmapped") or {}
    if not isinstance(unmapped, dict):
        unmapped = {}
    metadata = _as_mapping(raw.get("metadata"))
    check_id = (
        unmapped.get("check_id")
        or metadata.get("event_code")
        or check_id
    )

    title = (
        finding_info.get("title")
        or raw.get("CheckTitle")
        or raw.get("title")
        or str(check_id)
    )
    description = (
        finding_info.get("desc")
        or finding_info.get("description")
        or raw.get("message")
        or title
    )

    file_path = (
        resource.get("uid")
        or resource.get("name")
        or raw.get("resource_uid")
        or raw.get("file")
        or ""
    )
    # OCSF often puts path in resource.data or labels
    data = resource.get("data") or {}
    if isinstance(data, dict) and data.get("path"):
        file_path = data["path"]

    product = _as_mapping(metadata.get("product"))
    feature = _as_mapping(product.get("feature"))
    service = (
        feature.get("name")
        or unmapped.get("service_name")
        or raw.get("ServiceName")
        or ""
    )

    provider = (
        unmapped.get("provider")
        or product.get("name")
        or raw.get("Provider")
        or ""
    )
    provider = str(provider).lower().replace("prowler-", "").replace("prowler", "").strip()
    if not provider and (
        str(check_id).startswith("repository_")
        or str(check_id).startswith("organization_")
        or str(check_id).startswith("githubactions_")
    ):
        provider = "github"

    return {
        "check_id": str(check_id),
        "title": str(title),
        "description": str(description),
        "severity": severity,
        "status": status if status in ("FAIL", "PASS", "MUTED") else (
            "FAIL" if "FAIL" in status else status
        ),
        "file": str(file_path),
        "service": str(service).lower(),
        "provider": provider or "iac",
        "raw": raw,
    }


def map_finding(finding: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
    mapping = mapping or load_mapping()
    normalized = normalize_finding(finding)
    soc2: list[str] = []
    iso: list[str] = []
    source = "heuristic"

    # 1) Compliance tags already attached by Prowler OCSF output
    from_ocsf = extract_compliance_from_ocsf(finding.get("raw") or finding)
    if from_ocsf["soc2"] or from_ocsf["iso27001"]:
        soc2 = list(from_ocsf["soc2"])
        iso = list(from_ocsf["iso27001"])
        source = "prowler_ocsf"

    # 2) Look up Prowler check ID in prowler/compliance/* JSON frameworks
    if not soc2 and not iso:
        from_index = controls_for_check(normalized.get("check_id", ""))
        if from_index["soc2"] or from_index["iso27001"]:
            soc2 = list(from_index["soc2"])
            iso = list(from_index["iso27001"])
            source = "prowler_compliance"

    # 3) Heuristic fallback (mainly for IaC / Trivy RuleIDs with no compliance JSON)
    if not soc2 and not iso:
        soc2, iso = _heuristic_controls(normalized, mapping)
        source = "heuristic"

    normalized["soc2"] = soc2
    normalized["iso27001"] = iso
    normalized["mapping_source"] = source
    normalized["controls_label"] = " / ".join(soc2 + iso) or "unmapped"
    return normalized


def _compact_match_text(value: str) -> str:
    """Strip separators so secret.scanning matches secret_scanning / secret scanning."""
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _heuristic_controls(
    normalized: dict[str, Any], mapping: dict[str, Any]
) -> tuple[list[str], list[str]]:
    service = normalized.get("service", "")
    provider = normalized.get("provider", "")
    haystack = " ".join(
        [
            normalized.get("check_id", ""),
            normalized.get("title", ""),
            normalized.get("description", ""),
            service,
            provider,
        ]
    ).lower()
    haystack_compact = _compact_match_text(haystack)

    by_scanner = mapping.get("by_scanner", {})
    scanner_key = None
    if "secret" in service or service == "secret":
        scanner_key = "secret"
    elif service in ("vuln", "vulnerability", "vulnerabilities"):
        scanner_key = "vuln"
    elif service == "license" or "license" in haystack:
        scanner_key = "license"

    if scanner_key and scanner_key in by_scanner:
        return (
            list(by_scanner[scanner_key].get("soc2", [])),
            list(by_scanner[scanner_key].get("iso27001", [])),
        )

    # GitHub provider checks (branch protection, secret scanning, Actions, …)
    if provider == "github" or "repository_" in haystack or "githubactions" in haystack:
        for rule in mapping.get("github_rules", []):
            needles = [_compact_match_text(n) for n in rule.get("match", [])]
            if any(n and n in haystack_compact for n in needles):
                return (
                    list(rule.get("soc2", [])),
                    list(rule.get("iso27001", [])),
                )

    for rule in mapping.get("misconfig_rules", []):
        needles = [_compact_match_text(n) for n in rule.get("match", [])]
        if any(n and n in haystack_compact for n in needles):
            return (
                list(rule.get("soc2", [])),
                list(rule.get("iso27001", [])),
            )

    default = mapping.get("default_misconfig", {})
    return (
        list(default.get("soc2", [])),
        list(default.get("iso27001", [])),
    )


def map_findings(
    findings: list[dict[str, Any]], mapping: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    mapping = mapping or load_mapping()
    mapped = [map_finding(f, mapping) for f in findings]
    return [f for f in mapped if f.get("status") == "FAIL"]


def _paths_align(finding_path: str, changed_path: str) -> bool:
    """True when paths are equal or one is a directory-bounded suffix of the other.

    Bare basenames (e.g. ``main.tf`` vs ``submodule/main.tf``) do not match.
    """
    fp = finding_path.replace("\\", "/").strip("/")
    cf = changed_path.replace("\\", "/").strip("/")
    if not fp or not cf:
        return False
    if fp == cf:
        return True
    if "/" in cf and fp.endswith("/" + cf):
        return True
    if "/" in fp and cf.endswith("/" + fp):
        return True
    return False


def filter_by_files(
    findings: list[dict[str, Any]], changed_files: set[str] | None
) -> list[dict[str, Any]]:
    if not changed_files:
        return findings
    changed = {cf for cf in changed_files if cf}
    result = []
    for finding in findings:
        file_path = (finding.get("file") or "").strip()
        if not file_path:
            # Pathless provider findings (e.g. GitHub repo-level checks) stay visible
            if str(finding.get("provider") or "").lower() == "github":
                result.append(finding)
            continue
        if any(_paths_align(file_path, cf) for cf in changed):
            result.append(finding)
    return result


def summarize_by_section(
    findings: list[dict[str, Any]], mapping: dict[str, Any] | None = None
) -> dict[str, dict[str, Any]]:
    mapping = mapping or load_mapping()
    sections = mapping.get("sections", {})
    summary: dict[str, dict[str, Any]] = {}

    for finding in findings:
        for control in finding.get("soc2", []) + finding.get("iso27001", []):
            section = sections.get(control, control)
            bucket = summary.setdefault(
                section, {"findings": 0, "controls": set(), "framework": _fw(control)}
            )
            bucket["findings"] += 1
            bucket["controls"].add(control)

    # Convert sets for JSON safety
    return {
        k: {
            "findings": v["findings"],
            "controls": sorted(v["controls"]),
            "framework": v["framework"],
        }
        for k, v in summary.items()
    }


def _fw(control: str) -> str:
    return "iso27001" if control.startswith("A.") else "soc2"
