"""Resolve SOC 2 / ISO 27001 frameworks and check→control maps from Prowler compliance JSON."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from audit_agent.enums import FrameworkFamily, Provider

# Framework IDs accepted by `prowler <provider> --compliance …`
PROVIDER_COMPLIANCE: dict[str, list[str]] = {
    Provider.AWS.value: ["soc2_aws", "iso27001_2022_aws"],
    Provider.AZURE.value: ["soc2_azure", "iso27001_2022_azure"],
    Provider.GCP.value: ["soc2_gcp", "iso27001_2022_gcp"],
    Provider.KUBERNETES.value: ["iso27001_2022_kubernetes"],
    Provider.M365.value: ["iso27001_2022_m365"],
    Provider.NHN.value: ["iso27001_2022_nhn"],
    # IaC is an external-tool provider — no compliance JSON yet
    Provider.IAC.value: [],
    Provider.GITHUB.value: [],
    Provider.IMAGE.value: [],
    Provider.LLM.value: [],
}

# Always-on security frameworks for providers that lack SOC2/ISO JSON
PROVIDER_EXTRA_COMPLIANCE: dict[str, list[str]] = {
    Provider.GITHUB.value: ["cis_1.2.0_github"],
}


def repo_root() -> Path:
    """Prowler monorepo root (…/prowler) relative to this package."""
    # contrib/audit-agent/audit_agent/prowler_compliance.py → repo root
    return Path(__file__).resolve().parents[3]


def compliance_dir() -> Path:
    return repo_root() / "prowler" / "compliance"


def frameworks_for_provider(provider: str, requested: list[str] | None = None) -> list[str]:
    """Return concrete --compliance IDs for a provider.

    `requested` may contain short names (`soc2`, `iso27001_2022`) which are
    expanded using PROVIDER_COMPLIANCE. Providers without SOC2/ISO still get
    their extra security frameworks (e.g. CIS for GitHub).
    """
    provider = provider.lower()
    available = PROVIDER_COMPLIANCE.get(provider, [])
    expanded: list[str] = []

    if requested:
        for name in requested:
            key = name.lower().replace("-", "_")
            if key in available:
                expanded.append(key)
                continue
            for fw in available:
                if fw.startswith(key) or key in fw:
                    expanded.append(fw)
    else:
        expanded = list(available)

    for fw in PROVIDER_EXTRA_COMPLIANCE.get(provider, []):
        expanded.append(fw)

    seen: set[str] = set()
    result: list[str] = []
    for fw in expanded:
        if fw not in seen:
            seen.add(fw)
            result.append(fw)
    return result


@lru_cache(maxsize=1)
def load_check_control_index() -> dict[str, dict[str, list[str]]]:
    """Build check_id → {soc2: [...], iso27001: [...]} from prowler/compliance/*.json."""
    index: dict[str, dict[str, list[str]]] = {}
    root = compliance_dir()
    if not root.is_dir():
        return index

    for path in root.rglob("*.json"):
        name = path.name.lower()
        if "soc2" in name:
            family = FrameworkFamily.SOC2.value
        elif "iso27001" in name:
            family = FrameworkFamily.ISO27001.value
        else:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        requirements = data.get("Requirements") or data.get("requirements") or []
        for req in requirements:
            control_id = str(req.get("Id") or req.get("id") or "")
            if not control_id:
                continue
            # Normalize SOC2 ids like cc_6_1 → CC6.1 for display consistency
            display = _normalize_control_id(control_id, family)

            checks = req.get("Checks") or req.get("checks") or []
            if isinstance(checks, dict):
                # universal schema: { "aws": [...], "azure": [...] }
                check_ids: list[str] = []
                for values in checks.values():
                    if isinstance(values, list):
                        check_ids.extend(str(c) for c in values)
            else:
                check_ids = [str(c) for c in checks]

            for check_id in check_ids:
                bucket = index.setdefault(
                    check_id,
                    {
                        FrameworkFamily.SOC2.value: [],
                        FrameworkFamily.ISO27001.value: [],
                    },
                )
                if display not in bucket[family]:
                    bucket[family].append(display)

    return index


def controls_for_check(check_id: str) -> dict[str, list[str]]:
    index = load_check_control_index()
    return index.get(
        check_id,
        {FrameworkFamily.SOC2.value: [], FrameworkFamily.ISO27001.value: []},
    )


def _normalize_control_id(control_id: str, family: str) -> str:
    raw = control_id.strip()
    if family == FrameworkFamily.SOC2.value:
        # cc_6_1 → CC6.1 ; CC6.1 stays
        if raw.lower().startswith("cc_") or raw.lower().startswith("a_") or raw.lower().startswith("c_") or raw.lower().startswith("pi_"):
            parts = raw.lower().split("_")
            prefix = parts[0].upper()
            rest = ".".join(parts[1:])
            return f"{prefix}{rest}" if rest else prefix
        return raw.upper() if raw.lower().startswith("cc") else raw
    # ISO: a.8.20 / A.8.20 / A_8_20
    if raw.lower().startswith("a_"):
        parts = raw.split("_")
        return "A." + ".".join(parts[1:])
    if raw.lower().startswith("a.") or raw.upper().startswith("A."):
        return "A." + raw.split(".", 1)[-1] if raw[1] == "." else raw
    return raw


def extract_compliance_from_ocsf(raw: dict[str, Any]) -> dict[str, list[str]]:
    """Read compliance tags embedded by Prowler OCSF (`unmapped.compliance`)."""
    soc2: list[str] = []
    iso: list[str] = []
    unmapped = raw.get("unmapped") or {}
    compliance = unmapped.get("compliance") or raw.get("compliance") or {}
    if not isinstance(compliance, dict):
        return {
            FrameworkFamily.SOC2.value: soc2,
            FrameworkFamily.ISO27001.value: iso,
        }

    for key, values in compliance.items():
        key_l = str(key).lower()
        vals = values if isinstance(values, list) else [values]
        vals = [str(v) for v in vals if v]
        if "soc2" in key_l or "soc-2" in key_l:
            soc2.extend(
                _normalize_control_id(v, FrameworkFamily.SOC2.value) for v in vals
            )
        elif "iso27001" in key_l or "iso-27001" in key_l or "iso_27001" in key_l:
            iso.extend(
                _normalize_control_id(v, FrameworkFamily.ISO27001.value) for v in vals
            )
    return {
        FrameworkFamily.SOC2.value: list(dict.fromkeys(soc2)),
        FrameworkFamily.ISO27001.value: list(dict.fromkeys(iso)),
    }
