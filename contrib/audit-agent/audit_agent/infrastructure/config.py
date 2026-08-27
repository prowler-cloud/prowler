"""Load Audit Agent config from defaults or an optional target-repo file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import yaml

from audit_agent.domain.enums import (
    ASPECT_SPECS,
    SCANNER_TO_TRIVY,
    SEVERITY_RANK,
    Framework,
    Provider,
    Scanner,
    TrivyScanner,
)
from audit_agent.infrastructure.http import ssl_context

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "frameworks": Framework.defaults(),
    "providers": Provider.defaults(),
    "scanners": {scanner.value: True for scanner in Scanner},
    "fail_pr_on": {
        "severity": "high",
        "new_findings_only": True,
    },
    "reporting": {
        "pr_comment": True,
        "sarif": True,
        "issues": True,
        "issue_labels": ["compliance", "prowler-audit"],
    },
}


def _normalize_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key).replace("-", "_"): _normalize_keys(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    return value


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(result.get(key), dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _from_parsed(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return dict(DEFAULT_CONFIG)
    data = _normalize_keys(data)
    if isinstance(data.get("prowler_audit"), dict):
        data = data["prowler_audit"]
    return _merge(DEFAULT_CONFIG, data)


def load_local_config(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return dict(DEFAULT_CONFIG)
    return _from_parsed(_parse_config_text(path.read_text(encoding="utf-8")))


def fetch_remote_config(
    owner: str, repo: str, token: str, ref: str = "HEAD"
) -> dict[str, Any] | None:
    """Fetch `.github/prowler-audit.yml` from the target repo, or None if missing."""
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f".github/prowler-audit.yml?ref={ref}"
    )
    req = Request(
        url,
        headers={
            "Accept": "application/vnd.github.raw+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "prowler-audit-agent",
        },
    )
    try:
        with urlopen(req, timeout=30, context=ssl_context()) as resp:
            text = resp.read().decode("utf-8")
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return _from_parsed(_parse_config_text(text))


def _parse_config_text(text: str) -> Any:
    text = text.strip()
    if not text:
        return {}
    if text.startswith("{") or text.startswith("["):
        return json.loads(text)
    return yaml.safe_load(text) or {}


def scanners_for_trivy(config: dict[str, Any]) -> list[str]:
    scanners = config.get("scanners") or {}
    result = [
        trivy.value
        for scanner, trivy in SCANNER_TO_TRIVY.items()
        if scanners.get(scanner.value, True)
    ]
    return result or [TrivyScanner.MISCONFIG.value, TrivyScanner.SECRET.value]


def enabled_security_aspects(config: dict[str, Any]) -> list[dict[str, str]]:
    providers = {p.lower() for p in (config.get("providers") or Provider.defaults())}
    scanners = config.get("scanners") or {}
    aspects: list[dict[str, str]] = []

    for spec in ASPECT_SPECS:
        if spec.provider.value not in providers:
            continue
        if spec.scanner is not None and not scanners.get(spec.scanner.value, True):
            continue
        aspects.append(
            {"id": spec.aspect.value, "label": spec.label, "detail": spec.detail}
        )

    for cloud in Provider.clouds():
        if cloud.value in providers:
            aspects.append(
                {
                    "id": cloud.value,
                    "label": f"Cloud ({cloud.value})",
                    "detail": f"Live {cloud.value} account checks with SOC 2 / ISO mappings",
                }
            )
    return aspects


def meets_severity_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity.lower(), 0) >= SEVERITY_RANK.get(
        threshold.lower(), 3
    )
