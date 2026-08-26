"""Load Audit Agent config from defaults or an optional target-repo file."""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def _ssl_context() -> ssl.SSLContext:
    """Build an SSL context; fall back when local CA certs are missing."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
        return ctx

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "frameworks": ["soc2", "iso27001_2022"],
    # Providers executed via the Prowler SDK/CLI.
    # Default: repo-level zero-touch (IaC + GitHub hardening). Add aws/azure/gcp when credentials exist.
    "providers": ["iac", "github"],
    "schedule": {"cron": "0 6 * * 1"},
    "scanners": {
        "iac": True,
        "secrets": True,
        "dependencies": True,
        "licenses": True,
        "github_actions": True,
    },
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

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "info": 0,
    "unknown": 0,
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        # Accept both snake_case and kebab-case from YAML-like JSON
        normalized = key.replace("-", "_")
        if (
            normalized in result
            and isinstance(result[normalized], dict)
            and isinstance(value, dict)
        ):
            result[normalized] = _deep_merge(result[normalized], value)
        elif key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[normalized] = value
    return result


def load_local_config(path: Path | None) -> dict[str, Any]:
    """Merge a local JSON/YAML-lite config file with defaults."""
    if path is None or not path.exists():
        return dict(DEFAULT_CONFIG)

    text = path.read_text(encoding="utf-8")
    data = _parse_config_text(text)
    if not isinstance(data, dict):
        return dict(DEFAULT_CONFIG)
    # Unwrap optional top-level key
    if "prowler-audit" in data and isinstance(data["prowler-audit"], dict):
        data = data["prowler-audit"]
    if "prowler_audit" in data and isinstance(data["prowler_audit"], dict):
        data = data["prowler_audit"]
    return _deep_merge(DEFAULT_CONFIG, data)


def fetch_remote_config(owner: str, repo: str, token: str, ref: str = "HEAD") -> dict[str, Any]:
    """Fetch `.github/prowler-audit.yml` from the target repo if it exists."""
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
        with urlopen(req, timeout=30, context=_ssl_context()) as resp:
            text = resp.read().decode("utf-8")
    except HTTPError as exc:
        if exc.code == 404:
            return dict(DEFAULT_CONFIG)
        raise

    data = _parse_config_text(text)
    if not isinstance(data, dict):
        return dict(DEFAULT_CONFIG)
    if "prowler-audit" in data and isinstance(data["prowler-audit"], dict):
        data = data["prowler-audit"]
    return _deep_merge(DEFAULT_CONFIG, data)


def _parse_config_text(text: str) -> Any:
    """Parse JSON, or a minimal YAML subset (no nested lists beyond simple scalars)."""
    text = text.strip()
    if not text:
        return {}
    if text.startswith("{") or text.startswith("["):
        return json.loads(text)

    # Prefer PyYAML when available
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        pass

    # Minimal fallback: only support flat-ish JSON exported configs
    # Convert simple YAML key: value into a dict via a tiny parser
    return _minimal_yaml(text)


def _minimal_yaml(text: str) -> dict[str, Any]:
    """Very small YAML subset for the documented config shape."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(0, root)]
    pending_list_key: str | None = None

    def _ensure_mapping_for_pending(container: dict[str, Any]) -> dict[str, Any]:
        """If pending key still holds an empty list placeholder, promote it to a map."""
        nonlocal pending_list_key
        if pending_list_key is None:
            return container
        value = container.get(pending_list_key)
        if isinstance(value, list) and len(value) == 0:
            nested: dict[str, Any] = {}
            container[pending_list_key] = nested
            pending_list_key = None
            return nested
        if isinstance(value, dict):
            pending_list_key = None
            return value
        return container

    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()

        while len(stack) > 1 and indent < stack[-1][0]:
            stack.pop()
            pending_list_key = None

        current = stack[-1][1]

        if line.startswith("- "):
            value = _scalar(line[2:].strip())
            if pending_list_key and isinstance(current, dict):
                lst = current.get(pending_list_key)
                if not isinstance(lst, list):
                    lst = []
                    current[pending_list_key] = lst
                lst.append(value)
            continue

        if ":" not in line:
            continue

        key, _, rest = line.partition(":")
        key = key.strip().replace("-", "_")
        rest = rest.strip()

        if rest == "":
            if not isinstance(current, dict):
                continue
            current = _ensure_mapping_for_pending(current)
            # Start as an empty list; promote to a mapping if nested keys appear
            current[key] = []
            pending_list_key = key
            stack.append((indent + 2, current))
        else:
            if not isinstance(current, dict):
                continue
            current = _ensure_mapping_for_pending(current)
            if current is not stack[-1][1]:
                stack.append((indent, current))
            current[key] = _scalar(rest)
            pending_list_key = None

    return root


def _scalar(value: str) -> Any:
    lower = value.lower()
    if lower in ("true", "yes"):
        return True
    if lower in ("false", "no"):
        return False
    if lower in ("null", "~", ""):
        return None
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def scanners_for_trivy(config: dict[str, Any]) -> list[str]:
    scanners = config.get("scanners", {})
    result: list[str] = []
    if scanners.get("iac", True):
        result.append("misconfig")
    if scanners.get("secrets", True):
        result.append("secret")
    if scanners.get("dependencies", True):
        result.append("vuln")
    if scanners.get("licenses", True):
        result.append("license")
    return result or ["misconfig", "secret"]


def enabled_security_aspects(config: dict[str, Any]) -> list[dict[str, str]]:
    """Return the security aspects this audit run is configured to cover."""
    providers = {p.lower() for p in (config.get("providers") or ["iac", "github"])}
    scanners = config.get("scanners") or {}
    aspects: list[dict[str, str]] = []

    if "iac" in providers:
        if scanners.get("iac", True):
            aspects.append(
                {
                    "id": "iac",
                    "label": "IaC / config",
                    "detail": "Terraform, Docker, K8s, CloudFormation misconfigurations",
                }
            )
        if scanners.get("secrets", True):
            aspects.append(
                {
                    "id": "secrets",
                    "label": "Secrets in source",
                    "detail": "Hardcoded credentials and tokens (Trivy secret)",
                }
            )
        if scanners.get("dependencies", True):
            aspects.append(
                {
                    "id": "dependencies",
                    "label": "Dependencies / CVEs",
                    "detail": "Lockfile and package vulnerabilities (Trivy vuln)",
                }
            )
        if scanners.get("licenses", True):
            aspects.append(
                {
                    "id": "licenses",
                    "label": "License compliance",
                    "detail": "Third-party license risk (Trivy license)",
                }
            )
        aspects.append(
            {
                "id": "containers",
                "label": "Containers / Dockerfiles",
                "detail": "Dockerfile and container config issues via IaC",
            }
        )

    if "github" in providers:
        aspects.append(
            {
                "id": "github",
                "label": "GitHub hardening",
                "detail": "Branch protection, secret scanning, Dependabot, org settings",
            }
        )
        if scanners.get("github_actions", True):
            aspects.append(
                {
                    "id": "github_actions",
                    "label": "GitHub Actions / CI-CD",
                    "detail": "Workflow security and supply-chain risks in Actions",
                }
            )

    for cloud in ("aws", "azure", "gcp", "kubernetes", "m365"):
        if cloud in providers:
            aspects.append(
                {
                    "id": cloud,
                    "label": f"Cloud ({cloud})",
                    "detail": f"Live {cloud} account checks with SOC 2 / ISO mappings",
                }
            )

    return aspects


def meets_severity_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity.lower(), 0) >= SEVERITY_RANK.get(
        threshold.lower(), 3
    )
