"""Single source of truth for the API version.

The semantic version is read once from ``api/pyproject.toml`` at module
import; consumers (health payload, OpenAPI schema) read the resulting
constants. Fails fast at boot if the file cannot be located, so a
packaging mistake surfaces immediately rather than serving stale data.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_PROJECT_NAME = "prowler-api"


def _discover_release_id() -> str:
    here = Path(__file__).resolve()
    for directory in here.parents:
        candidate = directory / "pyproject.toml"
        if not candidate.is_file():
            continue
        with candidate.open("rb") as f:
            data = tomllib.load(f)
        project = data.get("project") or {}
        if project.get("name") != _PROJECT_NAME:
            continue
        version = project.get("version")
        if not isinstance(version, str) or not version:
            raise RuntimeError(
                f"{candidate} declares an empty or invalid [project].version"
            )
        return version
    raise RuntimeError(
        f"Could not locate the {_PROJECT_NAME} pyproject.toml from {here}"
    )


RELEASE_ID: str = _discover_release_id()
# Public contract major (e.g. "1"); matches the /api/v1/ namespace.
API_VERSION: str = RELEASE_ID.split(".", 1)[0]
