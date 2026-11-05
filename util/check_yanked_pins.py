"""Fail when a pinned or locked package version has been yanked from PyPI.

Exact pins (`==`) still install a yanked release: pip and uv both accept a yanked
version when it is the only candidate an exact specifier allows, printing at most a
warning. That is how zstd 1.5.7.3 (yanked as "buggy - not thread safe") stayed in
uv.lock for months. Yanks happen on PyPI's side after the pin lands, so this check
must run on a schedule, not only on pull requests.

For each project directory given (default: current directory) the script collects:

- exact `==` pins from pyproject.toml: [project] dependencies and optional
  dependencies, [dependency-groups], and [tool.uv] constraint-dependencies and
  override-dependencies
- every registry-sourced package in uv.lock

and asks the PyPI JSON API whether each (name, version) is yanked or gone.

Usage:
    python util/check_yanked_pins.py            # checks ./pyproject.toml and ./uv.lock
    python util/check_yanked_pins.py . api mcp_server

Exit status is 1 when any pin is yanked or no longer exists on PyPI, 0 otherwise.
Network errors are retried; a persistent error also exits 1, because "unknown"
must not read as "clean".
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from time import sleep
from typing import Callable, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: tomllib arrived in 3.11
    import tomli as tomllib

PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
USER_AGENT = "prowler-check-yanked-pins (+https://github.com/prowler-cloud/prowler)"

# PEP 508 requirement with an exact pin: "name[extras]==version ; markers"
_EXACT_PIN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*(?P<version>[^\s;,]+)"
)


def normalize(name: str) -> str:
    """PEP 503 name normalization: alibabacloud_tea_openapi == alibabacloud-tea-openapi."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True, order=True)
class Pin:
    """One exact version requirement and the file/table it was read from."""

    name: str
    version: str
    source: str


@dataclass(frozen=True)
class Verdict:
    """PyPI's answer for one pin: ok, yanked, missing (404) or error (unreachable)."""

    pin: Pin
    status: str  # "ok" | "yanked" | "missing" | "error"
    detail: str = ""


def pins_from_pyproject(text: str, source_prefix: str) -> set[Pin]:
    """Collect exact == pins from every dependency-bearing table in a pyproject.toml."""
    data = tomllib.loads(text)
    tables: list[tuple[str, Iterable[str]]] = []

    project = data.get("project", {})
    tables.append(("project.dependencies", project.get("dependencies", [])))
    for extra, reqs in project.get("optional-dependencies", {}).items():
        tables.append((f"project.optional-dependencies.{extra}", reqs))
    for group, reqs in data.get("dependency-groups", {}).items():
        # dependency-groups entries may be tables ({include-group = ...}); keep strings only
        tables.append(
            (f"dependency-groups.{group}", [r for r in reqs if isinstance(r, str)])
        )
    uv = data.get("tool", {}).get("uv", {})
    tables.append(
        ("tool.uv.constraint-dependencies", uv.get("constraint-dependencies", []))
    )
    tables.append(
        ("tool.uv.override-dependencies", uv.get("override-dependencies", []))
    )

    pins: set[Pin] = set()
    for table, requirements in tables:
        for requirement in requirements:
            match = _EXACT_PIN.match(requirement)
            if match:
                pins.add(
                    Pin(
                        normalize(match.group("name")),
                        match.group("version"),
                        f"{source_prefix}pyproject.toml [{table}]",
                    )
                )
    return pins


def pins_from_uv_lock(text: str, source_prefix: str) -> set[Pin]:
    """Collect every registry-sourced (name, version) from a uv.lock."""
    data = tomllib.loads(text)
    pins: set[Pin] = set()
    for package in data.get("package", []):
        source = package.get("source", {})
        # git, path, editable and virtual sources are not on PyPI; skip them
        if "registry" not in source:
            continue
        pins.add(
            Pin(
                normalize(package["name"]),
                package["version"],
                f"{source_prefix}uv.lock",
            )
        )
    return pins


def collect_pins(project_dir: Path) -> set[Pin]:
    """Gather pins from a project's pyproject.toml and uv.lock, whichever exist."""
    prefix = "" if project_dir == Path(".") else f"{project_dir.as_posix()}/"
    pins: set[Pin] = set()
    pyproject = project_dir / "pyproject.toml"
    lock = project_dir / "uv.lock"
    if not pyproject.is_file() and not lock.is_file():
        raise FileNotFoundError(
            f"{project_dir}: neither pyproject.toml nor uv.lock found"
        )
    if pyproject.is_file():
        pins |= pins_from_pyproject(pyproject.read_text(encoding="utf-8"), prefix)
    if lock.is_file():
        pins |= pins_from_uv_lock(lock.read_text(encoding="utf-8"), prefix)
    return pins


def fetch_release(name: str, version: str, retries: int = 3) -> tuple[str, str]:
    """Return (status, detail) for one release, where status is ok|yanked|missing|error."""
    request = urllib.request.Request(
        PYPI_JSON.format(name=name, version=version), headers={"User-Agent": USER_AGENT}
    )
    last_error = ""
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                info = json.load(response)["info"]
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return "missing", "not found on PyPI"
            last_error = f"HTTP {exc.code}"
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
            KeyError,
        ) as exc:
            last_error = repr(exc)
        else:
            if info.get("yanked"):
                return "yanked", info.get("yanked_reason") or "no reason given"
            return "ok", ""
        sleep(2**attempt)
    return "error", last_error


def evaluate(
    pins: Iterable[Pin],
    fetch: Callable[[str, str], tuple[str, str]] | None = None,
    workers: int = 16,
) -> list[Verdict]:
    """Query each distinct (name, version) once and fan the answer out to every source."""
    if fetch is None:
        fetch = fetch_release
    pins = sorted(set(pins))
    releases = sorted({(pin.name, pin.version) for pin in pins})
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = dict(
            zip(
                releases,
                pool.map(lambda release: fetch(*release), releases),
                strict=True,
            )
        )
    return [Verdict(pin, *results[(pin.name, pin.version)]) for pin in pins]


def main(argv: list[str] | None = None) -> int:
    """Check every project on the command line; return 1 if any pin is not ok."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "projects",
        nargs="*",
        default=["."],
        help="project directories containing pyproject.toml and/or uv.lock (default: .)",
    )
    parser.add_argument(
        "--workers", type=int, default=16, help="concurrent PyPI requests"
    )
    args = parser.parse_args(argv)

    pins: set[Pin] = set()
    for project in args.projects:
        pins |= collect_pins(Path(project))
    print(
        f"Checking {len({(p.name, p.version) for p in pins})} pinned releases from {len(pins)} pins"
    )

    verdicts = evaluate(pins, workers=args.workers)
    problems = [v for v in verdicts if v.status != "ok"]
    for verdict in problems:
        pin = verdict.pin
        print(
            f"::error::{pin.name}=={pin.version} is {verdict.status} ({verdict.detail}) in {pin.source}"
        )
    if problems:
        print(f"{len(problems)} problem(s) found")
        return 1
    print("No yanked or missing releases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
