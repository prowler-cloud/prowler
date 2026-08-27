"""Run Prowler providers from this monorepo (SDK / CLI), not a heuristic-only wrapper."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from audit_agent.enums import Framework, Provider, TrivyScanner
from audit_agent.prowler_compliance import frameworks_for_provider, repo_root

# Stall watchdog for local Prowler invocations (import probe and full scan).
_PROWLER_SUBPROCESS_TIMEOUT_S = 60 * 30


def run_prowler_audit(
    repo_full_name: str,
    token: str,
    *,
    providers: list[str] | None = None,
    frameworks: list[str] | None = None,
    scanners: list[str] | None = None,
    github_actions: bool = True,
    output_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], Path]:
    """Run configured Prowler providers and return combined OCSF findings.

    Uses the local monorepo CLI. For IaC, clones the target with `gh`
    (avoids Python SSL issues on macOS) then scans `--scan-path`.
    """
    providers = [p.lower() for p in (providers or Provider.defaults())]
    scanners = scanners or [
        TrivyScanner.MISCONFIG.value,
        TrivyScanner.SECRET.value,
        TrivyScanner.VULN.value,
    ]
    frameworks = frameworks or Framework.defaults()
    out = output_dir or Path(tempfile.mkdtemp(prefix="prowler-audit-"))
    out.mkdir(parents=True, exist_ok=True)

    all_findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for provider in providers:
        provider_out = out / provider
        provider_out.mkdir(parents=True, exist_ok=True)
        try:
            findings = _run_provider(
                provider=provider,
                repo_full_name=repo_full_name,
                token=token,
                frameworks=frameworks,
                scanners=scanners,
                github_actions=github_actions,
                output_dir=provider_out,
            )
            all_findings.extend(findings)
        except RuntimeError as exc:
            errors.append(f"{provider}: {exc}")
            print(f"warning: provider {provider} failed: {exc}", file=sys.stderr)

    if not all_findings and errors:
        raise RuntimeError("All providers failed. " + " | ".join(errors))
    if errors:
        print(
            f"warning: completed with partial results ({len(errors)} provider error(s))",
            file=sys.stderr,
        )

    return all_findings, out


def load_ocsf_findings(output_dir: Path) -> list[dict[str, Any]]:
    files = sorted(
        output_dir.glob("**/*.ocsf.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not files:
        files = sorted(
            (
                p
                for p in output_dir.glob("**/*.json")
                if "sarif" not in p.name.lower() and "compliance" not in p.name.lower()
            ),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    # Prefer the newest file so re-runs into the same --output-dir do not stack duplicates
    if files:
        files = [files[0]]
    findings: list[dict[str, Any]] = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            findings.extend(data)
        elif isinstance(data, dict) and "findings" in data:
            findings.extend(data["findings"])
    return findings


def _run_provider(
    *,
    provider: str,
    repo_full_name: str,
    token: str,
    frameworks: list[str],
    scanners: list[str],
    github_actions: bool,
    output_dir: Path,
) -> list[dict[str, Any]]:
    env = os.environ.copy()
    env.setdefault("GITHUB_PERSONAL_ACCESS_TOKEN", token)
    env.setdefault("GITHUB_TOKEN", token)
    env.setdefault("GH_TOKEN", token)

    clone_dir: Path | None = None
    if provider == Provider.IAC.value:
        clone_dir = output_dir / "repo"
        _gh_clone(repo_full_name, clone_dir, token)

    cmd = _build_prowler_args(
        provider=provider,
        repo_full_name=repo_full_name,
        frameworks=frameworks,
        scanners=scanners,
        output_dir=output_dir,
        scan_path=clone_dir,
        github_actions=github_actions,
    )

    local = _local_prowler_launcher()
    if not local:
        raise RuntimeError(
            "Local Prowler CLI not found. Run `uv sync` from the repo root."
        )

    full_cmd = [*local, *cmd]
    print(f"Running Prowler via: {' '.join(local)} …", file=sys.stderr)
    try:
        result = subprocess.run(
            full_cmd,
            check=False,
            env=env,
            cwd=str(repo_root()),
            capture_output=True,
            text=True,
            timeout=_PROWLER_SUBPROCESS_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"local CLI timed out after {exc.timeout}s") from exc

    # Prowler exits 3 when findings exist — that is success for us
    if result.returncode in (0, 3):
        findings = load_ocsf_findings(output_dir)
        if findings or result.returncode == 0:
            return findings

    err = (result.stderr or result.stdout or "").strip()
    raise RuntimeError(
        f"local CLI failed (exit {result.returncode}): {err[-2000:] or 'no output'}"
    )


def _gh_clone(repo_full_name: str, dest: Path, token: str) -> None:
    """Clone target repo with gh/git (system SSL), not Prowler's Python git client."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    env = os.environ.copy()
    env["GH_TOKEN"] = token
    env["GITHUB_TOKEN"] = token

    gh = shutil.which("gh")
    if gh:
        print(f"Cloning {repo_full_name} with gh …", file=sys.stderr)
        result = subprocess.run(
            [
                gh,
                "repo",
                "clone",
                repo_full_name,
                str(dest),
                "--",
                "--depth",
                "1",
            ],
            check=False,
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return
        raise RuntimeError(
            f"gh clone failed: {(result.stderr or result.stdout or '').strip()}"
        )

    git = shutil.which("git")
    if not git:
        raise RuntimeError("Need `gh` or `git` to clone the target repository")

    print(f"Cloning {repo_full_name} with git …", file=sys.stderr)
    # Keep the token out of argv and out of the clone's .git/config
    cred_file = dest.parent / f".git-credentials-{os.getpid()}"
    try:
        cred_file.write_text(
            f"https://x-access-token:{token}@github.com\n",
            encoding="utf-8",
        )
        cred_file.chmod(0o600)
        result = subprocess.run(
            [
                git,
                "-c",
                f"credential.helper=store --file={cred_file}",
                "clone",
                "--depth",
                "1",
                f"https://github.com/{repo_full_name}.git",
                str(dest),
            ],
            check=False,
            env=env,
            capture_output=True,
            text=True,
        )
    finally:
        cred_file.unlink(missing_ok=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"git clone failed: {(result.stderr or result.stdout or '').strip()}"
        )


def _local_prowler_launcher() -> list[str] | None:
    """Return argv prefix to invoke this checkout's Prowler CLI with a working env."""
    root = repo_root()
    cli = root / "prowler-cli.py"
    if not cli.is_file():
        return None

    uv = shutil.which("uv") or str(Path.home() / ".local" / "bin" / "uv")
    if Path(uv).is_file() and _can_import_prowler([uv, "run", "python"]):
        return [uv, "run", "python", str(cli)]

    candidates: list[Path] = []
    if os.environ.get("VIRTUAL_ENV"):
        candidates.append(Path(os.environ["VIRTUAL_ENV"]) / "bin" / "python")
    candidates.append(root / ".venv" / "bin" / "python")

    for python in candidates:
        if python.is_file() and _can_import_prowler([str(python)]):
            return [str(python), str(cli)]

    for name in ("python3", "python"):
        python = shutil.which(name)
        if python and _can_import_prowler([python]):
            return [python, str(cli)]

    return None


def _can_import_prowler(python_prefix: list[str]) -> bool:
    try:
        result = subprocess.run(
            [*python_prefix, "-c", "import prowler, colorama"],
            check=False,
            capture_output=True,
            text=True,
            cwd=str(repo_root()),
            timeout=_PROWLER_SUBPROCESS_TIMEOUT_S,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _build_prowler_args(
    *,
    provider: str,
    repo_full_name: str,
    frameworks: list[str],
    scanners: list[str],
    output_dir: Path,
    scan_path: Path | None = None,
    github_actions: bool = True,
) -> list[str]:
    """Build the argument list after `prowler` / `prowler-cli.py`."""
    # SARIF is only supported for the IaC provider
    formats = ["json-ocsf", "sarif"] if provider == Provider.IAC.value else ["json-ocsf"]
    args: list[str] = [
        provider,
        "--output-formats",
        *formats,
        "--output-directory",
        str(output_dir),
    ]

    compliance = frameworks_for_provider(provider, frameworks)
    if compliance:
        args.extend(["--compliance", *compliance])

    if provider == Provider.IAC.value:
        if not scan_path:
            raise RuntimeError("IaC scan requires a local clone path")
        args.extend(
            [
                "--scan-path",
                str(scan_path),
                "--scanners",
                *scanners,
            ]
        )
    elif provider == Provider.GITHUB.value:
        args.extend(["--repository", repo_full_name])
        if not github_actions:
            args.append("--no-github-actions")

    return args


def run_iac_scan(*args: Any, **kwargs: Any) -> tuple[list[dict[str, Any]], Path]:
    kwargs.setdefault("providers", [Provider.IAC.value])
    return run_prowler_audit(*args, **kwargs)
