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
    image_tag: str = "stable",
    output_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], Path]:
    """Run configured Prowler providers and return combined OCSF findings.

    Prefers the local monorepo CLI. For IaC, clones the target with `gh`
    (avoids Python SSL issues on macOS) then scans `--scan-path`.
    """
    providers = [p.lower() for p in (providers or ["iac", "github"])]
    scanners = scanners or ["misconfig", "secret", "vuln"]
    frameworks = frameworks or ["soc2", "iso27001_2022"]
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
                image_tag=image_tag,
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
    image_tag: str,
    output_dir: Path,
) -> list[dict[str, Any]]:
    env = os.environ.copy()
    env.setdefault("GITHUB_PERSONAL_ACCESS_TOKEN", token)
    env.setdefault("GITHUB_TOKEN", token)
    env.setdefault("GH_TOKEN", token)

    clone_dir: Path | None = None
    if provider == "iac":
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

    errors: list[str] = []
    local = _local_prowler_launcher()
    if local:
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
            errors.append(
                f"local CLI timed out after {exc.timeout}s"
            )
            print(errors[-1], file=sys.stderr)
        else:
            # Prowler exits 3 when findings exist — that is success for us
            if result.returncode in (0, 3):
                findings = load_ocsf_findings(output_dir)
                if findings or result.returncode == 0:
                    return findings
            err = (result.stderr or result.stdout or "").strip()
            errors.append(
                f"local CLI failed (exit {result.returncode}): {err[-2000:] or 'no output'}"
            )
            print(errors[-1], file=sys.stderr)

    # Only use Docker when the image is already present (avoid hung pulls)
    if _docker_image_present(image_tag):
        print(
            f"Falling back to local Docker image prowlercloud/prowler:{image_tag} …",
            file=sys.stderr,
        )
        return _docker_prowler(
            provider_args=cmd,
            token=token,
            image_tag=image_tag,
            output_dir=output_dir,
            env=env,
            scan_path=clone_dir,
        )

    hint = (
        "Fix the local CLI error above, or pre-pull "
        f"`docker pull prowlercloud/prowler:{image_tag}` "
        "(the agent will not auto-pull to avoid hangs)."
    )
    raise RuntimeError(
        "Prowler could not run. "
        + (" ".join(errors) + " " if errors else "")
        + hint
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


def _docker_image_present(image_tag: str) -> bool:
    if not shutil.which("docker"):
        return False
    result = subprocess.run(
        ["docker", "image", "inspect", f"prowlercloud/prowler:{image_tag}"],
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


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
    formats = ["json-ocsf", "sarif"] if provider == "iac" else ["json-ocsf"]
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

    if provider == "iac":
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
    elif provider == "github":
        args.extend(["--repository", repo_full_name])
        if not github_actions:
            args.append("--no-github-actions")

    return args


def _docker_prowler(
    *,
    provider_args: list[str],
    token: str,
    image_tag: str,
    output_dir: Path,
    env: dict[str, str],
    scan_path: Path | None = None,
) -> list[dict[str, Any]]:
    container_out = "/home/prowler/workspace/output"
    container_repo = "/home/prowler/workspace/repo"
    rewritten: list[str] = []
    skip_next = False
    for i, part in enumerate(provider_args):
        if skip_next:
            skip_next = False
            continue
        if part == "--output-directory" and i + 1 < len(provider_args):
            rewritten.extend([part, container_out])
            skip_next = True
        elif part == "--scan-path" and i + 1 < len(provider_args):
            rewritten.extend([part, container_repo])
            skip_next = True
        else:
            rewritten.append(part)

    cmd = [
        "docker",
        "run",
        "--rm",
        "--env",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "--env",
        "GITHUB_TOKEN",
        "-v",
        f"{output_dir.resolve()}:{container_out}",
        "-w",
        "/home/prowler/workspace",
        f"prowlercloud/prowler:{image_tag}",
        *rewritten,
    ]
    if scan_path and scan_path.is_dir():
        cmd[3:3] = ["-v", f"{scan_path.resolve()}:{container_repo}:ro"]

    run_env = os.environ.copy()
    run_env.update(env)
    run_env["GITHUB_PERSONAL_ACCESS_TOKEN"] = token
    run_env["GITHUB_TOKEN"] = token

    for key in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_REGION",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        if run_env.get(key):
            cmd[3:3] = ["--env", key]

    result = subprocess.run(cmd, check=False, env=run_env)
    findings = load_ocsf_findings(output_dir)
    if result.returncode not in (0, 3) and not findings:
        raise RuntimeError(
            f"Docker Prowler failed (exit {result.returncode}) with no findings"
        )
    return findings


def run_iac_scan(*args: Any, **kwargs: Any) -> tuple[list[dict[str, Any]], Path]:
    kwargs.setdefault("providers", ["iac"])
    return run_prowler_audit(*args, **kwargs)
