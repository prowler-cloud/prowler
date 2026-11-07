"""Exercise the container entrypoint without starting Django or Celery."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ENTRYPOINT = Path(__file__).resolve().parents[4] / "docker-entrypoint.sh"


@pytest.fixture
def entrypoint_env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "pathlib.Path(os.environ['UV_CALLS']).write_text(json.dumps(sys.argv[1:]))\n"
        "sys.exit(int(os.environ.get('UV_EXIT', '0')))\n"
    )
    uv.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "TMPDIR": str(tmp_path),
        "UV_CALLS": str(tmp_path / "uv-call.json"),
    }
    env.pop("ECS_CONTAINER_METADATA_URI_V4", None)
    return env


def run_entrypoint(mode, env):
    return subprocess.run(
        ["sh", str(ENTRYPOINT), mode],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )


def uv_arguments(env):
    return json.loads(Path(env["UV_CALLS"]).read_text())


def test_healthcheck_targets_the_worker_started_in_this_container(entrypoint_env):
    assert run_entrypoint("worker", entrypoint_env).returncode == 0
    worker_args = uv_arguments(entrypoint_env)
    node = worker_args[worker_args.index("-n") + 1]
    assert re.fullmatch(r"[a-f0-9]{32}@.+", node)

    result = run_entrypoint("worker-healthcheck", entrypoint_env)

    assert result.returncode == 0, result.stderr + result.stdout
    probe_args = uv_arguments(entrypoint_env)
    assert "inspect" in probe_args and "ping" in probe_args
    assert probe_args[probe_args.index("--destination") + 1] == node
    assert float(probe_args[probe_args.index("--timeout") + 1]) > 0


def test_restart_replaces_the_previous_worker_identity(entrypoint_env):
    assert run_entrypoint("worker", entrypoint_env).returncode == 0
    first = uv_arguments(entrypoint_env)
    assert run_entrypoint("worker", entrypoint_env).returncode == 0
    second = uv_arguments(entrypoint_env)
    assert first[first.index("-n") + 1] != second[second.index("-n") + 1]

    assert run_entrypoint("worker-healthcheck", entrypoint_env).returncode == 0
    probe = uv_arguments(entrypoint_env)
    assert probe[probe.index("--destination") + 1] == second[second.index("-n") + 1]


@pytest.mark.parametrize(
    "metadata",
    ['{"TaskARN": "arn:aws:ecs:region:account:task/cluster/task-id"}', "unavailable"],
)
def test_healthcheck_uses_resolved_ecs_name_or_uuid_fallback(entrypoint_env, metadata):
    wget = Path(entrypoint_env["TMPDIR"]) / "bin" / "wget"
    wget.write_text("#!/bin/sh\nprintf '%s' \"" + metadata.replace('"', '\\"') + '"\n')
    wget.chmod(0o755)
    entrypoint_env["ECS_CONTAINER_METADATA_URI_V4"] = "http://metadata.invalid"
    assert run_entrypoint("worker", entrypoint_env).returncode == 0
    args = uv_arguments(entrypoint_env)
    node = args[args.index("-n") + 1]
    if metadata.startswith("{"):
        assert node.startswith("task-id@")
    else:
        assert re.fullmatch(r"[a-f0-9]{32}@.+", node)

    assert run_entrypoint("worker-healthcheck", entrypoint_env).returncode == 0
    probe = uv_arguments(entrypoint_env)
    assert probe[probe.index("--destination") + 1] == node


@pytest.mark.parametrize("contents", [None, "", "\n"])
def test_healthcheck_fails_before_worker_identity_is_available(
    entrypoint_env, contents
):
    if contents is not None:
        (Path(entrypoint_env["TMPDIR"]) / "prowler-worker-nodename").write_text(
            contents
        )

    assert run_entrypoint("worker-healthcheck", entrypoint_env).returncode != 0
    assert not Path(entrypoint_env["UV_CALLS"]).exists()


@pytest.mark.parametrize("exit_code", [1, 69])
def test_healthcheck_propagates_celery_failure(entrypoint_env, exit_code):
    assert run_entrypoint("worker", entrypoint_env).returncode == 0
    entrypoint_env["UV_EXIT"] = str(exit_code)

    assert run_entrypoint("worker-healthcheck", entrypoint_env).returncode == exit_code


def test_worker_does_not_start_when_identity_cannot_be_saved(entrypoint_env):
    (Path(entrypoint_env["TMPDIR"]) / "prowler-worker-nodename").mkdir()

    assert run_entrypoint("worker", entrypoint_env).returncode != 0
    assert not Path(entrypoint_env["UV_CALLS"]).exists()


def test_compose_probes_worker_without_changing_api_liveness():
    compose = yaml.safe_load(
        (ENTRYPOINT.parent.parent / "docker-compose.yml").read_text()
    )
    services = compose["services"]
    assert services["worker"]["healthcheck"]["test"] == [
        "CMD",
        "/home/prowler/docker-entrypoint.sh",
        "worker-healthcheck",
    ]
    assert "/health/live" in " ".join(services["api"]["healthcheck"]["test"])


def test_worker_replaces_identity_symlink_without_overwriting_its_target(
    entrypoint_env,
):
    directory = Path(entrypoint_env["TMPDIR"])
    target = directory / "unrelated"
    target.write_text("keep this content")
    identity = directory / "prowler-worker-nodename"
    identity.symlink_to(target)

    assert run_entrypoint("worker", entrypoint_env).returncode == 0
    assert not identity.is_symlink()
    assert target.read_text() == "keep this content"
    assert run_entrypoint("worker-healthcheck", entrypoint_env).returncode == 0
