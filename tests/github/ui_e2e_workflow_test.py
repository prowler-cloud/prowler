from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/ui-e2e-tests-v2.yml"
NODE_IMAGE_DIGEST = (
    "sha256:d1b3b4da11eefd5941e7f0b9cf17783fc99d9c6fc34884a665f40a06dbdfc94f"
)


def _jobs():
    with WORKFLOW_PATH.open() as workflow_file:
        return yaml.safe_load(workflow_file)["jobs"]


def _normalize(expression):
    return " ".join(expression.split())


def test_fork_pull_requests_use_explicit_skip_route():
    jobs = _jobs()
    fork_job = jobs["fork-e2e-unavailable"]

    assert _normalize(jobs["e2e-tests"]["if"]) == (
        "github.repository == 'prowler-cloud/prowler' && "
        "(github.event_name != 'pull_request' || "
        "github.event.pull_request.head.repo.fork == false) && "
        "(needs.impact-analysis.outputs.has-ui-e2e == 'true' || "
        "needs.impact-analysis.outputs.run-all == 'true')"
    )
    assert _normalize(fork_job["if"]) == (
        "github.repository == 'prowler-cloud/prowler' && "
        "github.event_name == 'pull_request' && "
        "github.event.pull_request.head.repo.fork == true && "
        "(needs.impact-analysis.outputs.has-ui-e2e == 'true' || "
        "needs.impact-analysis.outputs.run-all == 'true')"
    )
    assert fork_job["permissions"] == {"contents": "read"}

    reporting_step = next(
        step
        for step in fork_job["steps"]
        if step["name"] == "Report unavailable E2E tests"
    )
    assert "GITHUB_STEP_SUMMARY" in reporting_step["run"]
    assert (
        "UI E2E tests require repository secrets and cannot run for fork pull requests."
        in reporting_step["run"]
    )

    prerequisite_step = next(
        step
        for step in jobs["e2e-tests"]["steps"]
        if step["name"] == "Validate E2E prerequisites"
    )
    assert "IS_FORK_PR" not in prerequisite_step.get("env", {})
    assert "IS_FORK_PR" not in prerequisite_step["run"]
    assert "exit 0" not in prerequisite_step["run"]


def test_docker_node_image_matches_nvmrc():
    node_version = (REPOSITORY_ROOT / "ui/.nvmrc").read_text().strip()
    dockerfile = (REPOSITORY_ROOT / "ui/Dockerfile").read_text()

    assert f"FROM node:{node_version}-alpine@{NODE_IMAGE_DIGEST} AS base" in dockerfile
