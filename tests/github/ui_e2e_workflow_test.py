from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/ui-e2e-tests-v2.yml"
NODE_IMAGE_DIGEST = (
    "sha256:f70403e87646dc51b45295f4b8b70cdad0b63d2297c4c9899119b03f7af7a6b3"
)


def _indented_block(text, heading):
    lines = text.splitlines()
    start = lines.index(heading)
    indentation = len(heading) - len(heading.lstrip())
    end = len(lines)

    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and len(line) - len(line.lstrip()) <= indentation:
            end = index
            break

    return "\n".join(lines[start:end])


def _multiline_value(block, key):
    lines = block.splitlines()
    heading = next(line for line in lines if line.strip() == f"{key}: |")
    value_block = _indented_block(block, heading)
    return "\n".join(value_block.splitlines()[1:])


def _normalize(expression):
    return " ".join(expression.split())


def test_fork_pull_requests_use_explicit_skip_route():
    workflow = WORKFLOW_PATH.read_text()
    e2e_job = _indented_block(workflow, "  e2e-tests:")
    fork_job = _indented_block(workflow, "  fork-e2e-unavailable:")

    assert _normalize(_multiline_value(e2e_job, "if")) == (
        "github.repository == 'prowler-cloud/prowler' && "
        "(github.event_name != 'pull_request' || "
        "github.event.pull_request.head.repo.fork == false) && "
        "(needs.impact-analysis.outputs.has-ui-e2e == 'true' || "
        "needs.impact-analysis.outputs.run-all == 'true')"
    )
    assert _normalize(_multiline_value(fork_job, "if")) == (
        "github.repository == 'prowler-cloud/prowler' && "
        "github.event_name == 'pull_request' && "
        "github.event.pull_request.head.repo.fork == true && "
        "(needs.impact-analysis.outputs.has-ui-e2e == 'true' || "
        "needs.impact-analysis.outputs.run-all == 'true')"
    )
    assert _indented_block(fork_job, "    permissions:") == (
        "    permissions:\n      contents: read"
    )

    reporting_step = _indented_block(
        fork_job, "      - name: Report unavailable E2E tests"
    )
    assert "GITHUB_STEP_SUMMARY" in reporting_step
    assert (
        "UI E2E tests require repository secrets and cannot run for fork pull requests."
        in reporting_step
    )

    prerequisite_step = _indented_block(
        e2e_job, "      - name: Validate E2E prerequisites"
    )
    assert "IS_FORK_PR" not in prerequisite_step
    assert "exit 0" not in prerequisite_step


def test_docker_node_image_matches_nvmrc():
    node_version = (REPOSITORY_ROOT / "ui/.nvmrc").read_text().strip()
    dockerfile = (REPOSITORY_ROOT / "ui/Dockerfile").read_text()

    assert f"FROM node:{node_version}-alpine@{NODE_IMAGE_DIGEST} AS base" in dockerfile
