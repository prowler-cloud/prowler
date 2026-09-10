from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/api-tests.yml"


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

    return lines[start:end]


def test_codecov_configuration_changes_run_api_tests():
    workflow = WORKFLOW_PATH.read_text()
    changed_files_step = _indented_block(
        workflow, "      - name: Check for API changes"
    )
    files = _indented_block("\n".join(changed_files_step), "          files: |")

    assert "codecov.yml" in {line.strip() for line in files[1:]}
