import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_CHANGELOG_TYPE_ORDER = [
    "added",
    "changed",
    "deprecated",
    "removed",
    "fixed",
    "security",
]
EXPECTED_CHANGELOG_SECTION_NAMES = [
    "🚀 Added",
    "🔄 Changed",
    "⚠️ Deprecated",
    "❌ Removed",
    "🐞 Fixed",
    "🔐 Security",
]
COMPONENTS = ["prowler", "api", "ui", "mcp_server"]


def read_workflow(name):
    return (REPO_ROOT / ".github" / "workflows" / name).read_text()


def render_towncrier(tmp_path, type_definitions, fragments):
    pytest.importorskip("towncrier")

    fragments_dir = tmp_path / "changelog.d"
    fragments_dir.mkdir()
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n<!-- changelog: release notes start -->\n"
    )
    for filename, content in fragments.items():
        (fragments_dir / filename).write_text(f"{content}\n")

    type_config = "\n".join(
        "\n".join(
            [
                "[[tool.towncrier.type]]",
                f'directory = "{directory}"',
                f'name = "{name}"',
                "showcontent = true",
            ]
        )
        for directory, name in type_definitions
    )
    config = "\n".join(
        [
            "[tool.towncrier]",
            'directory = "changelog.d"',
            'filename = "CHANGELOG.md"',
            'start_string = "<!-- changelog: release notes start -->\\n"',
            f'template = "{(REPO_ROOT / ".github/towncrier/template.md.jinja").as_posix()}"',
            'title_format = "## [{version}] ({name})"',
            'issue_format = "[(#{issue})](https://example.com/pull/{issue})"',
            'underlines = ["", "", ""]',
            type_config,
        ]
    )
    config_path = tmp_path / "towncrier.toml"
    config_path.write_text(config)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "towncrier",
            "build",
            "--config",
            str(config_path),
            "--version",
            "0.1.0",
            "--name",
            "Test",
            "--draft",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.split("## [0.1.0] (Test)", 1)[1]


def test_towncrier_template_uses_configured_changelog_section_order(tmp_path):
    template = (REPO_ROOT / ".github/towncrier/template.md.jinja").read_text()

    assert "{% set category_order = definitions.keys() %}" in template
    assert (
        "{% for category in category_order if category in sections[section] %}"
        in template
    )
    assert "definitions.items()" not in template
    assert (
        '["added", "changed", "deprecated", "removed", "fixed", "security"]'
        not in template
    )

    output = render_towncrier(
        tmp_path,
        [("fixed", "Fixed"), ("added", "Added"), ("custom", "Custom")],
        {
            "1.added.md": "Entry one",
            "2.added.md": "Entry two",
            "3.fixed.md": "Fix entry",
            "4.custom.md": "Custom entry",
        },
    )

    headings = re.findall(r"^### (.+)$", output, re.MULTILINE)
    assert headings == ["Fixed", "Added", "Custom"]
    assert (
        "- Entry one [(#1)](https://example.com/pull/1)\n"
        "- Entry two [(#2)](https://example.com/pull/2)"
    ) in output
    assert (
        "- Entry one [(#1)](https://example.com/pull/1)\n\n"
        "- Entry two [(#2)](https://example.com/pull/2)"
    ) not in output


def test_component_towncrier_configs_keep_changelog_section_order():
    for component in COMPONENTS:
        config = tomllib.loads((REPO_ROOT / component / "towncrier.toml").read_text())
        type_definitions = config["tool"]["towncrier"]["type"]

        assert [item["directory"] for item in type_definitions] == (
            EXPECTED_CHANGELOG_TYPE_ORDER
        )
        assert [item["name"] for item in type_definitions] == (
            EXPECTED_CHANGELOG_SECTION_NAMES
        )


def test_pull_request_template_links_to_all_fragment_locations():
    template = (REPO_ROOT / ".github/pull_request_template.md").read_text()

    assert "[Prowler Community Slack](https://goto.prowler.com/slack)" in template
    assert "[Prowler Community Slack](goto.prowler.com/slack)" not in template
    for component in COMPONENTS:
        assert f"{component}/changelog.d/" in template


def test_changelog_gate_rejects_direct_changelog_edits():
    workflow = read_workflow("pr-check-changelog.yml")
    has_update = re.search(
        r"(?ms)^\s*has_changelog_update\(\) \{\n(?P<body>.*?)^\s*\}\n",
        workflow,
    )

    assert has_update is not None
    assert "CHANGELOG.md" not in has_update.group("body")
    assert "handwritten_changelogs" in workflow
    assert "Direct CHANGELOG.md edits are not allowed" in workflow
    assert "direct CHANGELOG.md edit" not in workflow


def test_changelog_gate_tests_compile_workflow_changes():
    workflow = read_workflow("pr-check-changelog.yml")

    assert ".github/workflows/compile-changelogs.yml" in workflow


def test_changelog_attribution_tests_use_pinned_python():
    workflow = read_workflow("pr-check-changelog.yml")
    match = re.search(
        r"(?ms)^  test-changelog-attribution:\n(?P<body>.*?)^  check-changelog:",
        workflow,
    )

    assert match is not None
    job = match.group("body")
    assert "uses: actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c" in job
    assert "python-version: '3.12'" in job
    assert "python3 -m pip install" in job
    assert "python3 -m pytest tests/github" in job
    assert "objects.githubusercontent.com:443" in job


def test_changelog_gate_rejects_common_manual_pr_link_forms():
    workflow = read_workflow("pr-check-changelog.yml")

    assert "manual_pr_link_re=" in workflow
    assert r"\[\(#[0-9]+\)\]" in workflow
    assert r"\[#[0-9]+\]\(" in workflow
    assert r"\(#[0-9]+\)" in workflow
    assert r"github\.com/[^[:space:]/]+/[^[:space:]/]+/(pull|issues)/[0-9]+" in workflow


def test_changelog_gate_derives_fragment_paths_from_monitored_folders():
    workflow = read_workflow("pr-check-changelog.yml")

    assert "folder_alt=$(echo \"$MONITORED_FOLDERS\" | tr ' ' '|')" in workflow
    assert "^(api|ui|prowler|mcp_server)/changelog\\.d/" not in workflow


def test_changelog_gate_lints_renamed_fragments():
    workflow = read_workflow("pr-check-changelog.yml")

    assert "STEPS_CHANGED_FILES_OUTPUTS_RENAMED_FILES" in workflow
    assert "${{ steps.changed-files.outputs.renamed_files }}" in workflow
    assert "added_or_renamed=" in workflow
    assert "added_modified_or_renamed=" in workflow
    assert (
        'echo "$added_or_renamed" | grep -E "^(${folder_alt})/changelog\\.d/"'
        in workflow
    )
    assert (
        'echo "$added_modified_or_renamed" | grep -E "^(${folder_alt})/changelog\\.d/"'
        in workflow
    )


def test_changelog_gate_uses_random_github_output_delimiters():
    workflow = read_workflow("pr-check-changelog.yml")

    assert "write_multiline_output()" in workflow
    assert "openssl rand -hex 16" in workflow
    assert '>> "$GITHUB_OUTPUT"' in workflow
    assert "<<EOF" not in workflow


def test_compile_workflow_blocks_egress_for_privileged_job():
    workflow = read_workflow("compile-changelogs.yml")

    assert "Harden the runner (Block outbound calls)" in workflow
    assert "egress-policy: block" in workflow
    for endpoint in [
        "api.github.com:443",
        "github.com:443",
        "objects.githubusercontent.com:443",
        "pypi.org:443",
        "files.pythonhosted.org:443",
    ]:
        assert endpoint in workflow


def test_forward_sync_inserts_release_blocks_by_prowler_version_order():
    workflow = read_workflow("compile-changelogs.yml")

    assert "insert_changelog_block_ordered()" in workflow
    assert 'incoming_release=$(release_from_heading "$incoming_heading")' in workflow
    assert 'incoming_key=$(version_key "$incoming_release")' in workflow
    assert '[[ "$incoming_key" > "$existing_key" ]]' in workflow
    assert "already contains a block for Prowler v${incoming_release}" in workflow
    assert 'head -n "$marker_line" "$component/CHANGELOG.md"' not in workflow


def test_compile_workflow_rejects_explicit_versions_that_do_not_bump():
    workflow = read_workflow("compile-changelogs.yml")

    assert 'current=$(latest_released_version "$component")' in workflow
    assert 'current_key=$(version_key "$current")' in workflow
    assert 'effective_key=$(version_key "$effective")' in workflow
    assert (
        '[[ "$effective_key" < "$current_key" || "$effective_key" == "$current_key" ]]'
        in workflow
    )
    assert (
        "explicit version '${effective}' must be greater than the latest released version"
        in workflow
    )


def test_compile_workflow_requires_target_branch_to_match_prowler_version():
    workflow = read_workflow("compile-changelogs.yml")

    assert (
        'IFS=. read -r prowler_major prowler_minor prowler_patch <<< "$PROWLER_VERSION"'
        in workflow
    )
    assert "prowler_patch=$((10#$prowler_patch))" in workflow
    assert 'if [ "$prowler_patch" -eq 0 ]; then' in workflow
    assert "target_branch must be 'master' for Prowler ${PROWLER_VERSION}" in workflow
    assert 'expected_target_branch="v${prowler_major}.${prowler_minor}"' in workflow
    assert 'if [ "$TARGET_BRANCH" != "$expected_target_branch" ]; then' in workflow
    assert (
        "target_branch must be '${expected_target_branch}' for Prowler ${PROWLER_VERSION}"
        in workflow
    )


def test_compile_workflow_normalizes_version_segments_before_arithmetic():
    workflow = read_workflow("compile-changelogs.yml")

    assert (
        'printf \'%06d.%06d.%06d\' "$((10#$major))" "$((10#$minor))" "$((10#$patch))"'
        in workflow
    )
    assert "major=$((10#$major))" in workflow
    assert "minor=$((10#$minor))" in workflow
    assert "patch=$((10#$patch))" in workflow
    assert "current_major=$((10#$current_major))" in workflow
    assert "effective_major=$((10#$effective_major))" in workflow
    assert "effective_minor=$((10#$effective_minor))" in workflow
    assert "effective_patch=$((10#$effective_patch))" in workflow


def test_compile_workflow_requires_removed_fragments_in_major_releases():
    workflow = read_workflow("compile-changelogs.yml")

    assert "has_removed_fragments" in workflow
    assert "removed fragments require a major component release" in workflow
    assert "effective_major" in workflow
    assert "effective_minor" in workflow
    assert "effective_patch" in workflow
