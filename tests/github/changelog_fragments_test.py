import re
import tomllib
from pathlib import Path

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


def test_towncrier_template_uses_explicit_changelog_section_order():
    template = (REPO_ROOT / ".github/towncrier/template.md.jinja").read_text()

    assert (
        "{% for category in category_order if category in sections[section] %}"
        in template
    )
    assert "definitions.items()" not in template

    order_match = re.search(r"category_order = \[(?P<items>[^\]]+)\]", template)
    assert order_match is not None

    actual_order = re.findall(r'"([^"]+)"', order_match.group("items"))
    assert actual_order == EXPECTED_CHANGELOG_TYPE_ORDER


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


def test_changelog_gate_rejects_common_manual_pr_link_forms():
    workflow = read_workflow("pr-check-changelog.yml")

    assert "manual_pr_link_re=" in workflow
    assert r"\[\(#[0-9]+\)\]" in workflow
    assert r"\[#[0-9]+\]\(" in workflow
    assert r"\(#[0-9]+\)" in workflow
    assert r"github\.com/prowler-cloud/prowler/(pull|issues)/[0-9]+" in workflow


def test_compile_workflow_requires_removed_fragments_in_major_releases():
    workflow = read_workflow("compile-changelogs.yml")

    assert "has_removed_fragments" in workflow
    assert "removed fragments require a major component release" in workflow
    assert "effective_major" in workflow
    assert "effective_minor" in workflow
    assert "effective_patch" in workflow
