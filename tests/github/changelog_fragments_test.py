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
