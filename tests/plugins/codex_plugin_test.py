import json
import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CODEX_PLUGIN_ROOT = REPOSITORY_ROOT / "codex_plugins" / "prowler"
CLAUDE_SKILL = (
    REPOSITORY_ROOT
    / "claude_plugins"
    / "prowler"
    / "skills"
    / "framework-compliance-triage"
    / "SKILL.md"
)
CODEX_SKILL = CODEX_PLUGIN_ROOT / "skills" / "framework-compliance-triage" / "SKILL.md"
CODEX_POST_FIX_VERIFICATION_FAILURE_SAFETY_SENTENCE = (
    "On post-fix verification failure, record the failure in the activity log and set "
    "the requirement status back to `[FAIL]` so the next loop can retry or choose another remediation."
)


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def normalize_skill_runtime_identity(content: str) -> str:
    """Normalize intentional Codex-only runtime differences."""
    content = re.sub(
        r"^name: prowler-framework-compliance-triage$",
        "name: framework-compliance-triage",
        content,
        count=1,
        flags=re.MULTILINE,
    )
    content = content.replace(
        "stored at `.prowler/compliance-<compliance_id>-<provider_uid>.md` "
        "relative to the current project root.",
        "stored at `${CLAUDE_PROJECT_DIR}/.prowler/compliance-<compliance_id>-<provider_uid>.md`.",
    )
    return content.replace(
        f" {CODEX_POST_FIX_VERIFICATION_FAILURE_SAFETY_SENTENCE}", ""
    )


class TestCodexPluginPackaging(unittest.TestCase):
    def test_marketplace_and_plugin_package_match_the_codex_contract(self):
        marketplace = load_json(REPOSITORY_ROOT / ".agents/plugins/marketplace.json")
        plugin = load_json(CODEX_PLUGIN_ROOT / ".codex-plugin/plugin.json")
        mcp = load_json(CODEX_PLUGIN_ROOT / ".mcp.json")

        self.assertEqual(marketplace["name"], "prowler-plugins")
        self.assertEqual(len(marketplace["plugins"]), 1)
        self.assertEqual(marketplace["plugins"][0]["name"], "prowler")
        self.assertEqual(
            marketplace["plugins"][0]["source"],
            {"source": "local", "path": "./codex_plugins/prowler"},
        )
        self.assertNotIn("installation", marketplace["plugins"][0].get("policy", {}))

        self.assertEqual(plugin["name"], "prowler")
        self.assertEqual(plugin["version"], "0.1.0")
        self.assertEqual(plugin["license"], "Apache-2.0")
        self.assertEqual(plugin["skills"], "./skills/")
        self.assertEqual(plugin["mcpServers"], "./.mcp.json")

        self.assertEqual(
            mcp["mcpServers"]["prowler"],
            {
                "type": "http",
                "url": "https://mcp.prowler.com/mcp",
                "bearer_token_env_var": "PROWLER_API_KEY",
                "headers": {"User-Agent": "codex"},
            },
        )
        self.assertTrue((CODEX_PLUGIN_ROOT / "README.md").is_file())

    def test_readme_requires_a_raw_api_key_without_bearer_prefix(self):
        readme = (CODEX_PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn(
            "Set `PROWLER_API_KEY` to the raw API key only, without the `Bearer` prefix. "
            "Codex adds the bearer prefix automatically.",
            readme,
        )

    def test_framework_compliance_skill_preserves_claude_behavior(self):
        claude_skill = CLAUDE_SKILL.read_text(encoding="utf-8")
        codex_skill = CODEX_SKILL.read_text(encoding="utf-8")

        self.assertNotIn("CLAUDE_PROJECT_DIR", codex_skill)
        self.assertIn(
            "stored at `.prowler/compliance-<compliance_id>-<provider_uid>.md` "
            "relative to the current project root.",
            codex_skill,
        )
        self.assertIn(CODEX_POST_FIX_VERIFICATION_FAILURE_SAFETY_SENTENCE, codex_skill)
        self.assertEqual(
            normalize_skill_runtime_identity(codex_skill),
            claude_skill,
        )


if __name__ == "__main__":
    unittest.main()
