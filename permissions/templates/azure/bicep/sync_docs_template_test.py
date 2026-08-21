import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("sync_docs_template.py")


class SyncDocsTemplateTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.source = root / "prowler-scan.json"
        self.asset = root / "docs/assets/prowler-scan.json"
        self.snippet = root / "docs/snippets/prowler-scan.mdx"
        self.canonical = b'{"contentVersion":"1.0.0.0"}'
        self.source.write_bytes(self.canonical)

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_script(self, mode):
        return subprocess.run(
            [
                sys.executable,
                SCRIPT,
                mode,
                "--source",
                self.source,
                "--asset",
                self.asset,
                "--snippet",
                self.snippet,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_sync_copies_asset_and_embeds_exact_canonical_bytes(self):
        result = self.run_script("--sync")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.asset.read_bytes(), self.canonical)
        snippet = self.snippet.read_bytes()
        self.assertIn(b"```json\n" + self.canonical + b"\n```", snippet)

    def test_check_fails_when_generated_output_drifts(self):
        self.assertEqual(self.run_script("--sync").returncode, 0)
        self.asset.write_text('{"contentVersion":"stale"}')

        result = self.run_script("--check")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Azure documentation template drift detected", result.stderr)

    def test_check_fails_when_displayed_snippet_drifts(self):
        self.assertEqual(self.run_script("--sync").returncode, 0)
        self.snippet.write_text("```json\n{}\n```\n")

        result = self.run_script("--check")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Azure documentation template drift detected", result.stderr)

    def test_check_fails_when_canonical_template_changes(self):
        self.assertEqual(self.run_script("--sync").returncode, 0)
        self.source.write_text('{"contentVersion":"2.0.0.0"}')

        result = self.run_script("--check")

        self.assertEqual(result.returncode, 1)
        self.assertIn("Azure documentation template drift detected", result.stderr)

    def test_role_assignment_ids_ignore_cosmetic_deployment_label(self):
        template = json.loads(Path(__file__).with_name("prowler-scan.json").read_text())
        role_assignments = [
            resource
            for resource in template["resources"]
            if resource["type"] == "Microsoft.Authorization/roleAssignments"
        ]

        self.assertEqual(len(role_assignments), 2)
        for assignment in role_assignments:
            self.assertNotIn("deploymentLabel", assignment["name"])


if __name__ == "__main__":
    unittest.main()
