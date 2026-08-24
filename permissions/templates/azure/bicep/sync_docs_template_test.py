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

    def test_sync_normalizes_canonical_and_asset_to_one_trailing_lf(self):
        for terminal_newlines in (b"", b"\n", b"\n\n", b"\r\n\r\n"):
            with self.subTest(terminal_newlines=terminal_newlines):
                self.source.write_bytes(self.canonical + terminal_newlines)

                result = self.run_script("--sync")

                self.assertEqual(result.returncode, 0, result.stderr)
                expected = self.canonical + b"\n"
                self.assertEqual(self.source.read_bytes(), expected)
                self.assertEqual(self.asset.read_bytes(), expected)

    def test_sync_normalizes_snippet_fence_and_final_lf(self):
        for terminal_newlines in (b"", b"\n", b"\n\n", b"\r\n\r\n"):
            with self.subTest(terminal_newlines=terminal_newlines):
                self.source.write_bytes(self.canonical + terminal_newlines)

                result = self.run_script("--sync")

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(
                    self.snippet.read_bytes().endswith(self.canonical + b"\n```\n")
                )

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
