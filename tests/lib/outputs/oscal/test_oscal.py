import io
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

# Add prowler path to sys.path
_prowler_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_prowler_root) not in sys.path:
    sys.path.insert(0, str(_prowler_root))

from prowler.lib.outputs.oscal.oscal import OSCAL


class TestOscalOutput(unittest.TestCase):
    def setUp(self):
        self.meta_pass = SimpleNamespace(
            Provider="aws",
            CheckID="s3_bucket_default_encryption",
            CheckTitle="S3 Buckets have default encryption enabled",
            Severity=SimpleNamespace(value="high"),
            Remediation=SimpleNamespace(
                Recommendation=SimpleNamespace(
                    Text="Enable default encryption.",
                )
            ),
        )

        self.finding_pass = SimpleNamespace(
            auth_method="role",
            timestamp=datetime.now(timezone.utc),
            account_uid="123456789012",
            metadata=self.meta_pass,
            uid="prowler-aws-s3_bucket_default_encryption-123456789012-us-east-1-mybucket-pass",
            status=SimpleNamespace(value="PASS"),
            status_extended="Bucket mybucket has default encryption enabled.",
            muted=False,
            resource_uid="arn:aws:s3:::mybucket",
            resource_name="mybucket",
            resource_details="AES256",
            region="us-east-1",
            compliance={"NIST-800-53-R5": ["SC-13", "SC-28"]},
            prowler_version="4.0.0",
        )

        self.finding_fail = SimpleNamespace(
            auth_method="role",
            timestamp=datetime.now(timezone.utc),
            account_uid="123456789012",
            metadata=self.meta_pass,
            uid="prowler-aws-s3_bucket_default_encryption-123456789012-us-east-1-mybucket-fail",
            status=SimpleNamespace(value="FAIL"),
            status_extended="Bucket mybucket does not have default encryption enabled.",
            muted=False,
            resource_uid="arn:aws:s3:::mybucket2",
            resource_name="mybucket2",
            resource_details="None",
            region="us-east-1",
            compliance={"NIST-800-53-R5": ["SC-13", "SC-28"]},
            prowler_version="4.0.0",
        )

    def test_oscal_transformation(self):
        exporter = OSCAL(findings=[self.finding_pass, self.finding_fail])
        self.assertEqual(len(exporter.data), 1)

        doc = exporter.data[0]
        results = doc.assessment_results.results
        self.assertEqual(len(results), 1)

        res = results[0]
        # Both PASS and FAIL become observations
        self.assertEqual(len(res.observations), 2)
        # Only FAIL becomes an OSCAL finding
        self.assertEqual(len(res.findings), 1)

        fail_finding = res.findings[0]
        self.assertIn("Non-compliant check", fail_finding.title)
        self.assertEqual(len(fail_finding.related_observations), 1)

        # Check NIST controls
        control_props = [p for p in fail_finding.props if p.name == "control-id"]
        control_vals = {p.value for p in control_props}
        self.assertIn("SC-13", control_vals)
        self.assertIn("SC-28", control_vals)

    def test_oscal_batch_write(self):
        exporter = OSCAL(findings=[self.finding_fail])
        stream = io.StringIO()
        exporter.file_descriptor = stream
        exporter.batch_write_data_to_file()

        raw_json = stream.getvalue()
        self.assertTrue(len(raw_json) > 0)
        parsed = json.loads(raw_json)
        self.assertIn("assessment-results", parsed)
        self.assertEqual(parsed["assessment-results"]["metadata"]["oscal-version"], "1.2.3")
        self.assertEqual(parsed["assessment-results"]["import-ap"]["href"], "urn:prowler:assessment-plan:default")


if __name__ == "__main__":
    unittest.main()
