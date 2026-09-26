import io
import json
import sys
import unittest
import uuid
from pathlib import Path

import jsonschema
import jsonschema._keywords
import regex

_prowler_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_prowler_root) not in sys.path:
    sys.path.insert(0, str(_prowler_root))

from prowler.lib.outputs.oscal.oscal import OSCAL
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

# jsonschema's `pattern` keyword calls re.search() directly; the official
# OSCAL schema uses \p{L}/\p{N} Unicode property escapes (valid ECMA-262
# regex) that Python's stdlib `re` does not support. `regex` does.
jsonschema._keywords.re = regex

_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "oscal_assessment-results_schema_1.2.3.json"
)
_OSCAL_AR_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


class TestOscalOutput(unittest.TestCase):
    def setUp(self):
        self.finding_pass = generate_finding_output(
            status="PASS",
            status_extended="Bucket mybucket has default encryption enabled.",
            service_name="s3",
            check_id="s3_bucket_default_encryption",
            check_title="S3 Buckets have default encryption enabled",
            resource_uid="arn:aws:s3:::mybucket",
            resource_name="mybucket",
            region="us-east-1",
            compliance={"NIST-800-53-R5": ["SC-13", "SC-28"]},
            remediation_recommendation_text="Enable default encryption.",
            muted=False,
        )
        # Distinct uid so observation/finding UUIDs differ from PASS
        self.finding_fail = generate_finding_output(
            status="FAIL",
            status_extended="Bucket mybucket2 does not have default encryption enabled.",
            service_name="s3",
            check_id="s3_bucket_default_encryption",
            check_title="S3 Buckets have default encryption enabled",
            resource_uid="arn:aws:s3:::mybucket2",
            resource_name="mybucket2",
            region="us-east-1",
            compliance={"NIST-800-53-R5": ["SC-13", "SC-28"]},
            remediation_recommendation_text="Enable default encryption.",
            muted=False,
        )
        self.finding_fail = self.finding_fail.copy(
            update={"uid": "test-unique-finding-fail"}
        )

        self.finding_fail_muted = generate_finding_output(
            status="FAIL",
            status_extended="Muted failure for suppressed bucket.",
            service_name="s3",
            check_id="s3_bucket_default_encryption",
            check_title="S3 Buckets have default encryption enabled",
            resource_uid="arn:aws:s3:::mybucket-muted",
            resource_name="mybucket-muted",
            region="us-east-1",
            compliance={"NIST-800-53-R5": ["SC-13"]},
            muted=True,
        )
        self.finding_fail_muted = self.finding_fail_muted.copy(
            update={"uid": "test-unique-finding-muted"}
        )

    def test_oscal_transformation(self):
        exporter = OSCAL(findings=[self.finding_pass, self.finding_fail])
        self.assertEqual(len(exporter.data), 1)

        doc = exporter.data[0]
        results = doc.assessment_results.results
        self.assertEqual(len(results), 1)

        res = results[0]
        self.assertEqual(len(res.observations), 2)
        self.assertEqual(len(res.findings), 1)

        fail_finding = res.findings[0]
        self.assertIn("Non-compliant check", fail_finding.title)
        self.assertEqual(len(fail_finding.related_observations), 1)

        control_props = [p for p in fail_finding.props if p.name == "control-id"]
        control_vals = {p.value for p in control_props}
        self.assertIn("SC-13", control_vals)
        self.assertIn("SC-28", control_vals)

    def test_muted_fail_is_observation_only(self):
        exporter = OSCAL(findings=[self.finding_fail_muted])
        res = exporter.data[0].assessment_results.results[0]
        self.assertEqual(len(res.observations), 1)
        self.assertEqual(len(res.findings), 0)
        muted_prop = next(p for p in res.observations[0].props if p.name == "muted")
        self.assertEqual(muted_prop.value, "true")

    def test_result_uuid_unique_per_export(self):
        a = OSCAL(findings=[self.finding_pass]).data[0].assessment_results.results[0]
        b = OSCAL(findings=[self.finding_pass]).data[0].assessment_results.results[0]
        self.assertNotEqual(a.result_uuid, b.result_uuid)
        uuid.UUID(a.result_uuid)  # raises if not a valid UUID

    def test_oscal_batch_write(self):
        exporter = OSCAL(findings=[self.finding_fail])
        stream = io.StringIO()
        exporter.file_descriptor = stream
        exporter.batch_write_data_to_file()

        raw_json = stream.getvalue()
        self.assertTrue(len(raw_json) > 0)
        parsed = json.loads(raw_json)
        self.assertIn("assessment-results", parsed)
        self.assertEqual(
            parsed["assessment-results"]["metadata"]["oscal-version"], "1.2.3"
        )
        self.assertEqual(
            parsed["assessment-results"]["import-ap"]["href"],
            "urn:prowler:assessment-plan:default",
        )

    def test_oscal_output_validates_against_official_schema_with_fail_finding(self):
        exporter = OSCAL(findings=[self.finding_pass, self.finding_fail])
        doc = exporter.data[0].to_dict()

        validator = jsonschema.Draft7Validator(_OSCAL_AR_SCHEMA)
        errors = list(validator.iter_errors(doc))
        self.assertEqual(
            errors,
            [],
            msg="\n".join(
                f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in errors
            ),
        )

    def test_oscal_output_validates_against_official_schema_pass_only(self):
        """PASS-only run must omit empty `findings` (schema minItems: 1)."""
        exporter = OSCAL(findings=[self.finding_pass])
        doc = exporter.data[0].to_dict()

        result = doc["assessment-results"]["results"][0]
        self.assertNotIn("findings", result)

        validator = jsonschema.Draft7Validator(_OSCAL_AR_SCHEMA)
        errors = list(validator.iter_errors(doc))
        self.assertEqual(
            errors,
            [],
            msg="\n".join(
                f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in errors
            ),
        )

    def test_finding_carries_its_own_uuid_and_a_real_target(self):
        exporter = OSCAL(findings=[self.finding_fail])
        finding = exporter.data[0].assessment_results.results[0].findings[0].to_dict()

        self.assertEqual(
            finding["uuid"],
            exporter.data[0].assessment_results.results[0].findings[0].finding_uuid,
        )
        self.assertNotIn("collected", finding)
        self.assertEqual(finding["target"]["target-id"], "s3_bucket_default_encryption")
        self.assertEqual(finding["target"]["type"], "objective-id")
        self.assertEqual(
            finding["target"]["status"], {"state": "not-satisfied", "reason": "fail"}
        )

    def test_observation_emits_uuid_not_observation_uuid(self):
        exporter = OSCAL(findings=[self.finding_pass])
        observation = (
            exporter.data[0].assessment_results.results[0].observations[0].to_dict()
        )

        self.assertIn("uuid", observation)
        self.assertNotIn("observation-uuid", observation)

    def test_result_always_carries_reviewed_controls(self):
        exporter = OSCAL(findings=[self.finding_pass])
        result = exporter.data[0].assessment_results.results[0].to_dict()

        self.assertIn("reviewed-controls", result)
        self.assertIn("control-selections", result["reviewed-controls"])


if __name__ == "__main__":
    unittest.main()
