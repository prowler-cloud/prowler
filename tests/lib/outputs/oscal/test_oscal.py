import io
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import jsonschema._keywords
import regex

# Add prowler path to sys.path
_prowler_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_prowler_root) not in sys.path:
    sys.path.insert(0, str(_prowler_root))

from prowler.lib.outputs.oscal.oscal import OSCAL

# jsonschema's `pattern` keyword calls re.search() directly; the official
# OSCAL schema uses \p{L}/\p{N} Unicode property escapes (valid ECMA-262
# regex, per the JSON Schema spec's default dialect) that Python's stdlib
# `re` module does not support. `regex` is a compatible drop-in that does.
jsonschema._keywords.re = regex

_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "oscal_assessment-results_schema_1.2.3.json"
)
_OSCAL_AR_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


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
        self.assertEqual(
            parsed["assessment-results"]["metadata"]["oscal-version"], "1.2.3"
        )
        self.assertEqual(
            parsed["assessment-results"]["import-ap"]["href"],
            "urn:prowler:assessment-plan:default",
        )

    # ---- Schema validation: json.loads() only confirms syntactically valid
    # JSON, not that it's a schema-valid OSCAL document (a document can pass
    # json.loads() while violating required fields, using wrong property
    # names, or including properties the schema forbids). These tests
    # validate the actual serialized output against the pinned, official
    # NIST OSCAL 1.2.3 assessment-results schema (fixtures/).

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
        """A PASS-only run produces zero OscalFindings; `findings` and
        `observations` both have schema minItems: 1, so the arrays must be
        omitted entirely rather than emitted empty -- this specifically
        exercises that path."""
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
        self.assertNotIn(
            "collected", finding
        )  # not a valid `finding` property in OSCAL
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
