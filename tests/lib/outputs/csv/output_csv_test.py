import unittest
from datetime import datetime
from io import StringIO
from unittest.mock import Mock

from prowler.lib.outputs.common_models import CSV, Finding, Output, Severity, Status


class TestOutputCSV(unittest.TestCase):

    def setUp(self):
        self.finding_example = Finding(
            auth_method="OAuth",
            timestamp=datetime.now(),
            account_uid="12345",
            account_name="Example Account",
            account_email="example@example.com",
            account_organization_uid="org-123",
            account_organization_name="Example Org",
            account_tags=["tag1", "tag2"],
            finding_uid="finding-123",
            provider="AWS",
            check_id="check-123",
            check_title="Example Check",
            check_type="Security",
            status=Status("FAIL"),
            status_extended="Extended status",
            muted=False,
            service_name="Example Service",
            subservice_name="Example Subservice",
            severity=Severity("critical"),
            resource_type="Instance",
            resource_uid="resource-123",
            resource_name="Example Resource",
            resource_details="Detailed information about the resource",
            resource_tags="tag1,tag2",
            partition="aws",
            region="us-west-1",
            description="Description of the finding",
            risk="High",
            related_url="http://example.com",
            remediation_recommendation_text="Recommendation text",
            remediation_recommendation_url="http://example.com/remediation",
            remediation_code_nativeiac="native-iac-code",
            remediation_code_terraform="terraform-code",
            remediation_code_cli="cli-code",
            remediation_code_other="other-code",
            compliance={"compliance_key": "compliance_value"},
            categories="category1,category2",
            depends_on="dependency",
            related_to="related finding",
            notes="Notes about the finding",
            prowler_version=".0",
        )

    def test_output_transform(self):
        output = CSV(self.finding_example)
        self.assertIsInstance(output, Output)
        self.assertIsInstance(output.data, dict)
        self.assertIsInstance(output.data["timestamp"], datetime)
        self.assertIsInstance(output.data["status"], Status)
        self.assertIsInstance(output.data["severity"], Severity)
        self.assertIsInstance(output.data["muted"], bool)
        self.assertIsInstance(output.data["risk"], str)
        self.assertIsInstance(output.data["compliance"], str)
        self.assertIsInstance(output.data["categories"], str)
        self.assertIsInstance(output.data["account_tags"], str)
        self.assertIn("auth_method", output.data)
        self.assertIn("account_uid", output.data)
        self.assertIn("account_name", output.data)
        self.assertIn("account_email", output.data)
        self.assertIn("account_organization_uid", output.data)
        self.assertIn("account_organization_name", output.data)
        self.assertIn("account_tags", output.data)
        self.assertIn("finding_uid", output.data)
        self.assertIn("provider", output.data)
        self.assertIn("check_id", output.data)
        self.assertIn("check_title", output.data)
        self.assertIn("check_type", output.data)
        self.assertIn("status", output.data)
        self.assertIn("status_extended", output.data)
        self.assertIn("muted", output.data)
        self.assertIn("service_name", output.data)
        self.assertIn("subservice_name", output.data)
        self.assertIn("severity", output.data)
        self.assertIn("resource_type", output.data)
        self.assertIn("resource_uid", output.data)
        self.assertIn("resource_name", output.data)
        self.assertIn("resource_details", output.data)
        self.assertIn("resource_tags", output.data)
        self.assertIn("partition", output.data)
        self.assertIn("region", output.data)
        self.assertIn("description", output.data)
        self.assertIn("risk", output.data)
        self.assertIn("related_url", output.data)
        self.assertIn("remediation_recommendation_text", output.data)
        self.assertIn("remediation_recommendation_url", output.data)
        self.assertIn("remediation_code_nativeiac", output.data)
        self.assertIn("remediation_code_terraform", output.data)
        self.assertIn("remediation_code_cli", output.data)
        self.assertIn("remediation_code_other", output.data)
        self.assertIn("compliance", output.data)
        self.assertIn("categories", output.data)
        self.assertIn("depends_on", output.data)
        self.assertIn("related_to", output.data)
        self.assertIn("notes", output.data)
        self.assertIn("prowler_version", output.data)

    def test_csv_write_to_file(self):
        output = CSV(self.finding_example)
        mock_file = StringIO()
        output.write_to_file(mock_file)

        mock_file.seek(0)
        content = mock_file.readlines()
        self.assertGreater(len(content), 0)
        self.assertIn("OAuth", content[0])
        self.assertIn("12345", content[0])
        self.assertIn("Example Account", content[0])
        self.assertIn("example@example.com", content[0])
        self.assertIn("org-123", content[0])
        self.assertIn("Example Org", content[0])
        self.assertIn("tag1,tag2", content[0])
        self.assertIn("finding-123", content[0])
        self.assertIn("AWS", content[0])
        self.assertIn("check-123", content[0])
        self.assertIn("Example Check", content[0])
        self.assertIn("Security", content[0])
        self.assertIn("FAIL", content[0])
        self.assertIn("Extended status", content[0])
        self.assertIn("False", content[0])
        self.assertIn("Example Service", content[0])
        self.assertIn("Example Subservice", content[0])
        self.assertIn("critical", content[0])
        self.assertIn("Instance", content[0])
        self.assertIn("resource-123", content[0])
        self.assertIn("Example Resource", content[0])
        self.assertIn("Detailed information about the resource", content[0])
        self.assertIn("tag1,tag2", content[0])
        self.assertIn("aws", content[0])
        self.assertIn("us-west-1", content[0])
        self.assertIn("Description of the finding", content[0])
        self.assertIn("High", content[0])
        self.assertIn("http://example.com", content[0])
        self.assertIn("Recommendation text", content[0])
        self.assertIn("http://example.com/remediation", content[0])
        self.assertIn("native-iac-code", content[0])
        self.assertIn("terraform-code", content[0])
        self.assertIn("cli-code", content[0])
        self.assertIn("other-code", content[0])
        self.assertIn("compliance_key", content[0])
        self.assertIn("category1,category2", content[0])
        self.assertIn("dependency", content[0])
        self.assertIn("related finding", content[0])
        self.assertIn("Notes about the finding", content[0])

    def test_abstract_methods(self):
        class DummyOutput(Output):
            def transform(self, finding: Finding):
                pass

        dummy_output = DummyOutput(self.finding_example)
        with self.assertRaises(NotImplementedError):
            dummy_output.write_to_file(Mock())
