from datetime import datetime
from io import StringIO
from unittest.mock import Mock

import pytest

from prowler.lib.outputs.common_models import CSV, Finding, Output, Severity, Status
from prowler.lib.outputs.csv.csv import write_csv


@pytest.fixture
def finding_example():
    return Finding(
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
        prowler_version="1.0",
    )


def test_output_transform(finding_example):
    output = CSV(finding_example)

    assert isinstance(output.data, dict)
    assert isinstance(output.data["timestamp"], datetime)
    assert isinstance(output.data["account_tags"], str)
    assert isinstance(output.data["severity"], str)
    assert isinstance(output.data["status"], str)
    assert isinstance(output.data["muted"], bool)
    assert isinstance(output.data["compliance"], str)

    assert output.data["auth_method"] == "OAuth"
    assert output.data["timestamp"] == finding_example.timestamp
    assert output.data["account_uid"] == "12345"
    assert output.data["account_name"] == "Example Account"
    assert output.data["account_email"] == "example@example.com"
    assert output.data["account_organization_uid"] == "org-123"
    assert output.data["account_organization_name"] == "Example Org"
    assert output.data["account_tags"] == "tag1 | tag2"
    assert output.data["finding_uid"] == "finding-123"
    assert output.data["provider"] == "AWS"
    assert output.data["check_id"] == "check-123"
    assert output.data["check_title"] == "Example Check"
    assert output.data["check_type"] == "Security"
    assert output.data["status"] == "FAIL"
    assert output.data["status_extended"] == "Extended status"
    assert output.data["muted"] is False
    assert output.data["service_name"] == "Example Service"
    assert output.data["subservice_name"] == "Example Subservice"
    assert output.data["severity"] == "critical"
    assert output.data["resource_type"] == "Instance"
    assert output.data["resource_uid"] == "resource-123"
    assert output.data["resource_name"] == "Example Resource"
    assert output.data["resource_details"] == "Detailed information about the resource"
    assert output.data["resource_tags"] == "tag1,tag2"
    assert output.data["partition"] == "aws"
    assert output.data["region"] == "us-west-1"
    assert output.data["description"] == "Description of the finding"
    assert output.data["risk"] == "High"
    assert output.data["related_url"] == "http://example.com"
    assert output.data["remediation_recommendation_text"] == "Recommendation text"
    assert (
        output.data["remediation_recommendation_url"]
        == "http://example.com/remediation"
    )
    assert output.data["remediation_code_nativeiac"] == "native-iac-code"
    assert output.data["remediation_code_terraform"] == "terraform-code"
    assert output.data["remediation_code_cli"] == "cli-code"
    assert output.data["remediation_code_other"] == "other-code"
    assert output.data["compliance"] == "compliance_key: compliance_value"
    assert output.data["categories"] == "category1,category2"
    assert output.data["depends_on"] == "dependency"
    assert output.data["related_to"] == "related finding"
    assert output.data["notes"] == "Notes about the finding"
    assert output.data["prowler_version"] == "1.0"


def test_csv_write_to_file(finding_example):
    output = CSV(finding_example)
    mock_file = StringIO()
    output.write_to_file(mock_file)

    mock_file.seek(0)
    content = mock_file.read()

    assert "OAuth" in content
    assert "12345" in content
    assert "Example Account" in content
    assert "example@example.com" in content
    assert "org-123" in content
    assert "Example Org" in content
    assert "tag1 | tag2" in content
    assert "finding-123" in content
    assert "AWS" in content
    assert "check-123" in content
    assert "Example Check" in content
    assert "Security" in content
    assert "FAIL" in content
    assert "Extended status" in content
    assert "False" in content
    assert "Example Service" in content
    assert "Example Subservice" in content
    assert "critical" in content
    assert "Instance" in content
    assert "resource-123" in content
    assert "Example Resource" in content
    assert "Detailed information about the resource" in content
    assert "tag1,tag2" in content
    assert "aws" in content
    assert "us-west-1" in content
    assert "Description of the finding" in content
    assert "High" in content
    assert "http://example.com" in content
    assert "Recommendation text" in content
    assert "http://example.com/remediation" in content
    assert "native-iac-code" in content
    assert "terraform-code" in content
    assert "cli-code" in content
    assert "other-code" in content
    assert "compliance_key: compliance_value" in content
    assert "category1,category2" in content
    assert "dependency" in content
    assert "related finding" in content
    assert "Notes about the finding" in content
    assert "1.0" in content


def test_abstract_methods(finding_example):
    class DummyOutput(Output):
        def transform(self, finding: Finding):
            pass

    dummy_output = DummyOutput(finding_example)
    assert dummy_output.transform(finding_example) is None
    with pytest.raises(NotImplementedError):
        dummy_output.write_to_file(Mock())


class TestWriteCSV:

    def test_write_csv_with_dict(self):
        headers = ["provider", "account", "check_id"]
        row = {"provider": "aws", "account": "account_try", "check_id": "account_check"}
        mock_file = StringIO()

        write_csv(mock_file, headers, row)

        mock_file.seek(0)
        content = mock_file.read()
        assert "aws;account_try;account_check" in content

    def test_write_csv_with_object(self):
        class Row:
            def __init__(self, provider, account, check_id):
                self.provider = provider
                self.account = account
                self.check_id = check_id

        headers = ["provider", "account", "check_id"]
        row = Row("aws", "account_try", "account_check")
        mock_file = StringIO()

        write_csv(mock_file, headers, row)

        mock_file.seek(0)
        content = mock_file.read()
        assert "aws;account_try;account_check" in content
