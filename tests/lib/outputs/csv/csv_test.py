import tempfile
from datetime import datetime
from io import StringIO, TextIOWrapper
from typing import List
from unittest.mock import MagicMock

import pytest

from prowler.lib.outputs.csv.csv import write_csv
from prowler.lib.outputs.csv.models import CSV
from prowler.lib.outputs.finding import Finding, Severity, Status
from prowler.lib.outputs.output import Output


@pytest.fixture
def generate_finding():
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
        provider="aws",
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


class TestCSV:

    def test_output_transform(self, generate_finding):
        findings = [generate_finding]

        # Clear the data from CSV class
        CSV._data = []

        output = CSV(findings)
        output_data = output.data[0]
        assert isinstance(output_data, dict)
        assert isinstance(output_data["TIMESTAMP"], datetime)
        assert isinstance(output_data["ACCOUNT_TAGS"], str)
        assert isinstance(output_data["SEVERITY"], str)
        assert isinstance(output_data["STATUS"], str)
        assert isinstance(output_data["MUTED"], bool)
        assert isinstance(output_data["COMPLIANCE"], str)

        assert output_data["AUTH_METHOD"] == "OAuth"
        assert output_data["ACCOUNT_UID"] == "12345"
        assert output_data["ACCOUNT_NAME"] == "Example Account"
        assert output_data["ACCOUNT_EMAIL"] == "example@example.com"
        assert output_data["ACCOUNT_ORGANIZATION_UID"] == "org-123"
        assert output_data["ACCOUNT_ORGANIZATION_NAME"] == "Example Org"
        assert output_data["ACCOUNT_TAGS"] == "tag1 | tag2"
        assert output_data["FINDING_UID"] == "finding-123"
        assert output_data["PROVIDER"] == "aws"
        assert output_data["CHECK_ID"] == "check-123"
        assert output_data["CHECK_TITLE"] == "Example Check"
        assert output_data["CHECK_TYPE"] == "Security"
        assert output_data["STATUS"] == "FAIL"
        assert output_data["STATUS_EXTENDED"] == "Extended status"
        assert output_data["MUTED"] is False
        assert output_data["SERVICE_NAME"] == "Example Service"
        assert output_data["SUBSERVICE_NAME"] == "Example Subservice"
        assert output_data["SEVERITY"] == "critical"
        assert output_data["RESOURCE_TYPE"] == "Instance"
        assert output_data["RESOURCE_UID"] == "resource-123"
        assert output_data["RESOURCE_NAME"] == "Example Resource"
        assert (
            output_data["RESOURCE_DETAILS"] == "Detailed information about the resource"
        )
        assert output_data["RESOURCE_TAGS"] == "tag1,tag2"
        assert output_data["PARTITION"] == "aws"
        assert output_data["REGION"] == "us-west-1"
        assert output_data["DESCRIPTION"] == "Description of the finding"
        assert output_data["RISK"] == "High"
        assert output_data["RELATED_URL"] == "http://example.com"
        assert output_data["REMEDIATION_RECOMMENDATION_TEXT"] == "Recommendation text"
        assert (
            output_data["REMEDIATION_RECOMMENDATION_URL"]
            == "http://example.com/remediation"
        )
        assert output_data["REMEDIATION_CODE_NATIVEIAC"] == "native-iac-code"
        assert output_data["REMEDIATION_CODE_TERRAFORM"] == "terraform-code"
        assert output_data["REMEDIATION_CODE_CLI"] == "cli-code"
        assert output_data["REMEDIATION_CODE_OTHER"] == "other-code"
        assert output_data["COMPLIANCE"] == "compliance_key: compliance_value"
        assert output_data["CATEGORIES"] == "category1,category2"
        assert output_data["DEPENDS_ON"] == "dependency"
        assert output_data["RELATED_TO"] == "related finding"
        assert output_data["NOTES"] == "Notes about the finding"
        assert output_data["PROWLER_VERSION"] == "1.0"

    def test_csv_write_to_file(self, generate_finding):
        mock_file = StringIO()
        findings = [generate_finding]
        # Clear the data from CSV class
        CSV._data = []
        output = CSV(findings)
        output._file_descriptor = mock_file

        output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        content = content.split("PROWLER_VERSION")[1]
        content = content.removeprefix("\r\n")
        content = content.removesuffix("\r\n")
        string = ""
        for value in output.data[0].values():
            string += f"{value};"
        string = string.removesuffix(";")
        assert string in content

    @pytest.fixture
    def mock_output_class(self):
        class MockOutput(Output):
            def transform(self, findings: List[Finding]):
                pass

            def batch_write_data_to_file(self, file_descriptor: TextIOWrapper) -> None:
                pass

        return MockOutput

    def test_abstract_methods_called(self, mock_output_class):
        # Create mocks for the abstract methods
        mock_output_class.transform = MagicMock()
        mock_output_class.batch_write_data_to_file = MagicMock()

        findings = [MagicMock(spec=Finding)]

        # Create a temporary file
        with tempfile.NamedTemporaryFile() as file:
            file_path = file.name

            # Instantiate the mock class
            output_instance = mock_output_class(
                findings, create_file_descriptor=True, file_path=file_path
            )

            # Check that transform was called once
            output_instance.transform.assert_called_once_with(findings)

            # Check that create_file_descriptor was called and the file descriptor was created
            assert output_instance.file_descriptor is not None

            # Check the type
            assert isinstance(output_instance.file_descriptor, TextIOWrapper)

            # Assuming we need to call batch_write_data_to_file for this test
            output_instance.batch_write_data_to_file(output_instance.file_descriptor)

            # Check that batch_write_data_to_file was called once
            output_instance.batch_write_data_to_file.assert_called_once_with(
                output_instance.file_descriptor
            )

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
