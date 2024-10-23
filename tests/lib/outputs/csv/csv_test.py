import tempfile
from datetime import datetime
from io import StringIO, TextIOWrapper
from typing import List
from unittest.mock import MagicMock

import pytest
from freezegun import freeze_time
from mock import patch

from prowler.config.config import prowler_version
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestCSV:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                status="PASS",
                status_extended="status-extended",
                resource_uid="resource-123",
                resource_name="Example Resource",
                resource_details="Detailed information about the resource",
                resource_tags={"tag1": "value1", "tag2": "value2"},
                partition="aws",
                description="Description of the finding",
                risk="High",
                related_url="http://example.com",
                remediation_recommendation_text="Recommendation text",
                remediation_recommendation_url="http://example.com/remediation",
                remediation_code_nativeiac="native-iac-code",
                remediation_code_terraform="terraform-code",
                remediation_code_other="other-code",
                remediation_code_cli="cli-code",
                compliance={"compliance_key": "compliance_value"},
                categories=["categorya", "categoryb"],
                depends_on=["dependency"],
                related_to=["related"],
                notes="Notes about the finding",
            )
        ]

        output = CSV(findings)
        output_data = output.data[0]
        assert isinstance(output_data, dict)
        assert isinstance(output_data["TIMESTAMP"], datetime)

        assert output_data["AUTH_METHOD"] == "profile: default"
        assert output_data["ACCOUNT_UID"] == AWS_ACCOUNT_NUMBER
        assert output_data["ACCOUNT_NAME"] == AWS_ACCOUNT_NUMBER
        assert output_data["ACCOUNT_EMAIL"] == ""
        assert output_data["ACCOUNT_ORGANIZATION_UID"] == "test-organization-id"
        assert output_data["ACCOUNT_ORGANIZATION_NAME"] == "test-organization"
        assert isinstance(output_data["ACCOUNT_TAGS"], str)
        assert output_data["ACCOUNT_TAGS"] == "test-tag:test-value"
        assert output_data["FINDING_UID"] == "test-unique-finding"
        assert output_data["PROVIDER"] == "aws"
        assert output_data["CHECK_ID"] == "test-check-id"
        assert output_data["CHECK_TITLE"] == "test-check-id"
        assert output_data["CHECK_TYPE"] == "test-type"
        assert isinstance(output_data["STATUS"], str)
        assert output_data["STATUS"] == "PASS"
        assert output_data["STATUS_EXTENDED"] == "status-extended"
        assert isinstance(output_data["MUTED"], bool)
        assert output_data["MUTED"] is False
        assert output_data["SERVICE_NAME"] == "test-service"
        assert output_data["SUBSERVICE_NAME"] == ""
        assert isinstance(output_data["SEVERITY"], str)
        assert output_data["SEVERITY"] == "high"
        assert output_data["RESOURCE_TYPE"] == "test-resource"
        assert output_data["RESOURCE_UID"] == "resource-123"
        assert output_data["RESOURCE_NAME"] == "Example Resource"
        assert (
            output_data["RESOURCE_DETAILS"] == "Detailed information about the resource"
        )
        assert output_data["RESOURCE_TAGS"] == "tag1=value1 | tag2=value2"
        assert output_data["PARTITION"] == "aws"
        assert output_data["REGION"] == AWS_REGION_EU_WEST_1
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
        assert isinstance(output_data["COMPLIANCE"], str)
        assert output_data["COMPLIANCE"] == "compliance_key: compliance_value"
        assert output_data["CATEGORIES"] == "categorya | categoryb"
        assert output_data["DEPENDS_ON"] == "dependency"
        assert output_data["RELATED_TO"] == "related"
        assert output_data["NOTES"] == "Notes about the finding"
        assert output_data["PROWLER_VERSION"] == prowler_version

    @freeze_time(datetime.now())
    def test_csv_write_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output()]

        output = CSV(findings)
        output._file_descriptor = mock_file

        # We don't want to close the file to read it later
        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        expected_csv = f"AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_EMAIL;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION\r\nprofile: default;{datetime.now()};123456789012;123456789012;;test-organization-id;test-organization;test-tag:test-value;test-unique-finding;aws;test-check-id;test-check-id;test-type;PASS;;False;test-service;;high;test-resource;;;;;aws;eu-west-1;check description;test-risk;test-url;;;;;;;test-compliance: test-compliance;test-category;test-dependency;test-related-to;test-notes;{prowler_version}\r\n"
        content = mock_file.read()

        assert content == expected_csv

    def test_batch_write_data_to_file_without_findings(self):
        assert not hasattr(CSV([]), "_file_descriptor")

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

    def test_csv_with_file_path(self):
        file_name = "test"
        extension = ".csv"
        file_path = f"{file_name}{extension}"
        csv = CSV(findings=[], file_path=file_path)

        assert csv.file_extension == extension

    def test_csv_with_extension(self):
        extension = ".csv"
        csv = CSV(findings=[], file_extension=extension)

        assert csv.file_extension == extension

    def test_csv_without_path_or_extension(self):
        csv = CSV(findings=[])

        assert not hasattr(csv, "_file_extension")

    @freeze_time(datetime.now())
    def test_csv_custom_file_descriptor(self):
        with tempfile.TemporaryFile(mode="a+") as temp_file:
            csv = CSV(findings=[generate_finding_output()])
            csv.file_descriptor = temp_file
            # We don't want to close the file to read it later
            with patch.object(temp_file, "close", return_value=None):
                csv.batch_write_data_to_file()

            expected_csv = f"AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_EMAIL;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION\nprofile: default;{datetime.now()};123456789012;123456789012;;test-organization-id;test-organization;test-tag:test-value;test-unique-finding;aws;test-check-id;test-check-id;test-type;PASS;;False;test-service;;high;test-resource;;;;;aws;eu-west-1;check description;test-risk;test-url;;;;;;;test-compliance: test-compliance;test-category;test-dependency;test-related-to;test-notes;{prowler_version}\n"

            temp_file.seek(0)

            assert temp_file.read() == expected_csv
