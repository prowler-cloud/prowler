import os
from os import getcwd, path, remove
from unittest import mock

import boto3
import botocore
import pytest
from colorama import Fore
from moto import mock_s3

from prowler.config.config import (
    csv_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    orange_color,
    output_file_timestamp,
    prowler_version,
    timestamp_utc,
)
from prowler.lib.check.models import Check_Report, load_check_metadata
from prowler.lib.outputs.file_descriptors import fill_file_descriptors
from prowler.lib.outputs.json import fill_json_asff
from prowler.lib.outputs.models import (
    Check_Output_CSV,
    Check_Output_JSON_ASFF,
    Compliance,
    ProductFields,
    Resource,
    Severity,
    generate_csv_fields,
)
from prowler.lib.outputs.outputs import (
    extract_findings_statistics,
    send_to_s3_bucket,
    set_report_color,
)
from prowler.lib.utils.utils import hash_sha512, open_file
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.lib.security_hub.security_hub import send_to_security_hub

AWS_ACCOUNT_ID = "123456789012"

# Mocking Security Hub Get Findings
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "BatchImportFindings":
        return {
            "FailedCount": 0,
            "SuccessCount": 1,
        }
    if operation_name == "DescribeHub":
        return {
            "HubArn": "test-hub",
        }
    if operation_name == "ListEnabledProductsForImport":
        return {
            "ProductSubscriptions": [
                "prowler/prowler",
            ],
        }
    return make_api_call(self, operation_name, kwarg)


class Test_Outputs:
    def test_fill_file_descriptors(self):
        audited_account = AWS_ACCOUNT_ID
        output_directory = f"{os.path.dirname(os.path.realpath(__file__))}"
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_identity_arn="test-arn",
            audited_user_id="test",
            audited_partition="aws",
            profile="default",
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        test_output_modes = [
            ["csv"],
            ["json"],
            ["json-asff"],
            ["csv", "json"],
            ["csv", "json", "json-asff"],
        ]
        output_filename = f"prowler-output-{audited_account}-{output_file_timestamp}"
        expected = [
            {
                "csv": open_file(
                    f"{output_directory}/{output_filename}{csv_file_suffix}",
                    "a",
                )
            },
            {
                "json": open_file(
                    f"{output_directory}/{output_filename}{json_file_suffix}",
                    "a",
                )
            },
            {
                "json-asff": open_file(
                    f"{output_directory}/{output_filename}{json_asff_file_suffix}",
                    "a",
                )
            },
            {
                "csv": open_file(
                    f"{output_directory}/{output_filename}{csv_file_suffix}",
                    "a",
                ),
                "json": open_file(
                    f"{output_directory}/{output_filename}{json_file_suffix}",
                    "a",
                ),
            },
            {
                "csv": open_file(
                    f"{output_directory}/{output_filename}{csv_file_suffix}",
                    "a",
                ),
                "json": open_file(
                    f"{output_directory}/{output_filename}{json_file_suffix}",
                    "a",
                ),
                "json-asff": open_file(
                    f"{output_directory}/{output_filename}{json_asff_file_suffix}",
                    "a",
                ),
            },
        ]

        for index, output_mode_list in enumerate(test_output_modes):
            test_output_file_descriptors = fill_file_descriptors(
                output_mode_list,
                output_directory,
                output_filename,
                audit_info,
            )
            for output_mode in output_mode_list:
                assert (
                    test_output_file_descriptors[output_mode].name
                    == expected[index][output_mode].name
                )
                remove(expected[index][output_mode].name)

    def test_set_report_color(self):
        test_status = ["PASS", "FAIL", "ERROR", "WARNING"]
        test_colors = [Fore.GREEN, Fore.RED, Fore.BLACK, orange_color]

        for status in test_status:
            assert set_report_color(status) in test_colors

    def test_set_report_color_invalid(self):
        test_status = "INVALID"

        with pytest.raises(Exception) as exc:
            set_report_color(test_status)

        assert "Invalid Report Status. Must be PASS, FAIL, ERROR or WARNING" in str(
            exc.value
        )
        assert exc.type == Exception

    def test_generate_common_csv_fields(self):
        expected = [
            "assessment_start_time",
            "finding_unique_id",
            "provider",
            "check_id",
            "check_title",
            "check_type",
            "status",
            "status_extended",
            "service_name",
            "subservice_name",
            "severity",
            "resource_type",
            "resource_details",
            "resource_tags",
            "description",
            "risk",
            "related_url",
            "remediation_recommendation_text",
            "remediation_recommendation_url",
            "remediation_recommendation_code_nativeiac",
            "remediation_recommendation_code_terraform",
            "remediation_recommendation_code_cli",
            "remediation_recommendation_code_other",
            "compliance",
            "categories",
            "depends_on",
            "related_to",
            "notes",
        ]

        assert generate_csv_fields(Check_Output_CSV) == expected

    # def test_fill_json(self):
    #     input_audit_info = AWS_Audit_Info(
    session_config = (None,)
    #         original_session=None,
    #         audit_session=None,
    #         audited_account=AWS_ACCOUNT_ID,
    #         audited_identity_arn="test-arn",
    #         audited_user_id="test",
    #         audited_partition="aws",
    #         profile="default",
    #         profile_region="eu-west-1",
    #         credentials=None,
    #         assumed_role_info=None,
    #         audited_regions=["eu-west-2", "eu-west-1"],
    #         organizations_metadata=None,
    #     )
    #     finding = Check_Report(
    #         load_check_metadata(
    #             f"{path.dirname(path.realpath(__file__))}/fixtures/metadata.json"
    #         ).json()
    #     )
    #     finding.resource_details = "Test resource details"
    #     finding.resource_id = "test-resource"
    #     finding.resource_arn = "test-arn"
    #     finding.region = "eu-west-1"
    #     finding.status = "PASS"
    #     finding.status_extended = "This is a test"

    #     input = Check_Output_JSON(**finding.check_metadata.dict())

    #     expected = Check_Output_JSON(**finding.check_metadata.dict())
    #     expected.AssessmentStartTime = timestamp_iso
    #     expected.FindingUniqueId = ""
    #     expected.Profile = "default"
    #     expected.AccountId = AWS_ACCOUNT_ID
    #     expected.OrganizationsInfo = None
    #     expected.Region = "eu-west-1"
    #     expected.Status = "PASS"
    #     expected.StatusExtended = "This is a test"
    #     expected.ResourceId = "test-resource"
    #     expected.ResourceArn = "test-arn"
    #     expected.ResourceDetails = "Test resource details"

    #     assert fill_json(input, input_audit_info, finding) == expected

    def test_fill_json_asff(self):
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_identity_arn="test-arn",
            audited_user_id="test",
            audited_partition="aws",
            profile="default",
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/fixtures/metadata.json"
            ).json()
        )
        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        input = Check_Output_JSON_ASFF()

        expected = Check_Output_JSON_ASFF()
        expected.Id = f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}"
        expected.ProductArn = "arn:aws:securityhub:eu-west-1::product/prowler/prowler"
        expected.ProductFields = ProductFields(
            ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
        )
        expected.GeneratorId = "prowler-" + finding.check_metadata.CheckID
        expected.AwsAccountId = AWS_ACCOUNT_ID
        expected.Types = finding.check_metadata.CheckType
        expected.FirstObservedAt = (
            expected.UpdatedAt
        ) = expected.CreatedAt = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        expected.Severity = Severity(Label=finding.check_metadata.Severity.upper())
        expected.Title = finding.check_metadata.CheckTitle
        expected.Description = finding.status_extended
        expected.Resources = [
            Resource(
                Id="test-arn",
                Type=finding.check_metadata.ResourceType,
                Partition="aws",
                Region="eu-west-1",
            )
        ]

        expected.Compliance = Compliance(
            Status="PASS" + "ED",
            RelatedRequirements=finding.check_metadata.CheckType,
        )
        expected.Remediation = {
            "Recommendation": finding.check_metadata.Remediation.Recommendation
        }

        assert fill_json_asff(input, input_audit_info, finding) == expected

    @mock_s3
    def test_send_to_s3_bucket(self):
        # Create mock session
        session = boto3.session.Session(
            region_name="us-east-1",
        )
        # Create mock audit_info
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session,
            audited_account=AWS_ACCOUNT_ID,
            audited_identity_arn="test-arn",
            audited_user_id="test",
            audited_partition="aws",
            profile="default",
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        # Creat mock bucket
        bucket_name = "test_bucket"
        client = boto3.client("s3")
        client.create_bucket(Bucket=bucket_name)
        # Create mock csv output file
        fixtures_dir = "tests/lib/outputs/fixtures"
        output_directory = getcwd() + "/" + fixtures_dir
        output_mode = "csv"
        filename = f"prowler-output-{input_audit_info.audited_account}"
        # Send mock csv file to mock S3 Bucket
        send_to_s3_bucket(
            filename,
            output_directory,
            output_mode,
            bucket_name,
            input_audit_info.audit_session,
        )
        # Check if the file has been sent by checking its content type
        assert (
            client.get_object(
                Bucket=bucket_name,
                Key=fixtures_dir + "/" + output_mode + "/" + filename + csv_file_suffix,
            )["ContentType"]
            == "binary/octet-stream"
        )

    @mock_s3
    def test_send_to_s3_bucket_custom_directory(self):
        # Create mock session
        session = boto3.session.Session(
            region_name="us-east-1",
        )
        # Create mock audit_info
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session,
            audited_account=AWS_ACCOUNT_ID,
            audited_identity_arn="test-arn",
            audited_user_id="test",
            audited_partition="aws",
            profile="default",
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        # Creat mock bucket
        bucket_name = "test_bucket"
        client = boto3.client("s3")
        client.create_bucket(Bucket=bucket_name)
        # Create mock csv output file
        fixtures_dir = "fixtures"
        output_directory = f"tests/lib/outputs/{fixtures_dir}"
        output_mode = "csv"
        filename = f"prowler-output-{input_audit_info.audited_account}"
        # Send mock csv file to mock S3 Bucket
        send_to_s3_bucket(
            filename,
            output_directory,
            output_mode,
            bucket_name,
            input_audit_info.audit_session,
        )
        # Check if the file has been sent by checking its content type
        assert (
            client.get_object(
                Bucket=bucket_name,
                Key=output_directory
                + "/"
                + output_mode
                + "/"
                + filename
                + csv_file_suffix,
            )["ContentType"]
            == "binary/octet-stream"
        )

    def test_extract_findings_statistics_different_resources(self):
        finding_1 = mock.MagicMock()
        finding_1.status = "PASS"
        finding_1.resource_id = "test_resource_1"
        finding_2 = mock.MagicMock()
        finding_2.status = "FAIL"
        finding_2.resource_id = "test_resource_2"
        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 1
        assert stats["total_fail"] == 1
        assert stats["resources_count"] == 2
        assert stats["findings_count"] == 2

    def test_extract_findings_statistics_same_resources(self):
        finding_1 = mock.MagicMock()
        finding_1.status = "PASS"
        finding_1.resource_id = "test_resource_1"
        finding_2 = mock.MagicMock()
        finding_2.status = "PASS"
        finding_2.resource_id = "test_resource_1"
        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 2
        assert stats["total_fail"] == 0
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 2

    def test_extract_findings_statistics_info_resources(self):
        finding_1 = mock.MagicMock()
        finding_1.status = "INFO"
        finding_1.resource_id = "test_resource_1"
        finding_2 = mock.MagicMock()
        finding_2.status = "PASS"
        finding_2.resource_id = "test_resource_1"
        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 1
        assert stats["total_fail"] == 0
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 1

    def test_extract_findings_statistics_no_findings(self):
        findings = []

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 0
        assert stats["total_fail"] == 0
        assert stats["resources_count"] == 0
        assert stats["findings_count"] == 0

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_send_to_security_hub(self):
        # Create mock session
        session = boto3.session.Session(
            region_name="eu-west-1",
        )
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session,
            audited_account=AWS_ACCOUNT_ID,
            audited_identity_arn="test-arn",
            audited_user_id="test",
            audited_partition="aws",
            profile="default",
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/fixtures/metadata.json"
            ).json()
        )
        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        finding_output = Check_Output_JSON_ASFF()

        fill_json_asff(finding_output, input_audit_info, finding)

        assert (
            send_to_security_hub(
                False,
                finding.status,
                finding.region,
                finding_output,
                input_audit_info.audit_session,
            )
            == 1
        )
        # Setting is_quiet to True
        assert (
            send_to_security_hub(
                True,
                finding.status,
                finding.region,
                finding_output,
                input_audit_info.audit_session,
            )
            == 0
        )
