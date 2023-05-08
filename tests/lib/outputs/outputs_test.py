import os
import sys
from os import getcwd, path, remove
from unittest import mock

import boto3
import botocore
import pytest
from colorama import Fore
from moto import mock_s3

from prowler.config.config import (
    aws_logo,
    azure_logo,
    csv_file_suffix,
    gcp_logo,
    json_asff_file_suffix,
    json_file_suffix,
    orange_color,
    output_file_timestamp,
    prowler_version,
    timestamp_utc,
)
from prowler.lib.check.compliance_models import (
    CIS_Requirements,
    Compliance_Base_Model,
    Compliance_Requirement,
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
    get_check_compliance,
    parse_html_string,
    parse_json_tags,
    unroll_dict,
    unroll_list,
    unroll_tags,
)
from prowler.lib.outputs.outputs import (
    extract_findings_statistics,
    send_to_s3_bucket,
    set_report_color,
)
from prowler.lib.outputs.slack import create_message_blocks, create_message_identity
from prowler.lib.utils.utils import hash_sha512, open_file
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.lib.security_hub.security_hub import send_to_security_hub
from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    Azure_Identity_Info,
)
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info

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

    def test_unroll_list(self):
        list = ["test", "test1", "test2"]

        assert unroll_list(list) == "test | test1 | test2"

    def test_unroll_tags(self):
        dict_list = [
            {"Key": "name", "Value": "test"},
            {"Key": "project", "Value": "prowler"},
            {"Key": "environment", "Value": "dev"},
            {"Key": "terraform", "Value": "true"},
        ]
        unique_dict_list = [
            {
                "test1": "value1",
                "test2": "value2",
                "test3": "value3",
            }
        ]
        assert (
            unroll_tags(dict_list)
            == "name=test | project=prowler | environment=dev | terraform=true"
        )
        assert (
            unroll_tags(unique_dict_list)
            == "test1=value1 | test2=value2 | test3=value3"
        )

    def test_unroll_dict(self):
        test_compliance_dict = {
            "CISA": ["your-systems-3", "your-data-1", "your-data-2"],
            "CIS-1.4": ["2.1.1"],
            "CIS-1.5": ["2.1.1"],
            "GDPR": ["article_32"],
            "AWS-Foundational-Security-Best-Practices": ["s3"],
            "HIPAA": [
                "164_308_a_1_ii_b",
                "164_308_a_4_ii_a",
                "164_312_a_2_iv",
                "164_312_c_1",
                "164_312_c_2",
                "164_312_e_2_ii",
            ],
            "GxP-21-CFR-Part-11": ["11.10-c", "11.30"],
            "GxP-EU-Annex-11": ["7.1-data-storage-damage-protection"],
            "NIST-800-171-Revision-2": ["3_3_8", "3_5_10", "3_13_11", "3_13_16"],
            "NIST-800-53-Revision-4": ["sc_28"],
            "NIST-800-53-Revision-5": [
                "au_9_3",
                "cm_6_a",
                "cm_9_b",
                "cp_9_d",
                "cp_9_8",
                "pm_11_b",
                "sc_8_3",
                "sc_8_4",
                "sc_13_a",
                "sc_16_1",
                "sc_28_1",
                "si_19_4",
            ],
            "ENS-RD2022": ["mp.si.2.aws.s3.1"],
            "NIST-CSF-1.1": ["ds_1"],
            "RBI-Cyber-Security-Framework": ["annex_i_1_3"],
            "FFIEC": ["d3-pc-am-b-12"],
            "PCI-3.2.1": ["s3"],
            "FedRamp-Moderate-Revision-4": ["sc-13", "sc-28"],
            "FedRAMP-Low-Revision-4": ["sc-13"],
        }
        assert (
            unroll_dict(test_compliance_dict)
            == "CISA: your-systems-3, your-data-1, your-data-2 | CIS-1.4: 2.1.1 | CIS-1.5: 2.1.1 | GDPR: article_32 | AWS-Foundational-Security-Best-Practices: s3 | HIPAA: 164_308_a_1_ii_b, 164_308_a_4_ii_a, 164_312_a_2_iv, 164_312_c_1, 164_312_c_2, 164_312_e_2_ii | GxP-21-CFR-Part-11: 11.10-c, 11.30 | GxP-EU-Annex-11: 7.1-data-storage-damage-protection | NIST-800-171-Revision-2: 3_3_8, 3_5_10, 3_13_11, 3_13_16 | NIST-800-53-Revision-4: sc_28 | NIST-800-53-Revision-5: au_9_3, cm_6_a, cm_9_b, cp_9_d, cp_9_8, pm_11_b, sc_8_3, sc_8_4, sc_13_a, sc_16_1, sc_28_1, si_19_4 | ENS-RD2022: mp.si.2.aws.s3.1 | NIST-CSF-1.1: ds_1 | RBI-Cyber-Security-Framework: annex_i_1_3 | FFIEC: d3-pc-am-b-12 | PCI-3.2.1: s3 | FedRamp-Moderate-Revision-4: sc-13, sc-28 | FedRAMP-Low-Revision-4: sc-13"
        )

    def test_parse_html_string(self):
        string = "CISA: your-systems-3, your-data-1, your-data-2 | CIS-1.4: 2.1.1 | CIS-1.5: 2.1.1 | GDPR: article_32 | AWS-Foundational-Security-Best-Practices: s3 | HIPAA: 164_308_a_1_ii_b, 164_308_a_4_ii_a, 164_312_a_2_iv, 164_312_c_1, 164_312_c_2, 164_312_e_2_ii | GxP-21-CFR-Part-11: 11.10-c, 11.30 | GxP-EU-Annex-11: 7.1-data-storage-damage-protection | NIST-800-171-Revision-2: 3_3_8, 3_5_10, 3_13_11, 3_13_16 | NIST-800-53-Revision-4: sc_28 | NIST-800-53-Revision-5: au_9_3, cm_6_a, cm_9_b, cp_9_d, cp_9_8, pm_11_b, sc_8_3, sc_8_4, sc_13_a, sc_16_1, sc_28_1, si_19_4 | ENS-RD2022: mp.si.2.aws.s3.1 | NIST-CSF-1.1: ds_1 | RBI-Cyber-Security-Framework: annex_i_1_3 | FFIEC: d3-pc-am-b-12 | PCI-3.2.1: s3 | FedRamp-Moderate-Revision-4: sc-13, sc-28 | FedRAMP-Low-Revision-4: sc-13"
        assert (
            parse_html_string(string)
            == """
&#x2022;CISA: your-systems-3, your-data-1, your-data-2

&#x2022;CIS-1.4: 2.1.1

&#x2022;CIS-1.5: 2.1.1

&#x2022;GDPR: article_32

&#x2022;AWS-Foundational-Security-Best-Practices: s3

&#x2022;HIPAA: 164_308_a_1_ii_b, 164_308_a_4_ii_a, 164_312_a_2_iv, 164_312_c_1, 164_312_c_2, 164_312_e_2_ii

&#x2022;GxP-21-CFR-Part-11: 11.10-c, 11.30

&#x2022;GxP-EU-Annex-11: 7.1-data-storage-damage-protection

&#x2022;NIST-800-171-Revision-2: 3_3_8, 3_5_10, 3_13_11, 3_13_16

&#x2022;NIST-800-53-Revision-4: sc_28

&#x2022;NIST-800-53-Revision-5: au_9_3, cm_6_a, cm_9_b, cp_9_d, cp_9_8, pm_11_b, sc_8_3, sc_8_4, sc_13_a, sc_16_1, sc_28_1, si_19_4

&#x2022;ENS-RD2022: mp.si.2.aws.s3.1

&#x2022;NIST-CSF-1.1: ds_1

&#x2022;RBI-Cyber-Security-Framework: annex_i_1_3

&#x2022;FFIEC: d3-pc-am-b-12

&#x2022;PCI-3.2.1: s3

&#x2022;FedRamp-Moderate-Revision-4: sc-13, sc-28

&#x2022;FedRAMP-Low-Revision-4: sc-13
"""
        )

    def test_parse_json_tags(self):
        json_tags = [
            {"Key": "name", "Value": "test"},
            {"Key": "project", "Value": "prowler"},
            {"Key": "environment", "Value": "dev"},
            {"Key": "terraform", "Value": "true"},
        ]

        assert parse_json_tags(json_tags) == {
            "name": "test",
            "project": "prowler",
            "environment": "dev",
            "terraform": "true",
        }
        assert parse_json_tags([]) == {}
        assert parse_json_tags([None]) == {}
        assert parse_json_tags([{}]) == {}
        assert parse_json_tags(None) == {}

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
            RelatedRequirements=[],
            AssociatedStandards=[],
        )
        expected.Remediation = {
            "Recommendation": finding.check_metadata.Remediation.Recommendation
        }
        output_options = mock.MagicMock()

        assert (
            fill_json_asff(input, input_audit_info, finding, output_options) == expected
        )

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
    def test_send_to_s3_bucket_compliance(self):
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
        output_mode = "cis_1.4_aws"
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
                Key=fixtures_dir
                + "/"
                + output_mode
                + "/"
                + filename
                + "_"
                + output_mode
                + csv_file_suffix,
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
        output_options = mock.MagicMock()
        fill_json_asff(finding_output, input_audit_info, finding, output_options)

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

    def test_get_check_compliance(self):
        bulk_check_metadata = [
            Compliance_Base_Model(
                Framework="CIS",
                Provider="AWS",
                Version="1.4",
                Description="The CIS Benchmark for CIS Amazon Web Services Foundations Benchmark, v1.4.0, Level 1 and 2 provides prescriptive guidance for configuring security options for a subset of Amazon Web Services. It has an emphasis on foundational, testable, and architecture agnostic settings",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure MFA Delete is enabled on S3 buckets",
                        Attributes=[
                            CIS_Requirements(
                                Section="2.1. Simple Storage Service (S3)",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
                                RationaleStatement="Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the steps below to enable MFA delete on an S3 bucket.\n\nNote:\n-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.\n-You must use your 'root' account to enable MFA Delete on S3 buckets.\n\n**From Command line:**\n\n1. Run the s3api put-bucket-versioning command\n\n```\naws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa “arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”\n```",
                                AuditProcedure='Perform the steps below to confirm MFA delete is configured on an S3 Bucket\n\n**From Console:**\n\n1. Login to the S3 console at `https://console.aws.amazon.com/s3/`\n\n2. Click the `Check` box next to the Bucket name you want to confirm\n\n3. In the window under `Properties`\n\n4. Confirm that Versioning is `Enabled`\n\n5. Confirm that MFA Delete is `Enabled`\n\n**From Command Line:**\n\n1. Run the `get-bucket-versioning`\n```\naws s3api get-bucket-versioning --bucket my-bucket\n```\n\nOutput example:\n```\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> \n <Status>Enabled</Status>\n <MfaDelete>Enabled</MfaDelete> \n</VersioningConfiguration>\n```\n\nIf the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.',
                                AdditionalInformation="",
                                References="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html",
                            )
                        ],
                    )
                ],
            ),
            Compliance_Base_Model(
                Framework="CIS",
                Provider="AWS",
                Version="1.5",
                Description="The CIS Amazon Web Services Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Amazon Web Services with an emphasis on foundational, testable, and architecture agnostic settings.",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure MFA Delete is enabled on S3 buckets",
                        Attributes=[
                            CIS_Requirements(
                                Section="2.1. Simple Storage Service (S3)",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
                                RationaleStatement="Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the steps below to enable MFA delete on an S3 bucket.\n\nNote:\n-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.\n-You must use your 'root' account to enable MFA Delete on S3 buckets.\n\n**From Command line:**\n\n1. Run the s3api put-bucket-versioning command\n\n```\naws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa “arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”\n```",
                                AuditProcedure='Perform the steps below to confirm MFA delete is configured on an S3 Bucket\n\n**From Console:**\n\n1. Login to the S3 console at `https://console.aws.amazon.com/s3/`\n\n2. Click the `Check` box next to the Bucket name you want to confirm\n\n3. In the window under `Properties`\n\n4. Confirm that Versioning is `Enabled`\n\n5. Confirm that MFA Delete is `Enabled`\n\n**From Command Line:**\n\n1. Run the `get-bucket-versioning`\n```\naws s3api get-bucket-versioning --bucket my-bucket\n```\n\nOutput example:\n```\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> \n <Status>Enabled</Status>\n <MfaDelete>Enabled</MfaDelete> \n</VersioningConfiguration>\n```\n\nIf the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.',
                                AdditionalInformation="",
                                References="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html",
                            )
                        ],
                    )
                ],
            ),
        ]

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

        output_options = mock.MagicMock()
        output_options.bulk_checks_metadata = {}
        output_options.bulk_checks_metadata[
            "iam_disable_30_days_credentials"
        ] = mock.MagicMock()
        output_options.bulk_checks_metadata[
            "iam_disable_30_days_credentials"
        ].Compliance = bulk_check_metadata

        assert get_check_compliance(finding, "aws", output_options) == {
            "CIS-1.4": ["2.1.3"],
            "CIS-1.5": ["2.1.3"],
        }

    def test_create_message_identity(self):
        aws_audit_info = AWS_Audit_Info(
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
        gcp_audit_info = GCP_Audit_Info(
            credentials=None,
            project_id="test-project",
            audit_resources=None,
            audit_metadata=None,
        )
        azure_audit_info = Azure_Audit_Info(
            credentials=None,
            identity=Azure_Identity_Info(
                identity_id="",
                identity_type="",
                tenant_ids=[],
                domain="",
                subscriptions={
                    "subscription 1": "qwerty",
                    "subscription 2": "asdfg",
                },
            ),
            audit_resources=None,
            audit_metadata=None,
        )
        assert (
            create_message_identity("aws", aws_audit_info)
            == f"AWS Account *{aws_audit_info.audited_account}*"
        )
        assert (
            create_message_identity("gcp", gcp_audit_info)
            == f"GCP Project *{gcp_audit_info.project_id}*"
        )
        assert (
            create_message_identity("azure", azure_audit_info)
            == "Azure Subscriptions:\n- *subscription 1: qwerty*\n- *subscription 2: asdfg*\n"
        )

    def test_create_message_blocks(self):
        aws_identity = f"AWS Account *{AWS_ACCOUNT_ID}*"
        azure_identity = "Azure Subscriptions:\n- *subscription 1: qwerty*\n- *subscription 2: asdfg*\n"
        gcp_identity = "GCP Project *gcp-project*"
        stats = {}
        stats["total_pass"] = 12
        stats["total_fail"] = 10
        stats["resources_count"] = 20
        stats["findings_count"] = 22
        assert create_message_blocks(aws_identity, "aws", stats) == [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {aws_identity} with a total of *{stats['findings_count']}* findings.",
                },
                "accessory": {
                    "type": "image",
                    "image_url": aws_logo,
                    "alt_text": "Provider Logo",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass']/stats['findings_count']*100,2)}%)\n",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail']/stats['findings_count']*100,2)}%)\n ",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:bar_chart: *{stats['resources_count']} Scanned Resources*\n",
                },
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Used parameters: `prowler {' '.join(sys.argv[1:])} `",
                    }
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "Join our Slack Community!"},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :slack:"},
                    "url": "https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Feel free to contact us in our repo",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :github:"},
                    "url": "https://github.com/prowler-cloud/prowler",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "See all the things you can do with ProwlerPro",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler Pro"},
                    "url": "https://prowler.pro",
                },
            },
        ]
        assert create_message_blocks(azure_identity, "azure", stats) == [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {azure_identity} with a total of *{stats['findings_count']}* findings.",
                },
                "accessory": {
                    "type": "image",
                    "image_url": azure_logo,
                    "alt_text": "Provider Logo",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass']/stats['findings_count']*100,2)}%)\n",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail']/stats['findings_count']*100,2)}%)\n ",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:bar_chart: *{stats['resources_count']} Scanned Resources*\n",
                },
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Used parameters: `prowler {' '.join(sys.argv[1:])} `",
                    }
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "Join our Slack Community!"},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :slack:"},
                    "url": "https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Feel free to contact us in our repo",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :github:"},
                    "url": "https://github.com/prowler-cloud/prowler",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "See all the things you can do with ProwlerPro",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler Pro"},
                    "url": "https://prowler.pro",
                },
            },
        ]
        assert create_message_blocks(gcp_identity, "gcp", stats) == [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hey there 👋 \n I'm *Prowler*, _the handy cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {gcp_identity} with a total of *{stats['findings_count']}* findings.",
                },
                "accessory": {
                    "type": "image",
                    "image_url": gcp_logo,
                    "alt_text": "Provider Logo",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass']/stats['findings_count']*100,2)}%)\n",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail']/stats['findings_count']*100,2)}%)\n ",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"\n:bar_chart: *{stats['resources_count']} Scanned Resources*\n",
                },
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Used parameters: `prowler {' '.join(sys.argv[1:])} `",
                    }
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "Join our Slack Community!"},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :slack:"},
                    "url": "https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Feel free to contact us in our repo",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler :github:"},
                    "url": "https://github.com/prowler-cloud/prowler",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "See all the things you can do with ProwlerPro",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Prowler Pro"},
                    "url": "https://prowler.pro",
                },
            },
        ]
