import os
from os import path, remove
from unittest import mock

import pytest
from colorama import Fore

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
    output_file_timestamp,
)
from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    Compliance_Base_Model,
    Compliance_Requirement,
)
from prowler.lib.check.models import Check_Report, load_check_metadata
from prowler.lib.outputs.common import generate_provider_output
from prowler.lib.outputs.common_models import FindingOutput
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.outputs.csv.csv import generate_csv_fields
from prowler.lib.outputs.file_descriptors import fill_file_descriptors
from prowler.lib.outputs.outputs import extract_findings_statistics, set_report_color
from prowler.lib.outputs.utils import (
    parse_html_string,
    parse_json_tags,
    unroll_dict,
    unroll_dict_to_list,
    unroll_list,
    unroll_tags,
)
from prowler.lib.utils.utils import open_file
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, set_mocked_aws_provider


class TestOutputs:
    def test_fill_file_descriptors_aws(self):
        audited_account = AWS_ACCOUNT_NUMBER
        output_directory = f"{os.path.dirname(os.path.realpath(__file__))}"
        aws_provider = set_mocked_aws_provider()
        test_output_modes = [
            ["csv"],
            ["json-asff"],
            ["json-ocsf"],
            ["html"],
            ["csv", "json-asff", "json-ocsf", "html"],
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
                "json-asff": open_file(
                    f"{output_directory}/{output_filename}{json_asff_file_suffix}",
                    "a",
                )
            },
            {
                "json-ocsf": open_file(
                    f"{output_directory}/{output_filename}{json_ocsf_file_suffix}",
                    "a",
                )
            },
            {
                "html": open_file(
                    f"{output_directory}/{output_filename}{html_file_suffix}",
                    "a",
                )
            },
            {
                "csv": open_file(
                    f"{output_directory}/{output_filename}{csv_file_suffix}",
                    "a",
                ),
                "json-asff": open_file(
                    f"{output_directory}/{output_filename}{json_asff_file_suffix}",
                    "a",
                ),
                "json-ocsf": open_file(
                    f"{output_directory}/{output_filename}{json_ocsf_file_suffix}",
                    "a",
                ),
                "html": open_file(
                    f"{output_directory}/{output_filename}{html_file_suffix}",
                    "a",
                ),
            },
        ]

        for index, output_mode_list in enumerate(test_output_modes):
            test_output_file_descriptors = fill_file_descriptors(
                output_mode_list,
                output_directory,
                output_filename,
                aws_provider,
            )
            for output_mode in output_mode_list:
                assert (
                    test_output_file_descriptors[output_mode].name
                    == expected[index][output_mode].name
                )
                remove(expected[index][output_mode].name)

    def test_set_report_color(self):
        test_status = ["PASS", "FAIL", "MANUAL"]
        test_colors = [Fore.GREEN, Fore.RED, Fore.YELLOW]

        for status in test_status:
            assert set_report_color(status) in test_colors

    def test_set_report_color_invalid(self):
        test_status = "INVALID"

        with pytest.raises(Exception) as exc:
            set_report_color(test_status)

        assert "Invalid Report Status. Must be PASS, FAIL or MANUAL" in str(exc.value)
        assert exc.type == Exception

    def test_generate_common_csv_fields(self):
        expected = [
            "auth_method",
            "timestamp",
            "account_uid",
            "account_name",
            "account_email",
            "account_organization_uid",
            "account_organization_name",
            "account_tags",
            "finding_uid",
            "provider",
            "check_id",
            "check_title",
            "check_type",
            "status",
            "status_extended",
            "muted",
            "service_name",
            "subservice_name",
            "severity",
            "resource_type",
            "resource_uid",
            "resource_name",
            "resource_details",
            "resource_tags",
            "partition",
            "region",
            "description",
            "risk",
            "related_url",
            "remediation_recommendation_text",
            "remediation_recommendation_url",
            "remediation_code_nativeiac",
            "remediation_code_terraform",
            "remediation_code_cli",
            "remediation_code_other",
            "compliance",
            "categories",
            "depends_on",
            "related_to",
            "notes",
            "prowler_version",
        ]

        assert generate_csv_fields(FindingOutput) == expected

    def test_unroll_list_no_separator(self):
        list = ["test", "test1", "test2"]

        assert unroll_list(list) == "test | test1 | test2"

    def test_unroll_list_separator(self):
        list = ["test", "test1", "test2"]

        assert unroll_list(list, ",") == "test, test1, test2"

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

    def test_unroll_dict_to_list(self):
        dict_A = {"A": "B"}
        list_A = ["A: B"]

        assert unroll_dict_to_list(dict_A) == list_A

        dict_B = {"A": ["B", "C"]}
        list_B = ["A: B, C"]

        assert unroll_dict_to_list(dict_B) == list_B

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

    def test_extract_findings_statistics_manual_resources(self):
        finding_1 = mock.MagicMock()
        finding_1.status = "MANUAL"
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

    def test_extract_findings_statistics_all_fail_are_muted(self):
        finding_1 = mock.MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.resource_id = "test_resource_1"
        findings = [finding_1]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 0
        assert stats["total_fail"] == 1
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 1
        assert stats["all_fails_are_muted"]

    def test_extract_findings_statistics_all_fail_are_not_muted(self):
        finding_1 = mock.MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.resource_id = "test_resource_1"
        finding_2 = mock.MagicMock()
        finding_2.status = "FAIL"
        finding_2.muted = False
        finding_2.resource_id = "test_resource_1"
        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 0
        assert stats["total_fail"] == 2
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 2
        assert not stats["all_fails_are_muted"]

    def test_get_check_compliance_aws(self):
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
                            CIS_Requirement_Attribute(
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
                            CIS_Requirement_Attribute(
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
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"] = (
            mock.MagicMock()
        )
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = (
            bulk_check_metadata
        )

        assert get_check_compliance(finding, "aws", output_options) == {
            "CIS-1.4": ["2.1.3"],
            "CIS-1.5": ["2.1.3"],
        }

    def test_get_check_compliance_gcp(self):
        bulk_check_metadata = [
            Compliance_Base_Model(
                Framework="CIS",
                Provider="GCP",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
            Compliance_Base_Model(
                Framework="CIS",
                Provider="GCP",
                Version="2.1",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
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
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"] = (
            mock.MagicMock()
        )
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = (
            bulk_check_metadata
        )

        assert get_check_compliance(finding, "gcp", output_options) == {
            "CIS-2.0": ["2.1.3"],
            "CIS-2.1": ["2.1.3"],
        }

    def test_get_check_compliance_azure(self):
        bulk_check_metadata = [
            Compliance_Base_Model(
                Framework="CIS",
                Provider="Azure",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Azuee Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
            Compliance_Base_Model(
                Framework="CIS",
                Provider="Azure",
                Version="2.1",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Azure Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
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
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"] = (
            mock.MagicMock()
        )
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = (
            bulk_check_metadata
        )

        assert get_check_compliance(finding, "azure", output_options) == {
            "CIS-2.0": ["2.1.3"],
            "CIS-2.1": ["2.1.3"],
        }

    def test_get_check_compliance_kubernetes(self):
        bulk_check_metadata = [
            Compliance_Base_Model(
                Framework="CIS",
                Provider="Kubernetes",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Kubernetes Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
            Compliance_Base_Model(
                Framework="CIS",
                Provider="Kubernetes",
                Version="2.1",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Kubernetes Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
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
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"] = (
            mock.MagicMock()
        )
        output_options.bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = (
            bulk_check_metadata
        )

        assert get_check_compliance(finding, "kubernetes", output_options) == {
            "CIS-2.0": ["2.1.3"],
            "CIS-2.1": ["2.1.3"],
        }

    def test_generate_provider_output(self):
        provider = mock.MagicMock()
        provider.type = "aws"
        finding = mock.MagicMock()
        finding.resource_id = "test"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.check_metadata = mock.MagicMock()
        finding.check_metadata.CheckID = "iam_user_accesskey_unused"
        csv_data = {
            "resource_uid": "test",
            "resource_arn": "test-arn",
            "region": "eu-west-1",
            "account_uid": "123456789012",
            "auth_method": "test",
            "resource_name": "test",
            "timestamp": "2022-01-01T00:00:00Z",
            "provider": "aws",
            "check_id": "iam_user_accesskey_unused",
            "check_title": "IAM User Access Key Unused",
            "check_type": "config",
            "status": "PASS",
            "status_extended": "This is a test",
            "service_name": "iam",
            "subservice_name": "user",
            "severity": "low",
            "resource_type": "aws_iam_user",
            "resource_details": "Test resource details",
            "resource_tags": "",
            "description": "IAM User Access Key Unused",
            "risk": "if an access key is not used, it should be removed",
            "related_url": "",
            "remediation_recommendation_text": "Remove unused access keys",
            "remediation_recommendation_url": "",
            "remediation_code_nativeiac": "",
            "remediation_code_terraform": "",
            "remediation_code_cli": "",
            "remediation_code_other": "",
            "compliance": {
                "CIS": ["2.1.3"],
                "NIST-800-53-Revision-5": ["sc_28_1"],
            },
            "categories": "security",
            "depends_on": "",
            "related_to": "",
            "notes": "",
            "finding_uid": "test-finding",
        }

        assert generate_provider_output(provider, finding, csv_data) == FindingOutput(
            auth_method="profile: test",
            account_uid="123456789012",
            timestamp="2022-01-01T00:00:00Z",
            account_name=None,
            account_email=None,
            account_organization_uid=None,
            account_organization_name=None,
            account_tags=None,
            finding_uid="prowler-aws-iam_user_accesskey_unused-123456789012-eu-west-1-test",
            provider="aws",
            check_id="iam_user_accesskey_unused",
            check_title="IAM User Access Key Unused",
            check_type="config",
            status="PASS",
            status_extended="This is a test",
            service_name="iam",
            subservice_name="user",
            severity="low",
            resource_type="aws_iam_user",
            resource_uid="test-arn",
            resource_name="test",
            resource_tags="",
            resource_details="Test resource details",
            region="eu-west-1",
            description="IAM User Access Key Unused",
            risk="if an access key is not used, it should be removed",
            related_url="",
            remediation_recommendation_text="Remove unused access keys",
            remediation_recommendation_url="",
            remediation_code_nativeiac="",
            remediation_code_terraform="",
            remediation_code_cli="",
            remediation_code_other="",
            compliance={"CIS": ["2.1.3"], "NIST-800-53-Revision-5": ["sc_28_1"]},
            categories="security",
            depends_on="",
            related_to="",
            notes="",
        )

    def test_generate_provider_output_unix_timestamp(self):
        provider = mock.MagicMock()
        provider.type = "aws"
        finding = mock.MagicMock()
        finding.resource_id = "test"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.check_metadata = mock.MagicMock()
        finding.check_metadata.CheckID = "iam_user_accesskey_unused"
        csv_data = {
            "resource_uid": "test",
            "resource_arn": "test-arn",
            "region": "eu-west-1",
            "account_uid": "123456789012",
            "auth_method": "test",
            "resource_name": "test",
            "timestamp": 1640995200,
            "provider": "aws",
            "check_id": "iam_user_accesskey_unused",
            "check_title": "IAM User Access Key Unused",
            "check_type": "config",
            "status": "PASS",
            "status_extended": "This is a test",
            "service_name": "iam",
            "subservice_name": "user",
            "severity": "low",
            "resource_type": "aws_iam_user",
            "resource_details": "Test resource details",
            "resource_tags": "",
            "description": "IAM User Access Key Unused",
            "risk": "if an access key is not used, it should be removed",
            "related_url": "",
            "remediation_recommendation_text": "Remove unused access keys",
            "remediation_recommendation_url": "",
            "remediation_code_nativeiac": "",
            "remediation_code_terraform": "",
            "remediation_code_cli": "",
            "remediation_code_other": "",
            "compliance": {
                "CIS": ["2.1.3"],
                "NIST-800-53-Revision-5": ["sc_28_1"],
            },
            "categories": "security",
            "depends_on": "",
            "related_to": "",
            "notes": "",
            "finding_uid": "test-finding",
        }

        assert generate_provider_output(provider, finding, csv_data) == FindingOutput(
            auth_method="profile: test",
            account_uid="123456789012",
            timestamp=1640995200,
            account_name=None,
            account_email=None,
            account_organization_uid=None,
            account_organization_name=None,
            account_tags=None,
            finding_uid="prowler-aws-iam_user_accesskey_unused-123456789012-eu-west-1-test",
            provider="aws",
            check_id="iam_user_accesskey_unused",
            check_title="IAM User Access Key Unused",
            check_type="config",
            status="PASS",
            status_extended="This is a test",
            service_name="iam",
            subservice_name="user",
            severity="low",
            resource_type="aws_iam_user",
            resource_uid="test-arn",
            resource_name="test",
            resource_tags="",
            resource_details="Test resource details",
            region="eu-west-1",
            description="IAM User Access Key Unused",
            risk="if an access key is not used, it should be removed",
            related_url="",
            remediation_recommendation_text="Remove unused access keys",
            remediation_recommendation_url="",
            remediation_code_nativeiac="",
            remediation_code_terraform="",
            remediation_code_cli="",
            remediation_code_other="",
            compliance={"CIS": ["2.1.3"], "NIST-800-53-Revision-5": ["sc_28_1"]},
            categories="security",
            depends_on="",
            related_to="",
            notes="",
        )
