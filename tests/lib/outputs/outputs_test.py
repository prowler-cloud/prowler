import os
from os import path, remove
from time import mktime
from unittest import mock

import pytest
from colorama import Fore
from mock import patch

from prowler.config.config import (
    csv_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    orange_color,
    output_file_timestamp,
    prowler_version,
    timestamp,
    timestamp_utc,
)
from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    Compliance_Base_Model,
    Compliance_Requirement,
)
from prowler.lib.check.models import Check_Report, load_check_metadata
from prowler.lib.outputs.file_descriptors import fill_file_descriptors
from prowler.lib.outputs.json import (
    fill_json_asff,
    fill_json_ocsf,
    generate_json_asff_resource_tags,
    generate_json_asff_status,
    generate_json_ocsf_severity_id,
    generate_json_ocsf_status,
    generate_json_ocsf_status_id,
)
from prowler.lib.outputs.models import (
    Account,
    Check_Output_CSV,
    Check_Output_JSON_ASFF,
    Check_Output_JSON_OCSF,
    Cloud,
    Compliance,
    Compliance_OCSF,
    Feature,
    Finding,
    Group,
    Metadata,
    Organization,
    Product,
    ProductFields,
    Remediation_OCSF,
    Resource,
    Resources,
    Severity,
    generate_csv_fields,
    get_check_compliance,
    parse_json_tags,
    unroll_dict,
    unroll_dict_to_list,
    unroll_list,
    unroll_tags,
)
from prowler.lib.outputs.outputs import extract_findings_statistics, set_report_color
from prowler.lib.utils.utils import hash_sha512, open_file
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_ID = "123456789012"


class Test_Outputs:
    def test_fill_file_descriptors(self):
        audited_account = AWS_ACCOUNT_ID
        output_directory = f"{os.path.dirname(os.path.realpath(__file__))}"
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        test_output_modes = [
            ["csv"],
            ["json-asff"],
            ["json-ocsf"],
            ["csv", "json-asff", "json-ocsf"],
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
                    f"{output_directory}/{output_filename}{json_asff_file_suffix}",
                    "a",
                )
            },
            {
                "csv": open_file(
                    f"{output_directory}/{output_filename}{csv_file_suffix}",
                    "a",
                ),
                "json-ocsf": open_file(
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
        test_status = ["PASS", "FAIL", "ERROR", "MUTED"]
        test_colors = [Fore.GREEN, Fore.RED, Fore.BLACK, orange_color]

        for status in test_status:
            assert set_report_color(status) in test_colors

    def test_set_report_color_invalid(self):
        test_status = "INVALID"

        with pytest.raises(Exception) as exc:
            set_report_color(test_status)

        assert "Invalid Report Status. Must be PASS, FAIL, ERROR or MUTED" in str(
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

    # def test_fill_json(self):
    #     input_audit_info = AWS_Audit_Info(
    #         session_config = None,
    #         original_session=None,
    #         audit_session=None,
    #         audited_account=AWS_ACCOUNT_ID,
    #         audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
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

        expected = Check_Output_JSON_ASFF()
        expected.Id = f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}"
        expected.ProductArn = "arn:aws:securityhub:eu-west-1::product/prowler/prowler"
        expected.ProductFields = ProductFields(
            ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
        )
        expected.GeneratorId = "prowler-" + finding.check_metadata.CheckID
        expected.AwsAccountId = AWS_ACCOUNT_ID
        expected.Types = finding.check_metadata.CheckType
        expected.FirstObservedAt = expected.UpdatedAt = expected.CreatedAt = (
            timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
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

        input = Check_Output_JSON_ASFF()
        output_options = mock.MagicMock()

        assert (
            fill_json_asff(input, input_audit_info, finding, output_options) == expected
        )

    def test_fill_json_asff_without_remediation_recommendation_url(self):
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/fixtures/metadata.json"
            ).json()
        )

        # Empty the Remediation.Recomendation.URL
        finding.check_metadata.Remediation.Recommendation.Url = ""

        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        expected = Check_Output_JSON_ASFF()
        expected.Id = f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}"
        expected.ProductArn = "arn:aws:securityhub:eu-west-1::product/prowler/prowler"
        expected.ProductFields = ProductFields(
            ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
        )
        expected.GeneratorId = "prowler-" + finding.check_metadata.CheckID
        expected.AwsAccountId = AWS_ACCOUNT_ID
        expected.Types = finding.check_metadata.CheckType
        expected.FirstObservedAt = expected.UpdatedAt = expected.CreatedAt = (
            timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
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

        # Set the check's remediation
        expected.Remediation = {
            "Recommendation": finding.check_metadata.Remediation.Recommendation,
            # "Code": finding.check_metadata.Remediation.Code,
        }

        expected.Remediation["Recommendation"].Text = (
            finding.check_metadata.Remediation.Recommendation.Text
        )
        expected.Remediation["Recommendation"].Url = (
            "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"
        )

        input = Check_Output_JSON_ASFF()
        output_options = mock.MagicMock()

        assert (
            fill_json_asff(input, input_audit_info, finding, output_options) == expected
        )

    def test_fill_json_asff_with_long_description(self):
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/fixtures/metadata.json"
            ).json()
        )

        # Empty the Remediation.Recomendation.URL
        finding.check_metadata.Remediation.Recommendation.Url = ""

        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "x" * 2000  # it has to be limited to 1000+...

        expected = Check_Output_JSON_ASFF()
        expected.Id = f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}"
        expected.ProductArn = "arn:aws:securityhub:eu-west-1::product/prowler/prowler"
        expected.ProductFields = ProductFields(
            ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
        )
        expected.GeneratorId = "prowler-" + finding.check_metadata.CheckID
        expected.AwsAccountId = AWS_ACCOUNT_ID
        expected.Types = finding.check_metadata.CheckType
        expected.FirstObservedAt = expected.UpdatedAt = expected.CreatedAt = (
            timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        expected.Severity = Severity(Label=finding.check_metadata.Severity.upper())
        expected.Title = finding.check_metadata.CheckTitle
        expected.Description = finding.status_extended[:1000] + "..."
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

        # Set the check's remediation
        expected.Remediation = {
            "Recommendation": finding.check_metadata.Remediation.Recommendation,
            # "Code": finding.check_metadata.Remediation.Code,
        }

        expected.Remediation["Recommendation"].Text = (
            finding.check_metadata.Remediation.Recommendation.Text
        )
        expected.Remediation["Recommendation"].Url = (
            "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"
        )

        input = Check_Output_JSON_ASFF()
        output_options = mock.MagicMock()

        assert (
            fill_json_asff(input, input_audit_info, finding, output_options) == expected
        )

    def test_fill_json_asff_with_long_associated_standards(self):
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        with patch(
            "prowler.lib.outputs.json.get_check_compliance",
            return_value={
                "CISA": ["your-systems-3", "your-data-2"],
                "SOC2": ["cc_2_1", "cc_7_2", "cc_a_1_2"],
                "CIS-1.4": ["3.1"],
                "CIS-1.5": ["3.1"],
                "GDPR": ["article_25", "article_30"],
                "AWS-Foundational-Security-Best-Practices": ["cloudtrail"],
                "HIPAA": [
                    "164_308_a_1_ii_d",
                    "164_308_a_3_ii_a",
                    "164_308_a_6_ii",
                    "164_312_b",
                    "164_312_e_2_i",
                ],
                "ISO27001": ["A.12.4"],
                "GxP-21-CFR-Part-11": ["11.10-e", "11.10-k", "11.300-d"],
                "AWS-Well-Architected-Framework-Security-Pillar": [
                    "SEC04-BP02",
                    "SEC04-BP03",
                ],
                "GxP-EU-Annex-11": [
                    "1-risk-management",
                    "4.2-validation-documentation-change-control",
                ],
                "NIST-800-171-Revision-2": [
                    "3_1_12",
                    "3_3_1",
                    "3_3_2",
                    "3_3_3",
                    "3_4_1",
                    "3_6_1",
                    "3_6_2",
                    "3_13_1",
                    "3_13_2",
                    "3_14_6",
                    "3_14_7",
                ],
                "NIST-800-53-Revision-4": [
                    "ac_2_4",
                    "ac_2",
                    "au_2",
                    "au_3",
                    "au_12",
                    "cm_2",
                ],
                "NIST-800-53-Revision-5": [
                    "ac_2_4",
                    "ac_3_1",
                    "ac_3_10",
                    "ac_4_26",
                    "ac_6_9",
                    "au_2_b",
                    "au_3_1",
                    "au_3_a",
                    "au_3_b",
                    "au_3_c",
                    "au_3_d",
                    "au_3_e",
                    "au_3_f",
                    "au_6_3",
                    "au_6_4",
                    "au_6_6",
                    "au_6_9",
                    "au_8_b",
                    "au_10",
                    "au_12_a",
                    "au_12_c",
                    "au_12_1",
                    "au_12_2",
                    "au_12_3",
                    "au_12_4",
                    "au_14_a",
                    "au_14_b",
                    "au_14_3",
                    "ca_7_b",
                    "cm_5_1_b",
                    "cm_6_a",
                    "cm_9_b",
                    "ia_3_3_b",
                    "ma_4_1_a",
                    "pm_14_a_1",
                    "pm_14_b",
                    "pm_31",
                    "sc_7_9_b",
                    "si_1_1_c",
                    "si_3_8_b",
                    "si_4_2",
                    "si_4_17",
                    "si_4_20",
                    "si_7_8",
                    "si_10_1_c",
                ],
                "ENS-RD2022": [
                    "op.acc.6.r5.aws.iam.1",
                    "op.exp.5.aws.ct.1",
                    "op.exp.8.aws.ct.1",
                    "op.exp.8.aws.ct.6",
                    "op.exp.9.aws.ct.1",
                    "op.mon.1.aws.ct.1",
                ],
                "NIST-CSF-1.1": [
                    "ae_1",
                    "ae_3",
                    "ae_4",
                    "cm_1",
                    "cm_3",
                    "cm_6",
                    "cm_7",
                    "am_3",
                    "ac_6",
                    "ds_5",
                    "ma_2",
                    "pt_1",
                ],
                "RBI-Cyber-Security-Framework": ["annex_i_7_4"],
                "FFIEC": [
                    "d2-ma-ma-b-1",
                    "d2-ma-ma-b-2",
                    "d3-dc-an-b-3",
                    "d3-dc-an-b-4",
                    "d3-dc-an-b-5",
                    "d3-dc-ev-b-1",
                    "d3-dc-ev-b-3",
                    "d3-pc-im-b-3",
                    "d3-pc-im-b-7",
                    "d5-dr-de-b-3",
                ],
                "PCI-3.2.1": ["cloudtrail"],
                "FedRamp-Moderate-Revision-4": [
                    "ac-2-4",
                    "ac-2-g",
                    "au-2-a-d",
                    "au-3",
                    "au-6-1-3",
                    "au-12-a-c",
                    "ca-7-a-b",
                    "si-4-16",
                    "si-4-2",
                    "si-4-4",
                    "si-4-5",
                ],
                "FedRAMP-Low-Revision-4": ["ac-2", "au-2", "ca-7"],
            },
        ):
            finding = Check_Report(
                load_check_metadata(
                    f"{path.dirname(path.realpath(__file__))}/fixtures/metadata.json"
                ).json()
            )

            # Empty the Remediation.Recomendation.URL
            finding.check_metadata.Remediation.Recommendation.Url = ""

            finding.resource_details = "Test resource details"
            finding.resource_id = "test-resource"
            finding.resource_arn = "test-arn"
            finding.region = "eu-west-1"
            finding.status = "PASS"
            finding.status_extended = "This is a test"

            expected = Check_Output_JSON_ASFF()
            expected.Id = f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}"
            expected.ProductArn = (
                "arn:aws:securityhub:eu-west-1::product/prowler/prowler"
            )
            expected.ProductFields = ProductFields(
                ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
            )
            expected.GeneratorId = "prowler-" + finding.check_metadata.CheckID
            expected.AwsAccountId = AWS_ACCOUNT_ID
            expected.Types = finding.check_metadata.CheckType
            expected.FirstObservedAt = expected.UpdatedAt = expected.CreatedAt = (
                timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
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
                RelatedRequirements=[
                    "CISA your-systems-3 your-data-2",
                    "SOC2 cc_2_1 cc_7_2 cc_a_1_2",
                    "CIS-1.4 3.1",
                    "CIS-1.5 3.1",
                    "GDPR article_25 article_30",
                    "AWS-Foundational-Security-Best-Practices cloudtrail",
                    "HIPAA 164_308_a_1_ii_d 164_308_a_3_ii_a 164_308_a_6_ii 164_312_",
                    "ISO27001 A.12.4",
                    "GxP-21-CFR-Part-11 11.10-e 11.10-k 11.300-d",
                    "AWS-Well-Architected-Framework-Security-Pillar SEC04-BP02 SEC04",
                    "GxP-EU-Annex-11 1-risk-management 4.2-validation-documentation-",
                    "NIST-800-171-Revision-2 3_1_12 3_3_1 3_3_2 3_3_3 3_4_1 3_6_1 3_",
                    "NIST-800-53-Revision-4 ac_2_4 ac_2 au_2 au_3 au_12 cm_2",
                    "NIST-800-53-Revision-5 ac_2_4 ac_3_1 ac_3_10 ac_4_26 ac_6_9 au_",
                    "ENS-RD2022 op.acc.6.r5.aws.iam.1 op.exp.5.aws.ct.1 op.exp.8.aws",
                    "NIST-CSF-1.1 ae_1 ae_3 ae_4 cm_1 cm_3 cm_6 cm_7 am_3 ac_6 ds_5 ",
                    "RBI-Cyber-Security-Framework annex_i_7_4",
                    "FFIEC d2-ma-ma-b-1 d2-ma-ma-b-2 d3-dc-an-b-3 d3-dc-an-b-4 d3-dc",
                    "PCI-3.2.1 cloudtrail",
                    "FedRamp-Moderate-Revision-4 ac-2-4 ac-2-g au-2-a-d au-3 au-6-1-",
                ],
                AssociatedStandards=[
                    {"StandardsId": "CISA"},
                    {"StandardsId": "SOC2"},
                    {"StandardsId": "CIS-1.4"},
                    {"StandardsId": "CIS-1.5"},
                    {"StandardsId": "GDPR"},
                    {"StandardsId": "AWS-Foundational-Security-Best-Practices"},
                    {"StandardsId": "HIPAA"},
                    {"StandardsId": "ISO27001"},
                    {"StandardsId": "GxP-21-CFR-Part-11"},
                    {"StandardsId": "AWS-Well-Architected-Framework-Security-Pillar"},
                    {"StandardsId": "GxP-EU-Annex-11"},
                    {"StandardsId": "NIST-800-171-Revision-2"},
                    {"StandardsId": "NIST-800-53-Revision-4"},
                    {"StandardsId": "NIST-800-53-Revision-5"},
                    {"StandardsId": "ENS-RD2022"},
                    {"StandardsId": "NIST-CSF-1.1"},
                    {"StandardsId": "RBI-Cyber-Security-Framework"},
                    {"StandardsId": "FFIEC"},
                    {"StandardsId": "PCI-3.2.1"},
                    {"StandardsId": "FedRamp-Moderate-Revision-4"},
                ],
            )

            # Set the check's remediation
            expected.Remediation = {
                "Recommendation": finding.check_metadata.Remediation.Recommendation,
                # "Code": finding.check_metadata.Remediation.Code,
            }

            expected.Remediation["Recommendation"].Text = (
                finding.check_metadata.Remediation.Recommendation.Text
            )
            expected.Remediation["Recommendation"].Url = (
                "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"
            )

            input = Check_Output_JSON_ASFF()
            output_options = mock.MagicMock()

            assert (
                fill_json_asff(input, input_audit_info, finding, output_options)
                == expected
            )

    def test_fill_json_ocsf_iso_format_timestamp(self):
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
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

        expected = Check_Output_JSON_OCSF(
            finding=Finding(
                title="Ensure Access Keys unused are disabled",
                desc="Ensure Access Keys unused are disabled",
                supporting_data={
                    "Risk": "Risk associated.",
                    "Notes": "additional information",
                },
                remediation=Remediation_OCSF(
                    kb_articles=[
                        "code or URL to the code location.",
                        "code or URL to the code location.",
                        "cli command or URL to the cli command location.",
                        "cli command or URL to the cli command location.",
                        "https://myfp.com/recommendations/dangerous_things_and_how_to_fix_them.html",
                    ],
                    desc="Run sudo yum update and cross your fingers and toes.",
                ),
                types=["Software and Configuration Checks"],
                src_url="https://serviceofficialsiteorpageforthissubject",
                uid="prowler-aws-iam_user_accesskey_unused-123456789012-eu-west-1-test-resource",
                related_events=[
                    "othercheck1",
                    "othercheck2",
                    "othercheck3",
                    "othercheck4",
                ],
            ),
            resources=[
                Resources(
                    group=Group(name="iam"),
                    region="eu-west-1",
                    name="test-resource",
                    uid="test-arn",
                    labels=[],
                    type="AwsIamAccessAnalyzer",
                    details="Test resource details",
                )
            ],
            status_detail="This is a test",
            compliance=Compliance_OCSF(
                status="Success", requirements=[], status_detail="This is a test"
            ),
            message="This is a test",
            severity_id=2,
            severity="Low",
            cloud=Cloud(
                account=Account(name="", uid="123456789012"),
                region="eu-west-1",
                org=Organization(uid="", name=""),
                provider="aws",
                project_uid="",
            ),
            time=timestamp.isoformat(),
            metadata=Metadata(
                original_time=timestamp.isoformat(),
                profiles=["default"],
                product=Product(
                    language="en",
                    name="Prowler",
                    version=prowler_version,
                    vendor_name="Prowler/ProwlerPro",
                    feature=Feature(
                        name="iam_user_accesskey_unused",
                        uid="iam_user_accesskey_unused",
                        version=prowler_version,
                    ),
                ),
                version="1.0.0-rc.3",
            ),
            state_id=0,
            state="New",
            status_id=1,
            status="Success",
            type_uid=200101,
            type_name="Security Finding: Create",
            impact_id=0,
            impact="Unknown",
            confidence_id=0,
            confidence="Unknown",
            activity_id=1,
            activity_name="Create",
            category_uid=2,
            category_name="Findings",
            class_uid=2001,
            class_name="Security Finding",
        )
        output_options = mock.MagicMock()
        output_options.unix_timestamp = False
        assert fill_json_ocsf(input_audit_info, finding, output_options) == expected

    def test_fill_json_ocsf_unix_timestamp(self):
        input_audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=None,
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
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

        expected = Check_Output_JSON_OCSF(
            finding=Finding(
                title="Ensure Access Keys unused are disabled",
                desc="Ensure Access Keys unused are disabled",
                supporting_data={
                    "Risk": "Risk associated.",
                    "Notes": "additional information",
                },
                remediation=Remediation_OCSF(
                    kb_articles=[
                        "code or URL to the code location.",
                        "code or URL to the code location.",
                        "cli command or URL to the cli command location.",
                        "cli command or URL to the cli command location.",
                        "https://myfp.com/recommendations/dangerous_things_and_how_to_fix_them.html",
                    ],
                    desc="Run sudo yum update and cross your fingers and toes.",
                ),
                types=["Software and Configuration Checks"],
                src_url="https://serviceofficialsiteorpageforthissubject",
                uid="prowler-aws-iam_user_accesskey_unused-123456789012-eu-west-1-test-resource",
                related_events=[
                    "othercheck1",
                    "othercheck2",
                    "othercheck3",
                    "othercheck4",
                ],
            ),
            resources=[
                Resources(
                    group=Group(name="iam"),
                    region="eu-west-1",
                    name="test-resource",
                    uid="test-arn",
                    labels=[],
                    type="AwsIamAccessAnalyzer",
                    details="Test resource details",
                )
            ],
            status_detail="This is a test",
            compliance=Compliance_OCSF(
                status="Success", requirements=[], status_detail="This is a test"
            ),
            message="This is a test",
            severity_id=2,
            severity="Low",
            cloud=Cloud(
                account=Account(name="", uid="123456789012"),
                region="eu-west-1",
                org=Organization(uid="", name=""),
                provider="aws",
                project_uid="",
            ),
            time=int(mktime(timestamp.timetuple())),
            metadata=Metadata(
                original_time=int(mktime(timestamp.timetuple())),
                profiles=["default"],
                product=Product(
                    language="en",
                    name="Prowler",
                    version=prowler_version,
                    vendor_name="Prowler/ProwlerPro",
                    feature=Feature(
                        name="iam_user_accesskey_unused",
                        uid="iam_user_accesskey_unused",
                        version=prowler_version,
                    ),
                ),
                version="1.0.0-rc.3",
            ),
            state_id=0,
            state="New",
            status_id=1,
            status="Success",
            type_uid=200101,
            type_name="Security Finding: Create",
            impact_id=0,
            impact="Unknown",
            confidence_id=0,
            confidence="Unknown",
            activity_id=1,
            activity_name="Create",
            category_uid=2,
            category_name="Findings",
            class_uid=2001,
            class_name="Security Finding",
        )
        output_options = mock.MagicMock()
        output_options.unix_timestamp = True
        assert fill_json_ocsf(input_audit_info, finding, output_options) == expected

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

    def test_generate_json_asff_status(self):
        assert generate_json_asff_status("PASS") == "PASSED"
        assert generate_json_asff_status("FAIL") == "FAILED"
        assert generate_json_asff_status("MUTED") == "MUTED"
        assert generate_json_asff_status("SOMETHING ELSE") == "NOT_AVAILABLE"

    def test_generate_json_asff_resource_tags(self):
        assert generate_json_asff_resource_tags(None) is None
        assert generate_json_asff_resource_tags([]) is None
        assert generate_json_asff_resource_tags([{}]) is None
        assert generate_json_asff_resource_tags([{"key1": "value1"}]) == {
            "key1": "value1"
        }
        assert generate_json_asff_resource_tags(
            [{"Key": "key1", "Value": "value1"}]
        ) == {"key1": "value1"}

    def test_generate_json_ocsf_status(self):
        assert generate_json_ocsf_status("PASS") == "Success"
        assert generate_json_ocsf_status("FAIL") == "Failure"
        assert generate_json_ocsf_status("MUTED") == "Other"
        assert generate_json_ocsf_status("SOMETHING ELSE") == "Unknown"

    def test_generate_json_ocsf_status_id(self):
        assert generate_json_ocsf_status_id("PASS") == 1
        assert generate_json_ocsf_status_id("FAIL") == 2
        assert generate_json_ocsf_status_id("MUTED") == 99
        assert generate_json_ocsf_status_id("SOMETHING ELSE") == 0

    def test_generate_json_ocsf_severity_id(self):
        assert generate_json_ocsf_severity_id("low") == 2
        assert generate_json_ocsf_severity_id("medium") == 3
        assert generate_json_ocsf_severity_id("high") == 4
        assert generate_json_ocsf_severity_id("critical") == 5
        assert generate_json_ocsf_severity_id("something else") == 0
