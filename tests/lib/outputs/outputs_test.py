from unittest import mock

import pytest
from colorama import Fore, Style
from mock import MagicMock

from prowler.config.config import orange_color
from prowler.lib.outputs.outputs import (
    extract_findings_statistics,
    report,
    set_report_color,
)
from prowler.lib.outputs.utils import (
    parse_html_string,
    parse_json_tags,
    unroll_dict,
    unroll_dict_to_list,
    unroll_list,
    unroll_tags,
)
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


class TestOutputs:
    def test_set_report_color(self):
        test_status = ["PASS", "FAIL", "MANUAL"]
        test_colors = [Fore.GREEN, Fore.RED, Fore.YELLOW]

        for status in test_status:
            assert set_report_color(status) in test_colors

    def test_set_report_color_invalid(self):
        test_status = "INVALID"

        with pytest.raises(Exception) as exc:
            set_report_color(test_status)

        assert "Invalid Report Status: INVALID. Must be PASS, FAIL or MANUAL" in str(
            exc.value
        )

    def test_unroll_list_no_separator(self):
        list = ["test", "test1", "test2"]

        assert unroll_list(list) == "test | test1 | test2"

    def test_unroll_list_separator(self):
        list = ["test", "test1", "test2"]

        assert unroll_list(list, ",") == "test, test1, test2"

    def test_parse_html_string(self):
        string = "CISA: your-systems-3, your-data-1, your-data-2 | CIS-1.4: 2.1.1 | CIS-1.5: 2.1.1 | GDPR: article_32 | AWS-Foundational-Security-Best-Practices: s3 | HIPAA: 164_308_a_1_ii_b, 164_308_a_4_ii_a, 164_312_a_2_iv, 164_312_c_1, 164_312_c_2, 164_312_e_2_ii | GxP-21-CFR-Part-11: 11.10-c, 11.30 | GxP-EU-Annex-11: 7.1-data-storage-damage-protection | NIST-800-171-Revision-2: 3_3_8, 3_5_10, 3_13_11, 3_13_16 | NIST-800-53-Revision-4: sc_28 | NIST-800-53-Revision-5: au_9_3, cm_6_a, cm_9_b, cp_9_d, cp_9_8, pm_11_b, sc_8_3, sc_8_4, sc_13_a, sc_16_1, sc_28_1, si_19_4 | ENS-RD2022: mp.si.2.aws.s3.1 | NIST-CSF-1.1: ds_1 | RBI-Cyber-Security-Framework: annex_i_1_3 | FFIEC: d3-pc-am-b-12 | PCI-3.2.1: s3 | FedRamp-Moderate-Revision-4: sc-13, sc-28 | FedRAMP-Low-Revision-4: sc-13 | KISA-ISMS-P-2023: 2.6.1 | KISA-ISMS-P-2023-korean: 2.6.1"
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

&#x2022;KISA-ISMS-P-2023: 2.6.1

&#x2022;KISA-ISMS-P-2023-korean: 2.6.1
"""
        )

    def test_unroll_tags(self):
        dict_list = [
            {"Key": "name", "Value": "test"},
            {"Key": "project", "Value": "prowler"},
            {"Key": "environment", "Value": "dev"},
            {"Key": "terraform", "Value": "true"},
        ]

        assert unroll_tags(dict_list) == {
            "environment": "dev",
            "name": "test",
            "project": "prowler",
            "terraform": "true",
        }

    def test_unroll_dict_tags(self):
        tags_dict = {
            "environment": "dev",
            "name": "test",
            "project": "prowler",
            "terraform": "true",
        }

        assert unroll_tags(tags_dict) == {
            "environment": "dev",
            "name": "test",
            "project": "prowler",
            "terraform": "true",
        }

    def test_unroll_tags_unique(self):
        unique_dict_list = [
            {
                "test1": "value1",
                "test2": "value2",
                "test3": "value3",
            }
        ]
        assert unroll_tags(unique_dict_list) == {
            "test1": "value1",
            "test2": "value2",
            "test3": "value3",
        }

    def test_unroll_tags_lowercase(self):
        dict_list = [
            {"key": "name", "value": "test"},
            {"key": "project", "value": "prowler"},
            {"key": "environment", "value": "dev"},
            {"key": "terraform", "value": "true"},
        ]

        assert unroll_tags(dict_list) == {
            "environment": "dev",
            "name": "test",
            "project": "prowler",
            "terraform": "true",
        }

    def test_unroll_tags_only_list(self):
        tags_list = ["tag1", "tag2", "tag3"]

        assert unroll_tags(tags_list) == {
            "tag1": "",
            "tag2": "",
            "tag3": "",
        }

    def test_unroll_tags_with_key_only(self):
        tags = [{"key": "name"}]

        assert unroll_tags(tags) == {"name": ""}

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
            "KISA-ISMS-P-2023": ["2.6.1"],
            "KISA-ISMS-P-2023-korean": ["2.6.1"],
        }
        assert (
            unroll_dict(test_compliance_dict, separator=": ")
            == "CISA: your-systems-3, your-data-1, your-data-2 | CIS-1.4: 2.1.1 | CIS-1.5: 2.1.1 | GDPR: article_32 | AWS-Foundational-Security-Best-Practices: s3 | HIPAA: 164_308_a_1_ii_b, 164_308_a_4_ii_a, 164_312_a_2_iv, 164_312_c_1, 164_312_c_2, 164_312_e_2_ii | GxP-21-CFR-Part-11: 11.10-c, 11.30 | GxP-EU-Annex-11: 7.1-data-storage-damage-protection | NIST-800-171-Revision-2: 3_3_8, 3_5_10, 3_13_11, 3_13_16 | NIST-800-53-Revision-4: sc_28 | NIST-800-53-Revision-5: au_9_3, cm_6_a, cm_9_b, cp_9_d, cp_9_8, pm_11_b, sc_8_3, sc_8_4, sc_13_a, sc_16_1, sc_28_1, si_19_4 | ENS-RD2022: mp.si.2.aws.s3.1 | NIST-CSF-1.1: ds_1 | RBI-Cyber-Security-Framework: annex_i_1_3 | FFIEC: d3-pc-am-b-12 | PCI-3.2.1: s3 | FedRamp-Moderate-Revision-4: sc-13, sc-28 | FedRAMP-Low-Revision-4: sc-13 | KISA-ISMS-P-2023: 2.6.1 | KISA-ISMS-P-2023-korean: 2.6.1"
        )

    def test_unroll_dict_to_list(self):
        dict_A = {"A": "B"}
        list_A = ["A:B"]

        assert unroll_dict_to_list(dict_A) == list_A

        dict_B = {"A": ["B", "C"]}
        list_B = ["A:B, C"]

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


class TestExtractFindingStats:
    def test_extract_findings_statistics_different_resources(self):
        finding_1 = generate_finding_output(
            status="PASS",
            resource_uid="test_resource_1",
            severity="critical",
            muted=False,
        )
        finding_2 = generate_finding_output(
            status="FAIL",
            resource_uid="test_resource_2",
            severity="critical",
            muted=False,
        )

        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 1
        assert stats["total_muted_pass"] == 0
        assert stats["total_fail"] == 1
        assert stats["total_muted_fail"] == 0
        assert stats["resources_count"] == 2
        assert stats["findings_count"] == 2
        assert stats["total_critical_severity_fail"] == 1
        assert stats["total_critical_severity_pass"] == 1
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 0
        assert stats["total_medium_severity_fail"] == 0
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 0
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 0
        assert stats["total_informational_severity_pass"] == 0
        assert stats["all_fails_are_muted"] is False

    def test_extract_findings_statistics_same_resources(self):
        finding_1 = generate_finding_output(
            status="PASS",
            resource_uid="test_resource_1",
            severity="critical",
            muted=False,
        )
        finding_2 = generate_finding_output(
            status="PASS",
            resource_uid="test_resource_1",
            severity="critical",
            muted=False,
        )

        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 2
        assert stats["total_muted_pass"] == 0
        assert stats["total_fail"] == 0
        assert stats["total_muted_fail"] == 0
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 2
        assert stats["total_critical_severity_fail"] == 0
        assert stats["total_critical_severity_pass"] == 2
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 0
        assert stats["total_medium_severity_fail"] == 0
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 0
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 0
        assert stats["total_informational_severity_pass"] == 0
        assert stats["all_fails_are_muted"] is True

    def test_extract_findings_statistics_manual_resources(self):
        finding_1 = generate_finding_output(
            status="MANUAL",
            resource_uid="test_resource_1",
            severity="critical",
            muted=False,
        )
        finding_2 = generate_finding_output(
            status="PASS",
            resource_uid="test_resource_1",
            severity="critical",
            muted=False,
        )

        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 1
        assert stats["total_muted_pass"] == 0
        assert stats["total_fail"] == 0
        assert stats["total_muted_fail"] == 0
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 1
        assert stats["total_critical_severity_fail"] == 0
        assert stats["total_critical_severity_pass"] == 1
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 0
        assert stats["total_medium_severity_fail"] == 0
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 0
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 0
        assert stats["total_informational_severity_pass"] == 0
        assert stats["all_fails_are_muted"] is True

    def test_extract_findings_statistics_no_findings(self):
        stats = extract_findings_statistics([])
        assert stats["total_pass"] == 0
        assert stats["total_muted_pass"] == 0
        assert stats["total_fail"] == 0
        assert stats["total_muted_fail"] == 0
        assert stats["resources_count"] == 0
        assert stats["findings_count"] == 0
        assert stats["total_critical_severity_fail"] == 0
        assert stats["total_critical_severity_pass"] == 0
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 0
        assert stats["total_medium_severity_fail"] == 0
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 0
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 0
        assert stats["total_informational_severity_pass"] == 0
        assert stats["all_fails_are_muted"] is True

    def test_extract_findings_statistics_all_fail_are_muted(self):
        finding_1 = generate_finding_output(
            status="FAIL",
            resource_uid="test_resource_1",
            severity="medium",
            muted=True,
        )
        finding_2 = generate_finding_output(
            status="FAIL",
            resource_uid="test_resource_2",
            severity="low",
            muted=True,
        )

        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 0
        assert stats["total_muted_pass"] == 0
        assert stats["total_fail"] == 2
        assert stats["total_muted_fail"] == 2
        assert stats["resources_count"] == 2
        assert stats["findings_count"] == 2
        assert stats["total_critical_severity_fail"] == 0
        assert stats["total_critical_severity_pass"] == 0
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 0
        assert stats["total_medium_severity_fail"] == 1
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 1
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 0
        assert stats["total_informational_severity_pass"] == 0
        assert stats["all_fails_are_muted"] is True

    def test_extract_findings_statistics_all_fail_are_not_muted(self):
        finding_1 = generate_finding_output(
            status="FAIL",
            resource_uid="test_resource_1",
            severity="critical",
            muted=True,
        )
        finding_2 = generate_finding_output(
            status="FAIL",
            resource_uid="test_resource_1",
            severity="critical",
            muted=False,
        )

        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 0
        assert stats["total_muted_pass"] == 0
        assert stats["total_fail"] == 2
        assert stats["total_muted_fail"] == 1
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 2
        assert stats["total_critical_severity_fail"] == 2
        assert stats["total_critical_severity_pass"] == 0
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 0
        assert stats["total_medium_severity_fail"] == 0
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 0
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 0
        assert stats["total_informational_severity_pass"] == 0
        assert stats["all_fails_are_muted"] is False

    def test_extract_findings_statistics_all_passes_are_not_muted(self):
        finding_1 = generate_finding_output(
            status="PASS",
            resource_uid="test_resource_1",
            severity="critical",
            muted=True,
        )
        finding_2 = generate_finding_output(
            status="PASS",
            resource_uid="test_resource_1",
            severity="high",
            muted=False,
        )

        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 2
        assert stats["total_muted_pass"] == 1
        assert stats["total_fail"] == 0
        assert stats["total_muted_fail"] == 0
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 2
        assert stats["total_critical_severity_fail"] == 0
        assert stats["total_critical_severity_pass"] == 1
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 1
        assert stats["total_medium_severity_fail"] == 0
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 0
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 0
        assert stats["total_informational_severity_pass"] == 0
        assert stats["all_fails_are_muted"] is True

    def test_extract_findings_statistics_all_passes_are_muted(self):
        finding_1 = generate_finding_output(
            status="PASS",
            resource_uid="test_resource_1",
            severity="informational",
            muted=True,
        )
        finding_2 = generate_finding_output(
            status="FAIL",
            resource_uid="test_resource_1",
            severity="informational",
            muted=True,
        )

        findings = [finding_1, finding_2]

        stats = extract_findings_statistics(findings)
        assert stats["total_pass"] == 1
        assert stats["total_muted_pass"] == 1
        assert stats["total_fail"] == 1
        assert stats["total_muted_fail"] == 1
        assert stats["resources_count"] == 1
        assert stats["findings_count"] == 2
        assert stats["total_critical_severity_fail"] == 0
        assert stats["total_critical_severity_pass"] == 0
        assert stats["total_high_severity_fail"] == 0
        assert stats["total_high_severity_pass"] == 0
        assert stats["total_medium_severity_fail"] == 0
        assert stats["total_medium_severity_pass"] == 0
        assert stats["total_low_severity_fail"] == 0
        assert stats["total_low_severity_pass"] == 0
        assert stats["total_informational_severity_fail"] == 1
        assert stats["total_informational_severity_pass"] == 1
        assert stats["all_fails_are_muted"] is True


class TestReport:
    def test_report_with_aws_provider_not_muted_pass(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.region = "us-east-1"
        finding_1.check_metadata.Provider = "aws"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.region = "us-west-2"
        finding_2.check_metadata.Provider = "aws"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "aws"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_1, finding_2]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.GREEN}PASS{Style.RESET_ALL} us-west-2: Extended status 2"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_aws_provider_not_muted_fail(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.region = "us-east-1"
        finding_1.check_metadata.Provider = "aws"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "FAIL"
        finding_2.muted = False
        finding_2.region = "us-west-2"
        finding_2.check_metadata.Provider = "aws"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "aws"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_1, finding_2]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.RED}FAIL{Style.RESET_ALL} us-west-2: Extended status 2"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_aws_provider_not_muted_manual(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.region = "us-east-1"
        finding_1.check_metadata.Provider = "aws"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "MANUAL"
        finding_2.muted = False
        finding_2.region = "us-west-2"
        finding_2.check_metadata.Provider = "aws"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL", "MANUAL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "aws"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_1, finding_2]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.YELLOW}MANUAL{Style.RESET_ALL} us-west-2: Extended status 2"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_aws_provider_muted(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.region = "us-east-1"
        finding_1.check_metadata.Provider = "aws"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = True
        finding_2.region = "us-west-2"
        finding_2.check_metadata.Provider = "aws"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "aws"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_1, finding_2]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{orange_color}MUTED (FAIL){Style.RESET_ALL} us-east-1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_azure_provider_not_muted_pass(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.subscription = "test_subscription_2"
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "azure"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.subscription = "test_subscription_1"
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "azure"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "azure"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.GREEN}PASS{Style.RESET_ALL} test_location_2: Extended status 2"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_azure_provider_not_muted_fail(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = False
        finding_1.subscription = "test_subscription_2"
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "azure"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.subscription = "test_subscription_1"
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "azure"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "azure"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.RED}FAIL{Style.RESET_ALL} test_location_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_azure_provider_not_muted_manual(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "MANUAL"
        finding_1.muted = False
        finding_1.subscription = "test_subscription_2"
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "azure"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.subscription = "test_subscription_1"
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "azure"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL", "MANUAL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "azure"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.YELLOW}MANUAL{Style.RESET_ALL} test_location_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_azure_provider_muted(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.subscription = "test_subscription_2"
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "azure"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.subscription = "test_subscription_1"
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "azure"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "azure"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{orange_color}MUTED (FAIL){Style.RESET_ALL} test_location_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_gcp_provider_not_muted_pass(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "gcp"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "gcp"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "gcp"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.GREEN}PASS{Style.RESET_ALL} test_location_2: Extended status 2"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_gcp_provider_not_muted_fail(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = False
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "gcp"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "gcp"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "gcp"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.RED}FAIL{Style.RESET_ALL} test_location_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_gcp_provider_not_muted_manual(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "MANUAL"
        finding_1.muted = False
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "gcp"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "gcp"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL", "MANUAL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "gcp"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.YELLOW}MANUAL{Style.RESET_ALL} test_location_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_gcp_provider_muted(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.location = "test_location_1"
        finding_1.check_metadata.Provider = "gcp"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.location = "test_location_2"
        finding_2.check_metadata.Provider = "gcp"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "gcp"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{orange_color}MUTED (FAIL){Style.RESET_ALL} test_location_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_kubernetes_provider_not_muted_pass(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.namespace = "test_namespace_1"
        finding_1.check_metadata.Provider = "kubernetes"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.namespace = "test_namespace_2"
        finding_2.check_metadata.Provider = "kubernetes"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "kubernetes"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.GREEN}PASS{Style.RESET_ALL} test_namespace_2: Extended status 2"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_kubernetes_provider_not_muted_fail(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = False
        finding_1.namespace = "test_namespace_1"
        finding_1.check_metadata.Provider = "kubernetes"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.namespace = "test_namespace_2"
        finding_2.check_metadata.Provider = "kubernetes"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "kubernetes"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.RED}FAIL{Style.RESET_ALL} test_namespace_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_kubernetes_provider_not_muted_manual(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "MANUAL"
        finding_1.muted = False
        finding_1.namespace = "test_namespace_1"
        finding_1.check_metadata.Provider = "kubernetes"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.namespace = "test_namespace_2"
        finding_2.check_metadata.Provider = "kubernetes"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL", "MANUAL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "kubernetes"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{Fore.YELLOW}MANUAL{Style.RESET_ALL} test_namespace_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_kubernetes_provider_muted(self):
        # Mocking check_findings and provider
        finding_1 = MagicMock()
        finding_1.status = "FAIL"
        finding_1.muted = True
        finding_1.namespace = "test_namespace_1"
        finding_1.check_metadata.Provider = "kubernetes"
        finding_1.status_extended = "Extended status 1"

        finding_2 = MagicMock()
        finding_2.status = "PASS"
        finding_2.muted = False
        finding_2.namespace = "test_namespace_2"
        finding_2.check_metadata.Provider = "kubernetes"
        finding_2.status_extended = "Extended status 2"

        check_findings = [finding_2, finding_1]  # Unsorted list

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "kubernetes"

        # Assertions
        with mock.patch("builtins.print") as mocked_print:
            # Call the report method
            report(check_findings, provider, output_options)

            # Assertions
            check_findings_sorted = [finding_2, finding_1]
            assert (
                check_findings == check_findings_sorted
            )  # Check if the list was sorted

            mocked_print.assert_any_call(
                f"\t{orange_color}MUTED (FAIL){Style.RESET_ALL} test_namespace_1: Extended status 1"
            )
            mocked_print.assert_called()  # Verifying that print was called

    def test_report_with_googleworkspace_provider_pass(self):
        finding = MagicMock()
        finding.status = "PASS"
        finding.muted = False
        finding.location = "global"
        finding.check_metadata.Provider = "googleworkspace"
        finding.status_extended = "Domain has 2 super administrators"

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "googleworkspace"

        with mock.patch("builtins.print") as mocked_print:
            report([finding], provider, output_options)
            mocked_print.assert_called()

    def test_report_with_googleworkspace_provider_fail(self):
        finding = MagicMock()
        finding.status = "FAIL"
        finding.muted = False
        finding.location = "global"
        finding.check_metadata.Provider = "googleworkspace"
        finding.status_extended = "Domain has only 1 super administrator"

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = False

        provider = MagicMock()
        provider.type = "googleworkspace"

        with mock.patch("builtins.print") as mocked_print:
            report([finding], provider, output_options)
            mocked_print.assert_called()

    def test_report_with_no_findings(self):
        # Mocking check_findings and provider
        check_findings = []

        output_options = MagicMock()
        output_options.verbose = True
        output_options.status = ["PASS", "FAIL"]
        output_options.fixer = True

        provider = MagicMock()
        provider.type = "azure"

        with mock.patch("builtins.print") as mocked_print:
            report(check_findings, provider, output_options)

            # Assertions
            mocked_print.assert_any_call(
                f"\t{Fore.YELLOW}INFO{Style.RESET_ALL} There are no resources"
            )
            mocked_print.assert_called()  # Verifying that print was called
