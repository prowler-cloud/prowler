from unittest import mock

import pytest
from colorama import Fore

from prowler.lib.outputs.csv.csv import generate_csv_fields
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.outputs import extract_findings_statistics, set_report_color
from prowler.lib.outputs.utils import (
    parse_html_string,
    parse_json_tags,
    unroll_dict,
    unroll_dict_to_list,
    unroll_list,
    unroll_tags,
)


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

        assert generate_csv_fields(Finding) == expected

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
