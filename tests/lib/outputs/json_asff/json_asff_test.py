from os import path

import mock

from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.check.models import Check_Report, load_check_metadata
from prowler.lib.outputs.json_asff.json_asff import (
    fill_json_asff,
    generate_json_asff_resource_tags,
    generate_json_asff_status,
)
from prowler.lib.outputs.json_asff.models import (
    Check_Output_JSON_ASFF,
    Compliance,
    ProductFields,
    Recommendation,
    Remediation,
    Resource,
    Severity,
)
from prowler.lib.utils.utils import hash_sha512
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, set_mocked_aws_provider

METADATA_FIXTURE_PATH = (
    f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
)


class TestOutputJSONASFF:
    def test_fill_json_asff(self):
        aws_provider = set_mocked_aws_provider()
        finding = Check_Report(load_check_metadata(METADATA_FIXTURE_PATH).json())
        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        expected = Check_Output_JSON_ASFF(
            Id=f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}",
            ProductArn="arn:aws:securityhub:eu-west-1::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
            ),
            GeneratorId="prowler-" + finding.check_metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.check_metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.check_metadata.Severity.upper()),
            Title=finding.check_metadata.CheckTitle,
            Description=finding.status_extended,
            Resources=[
                Resource(
                    Id="test-arn",
                    Type=finding.check_metadata.ResourceType,
                    Partition="aws",
                    Region="eu-west-1",
                )
            ],
            Compliance=Compliance(
                Status="PASS" + "ED",
                RelatedRequirements=[],
                AssociatedStandards=[],
            ),
            Remediation={
                "Recommendation": finding.check_metadata.Remediation.Recommendation
            },
        )

        assert fill_json_asff(aws_provider, finding) == expected

    def test_fill_json_asff_without_remediation_recommendation_url(self):
        aws_provider = set_mocked_aws_provider()
        finding = Check_Report(load_check_metadata(METADATA_FIXTURE_PATH).json())

        # Empty the Remediation.Recomendation.URL
        finding.check_metadata.Remediation.Recommendation.Url = ""

        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        expected = Check_Output_JSON_ASFF(
            Id=f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}",
            ProductArn="arn:aws:securityhub:eu-west-1::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
            ),
            GeneratorId="prowler-" + finding.check_metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.check_metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.check_metadata.Severity.upper()),
            Title=finding.check_metadata.CheckTitle,
            Description=finding.status_extended,
            Resources=[
                Resource(
                    Id="test-arn",
                    Type=finding.check_metadata.ResourceType,
                    Partition="aws",
                    Region="eu-west-1",
                )
            ],
            Compliance=Compliance(
                Status="PASS" + "ED",
                RelatedRequirements=[],
                AssociatedStandards=[],
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=finding.check_metadata.Remediation.Recommendation.Text,
                    Url="https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
                )
            ),
        )

        assert fill_json_asff(aws_provider, finding) == expected

    def test_fill_json_asff_with_long_description_and_remediation_recommendation_text(
        self,
    ):
        aws_provider = set_mocked_aws_provider()
        finding = Check_Report(load_check_metadata(METADATA_FIXTURE_PATH).json())

        # Empty the Remediation.Recomendation.URL
        finding.check_metadata.Remediation.Recommendation.Url = ""
        finding.check_metadata.Remediation.Recommendation.Text = "x" * 513

        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "x" * 2000  # it has to be limited to 1000+...

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        expected = Check_Output_JSON_ASFF(
            Id=f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}",
            ProductArn="arn:aws:securityhub:eu-west-1::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
            ),
            GeneratorId="prowler-" + finding.check_metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.check_metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.check_metadata.Severity.upper()),
            Title=finding.check_metadata.CheckTitle,
            Description=f"{finding.status_extended[:1021]}...",
            Resources=[
                Resource(
                    Id="test-arn",
                    Type=finding.check_metadata.ResourceType,
                    Partition="aws",
                    Region="eu-west-1",
                )
            ],
            Compliance=Compliance(
                Status="PASS" + "ED",
                RelatedRequirements=[],
                AssociatedStandards=[],
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=f"{'x' * 509}...",
                    Url="https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
                )
            ),
        )
        output_json_asff = fill_json_asff(aws_provider, finding)

        assert isinstance(output_json_asff, Check_Output_JSON_ASFF)
        assert output_json_asff.Id == expected.Id
        assert output_json_asff.ProductArn == expected.ProductArn
        assert output_json_asff.ProductFields == expected.ProductFields
        assert output_json_asff.GeneratorId == expected.GeneratorId
        assert output_json_asff.AwsAccountId == expected.AwsAccountId
        assert output_json_asff.Types == expected.Types
        assert output_json_asff.FirstObservedAt == expected.FirstObservedAt
        assert output_json_asff.UpdatedAt == expected.UpdatedAt
        assert output_json_asff.CreatedAt == expected.CreatedAt
        assert output_json_asff.Severity == expected.Severity
        assert output_json_asff.Title == expected.Title
        assert output_json_asff.Description == expected.Description
        assert output_json_asff.Resources == expected.Resources
        assert output_json_asff.Compliance == expected.Compliance
        assert isinstance(output_json_asff.Remediation, Remediation)
        assert isinstance(output_json_asff.Remediation.Recommendation, Recommendation)
        assert (
            output_json_asff.Remediation.Recommendation.Text
            == expected.Remediation.Recommendation.Text
        )
        assert (
            output_json_asff.Remediation.Recommendation.Url
            == expected.Remediation.Recommendation.Url
        )

    def test_fill_json_asff_with_long_associated_standards(self):
        aws_provider = set_mocked_aws_provider()
        with mock.patch(
            "prowler.lib.outputs.json_asff.json_asff.get_check_compliance",
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
            finding = Check_Report(load_check_metadata(METADATA_FIXTURE_PATH).json())

            # Empty the Remediation.Recomendation.URL
            finding.check_metadata.Remediation.Recommendation.Url = ""

            finding.resource_details = "Test resource details"
            finding.resource_id = "test-resource"
            finding.resource_arn = "test-arn"
            finding.region = "eu-west-1"
            finding.status = "PASS"
            finding.status_extended = "This is a test"

            timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

            expected = Check_Output_JSON_ASFF(
                Id=f"prowler-{finding.check_metadata.CheckID}-123456789012-eu-west-1-{hash_sha512('test-resource')}",
                ProductArn="arn:aws:securityhub:eu-west-1::product/prowler/prowler",
                ProductFields=ProductFields(
                    ProviderVersion=prowler_version, ProwlerResourceName="test-arn"
                ),
                GeneratorId="prowler-" + finding.check_metadata.CheckID,
                AwsAccountId=AWS_ACCOUNT_NUMBER,
                Types=finding.check_metadata.CheckType,
                FirstObservedAt=timestamp,
                UpdatedAt=timestamp,
                CreatedAt=timestamp,
                Severity=Severity(Label=finding.check_metadata.Severity.upper()),
                Title=finding.check_metadata.CheckTitle,
                Description=finding.status_extended,
                Resources=[
                    Resource(
                        Id="test-arn",
                        Type=finding.check_metadata.ResourceType,
                        Partition="aws",
                        Region="eu-west-1",
                    )
                ],
                Compliance=Compliance(
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
                        {
                            "StandardsId": "AWS-Well-Architected-Framework-Security-Pillar"
                        },
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
                ),
                Remediation=Remediation(
                    Recommendation=Recommendation(
                        Text=finding.check_metadata.Remediation.Recommendation.Text,
                        Url="https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
                    )
                ),
            )

            assert fill_json_asff(aws_provider, finding) == expected

    def test_generate_json_asff_status(self):
        assert generate_json_asff_status("PASS") == "PASSED"
        assert generate_json_asff_status("FAIL") == "FAILED"
        assert generate_json_asff_status("FAIL", True) == "WARNING"
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
