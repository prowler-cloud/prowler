from datetime import datetime
from io import StringIO
from json import loads
from os import path

from freezegun import freeze_time
from mock import patch

from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.outputs.asff.asff import (
    ASFF,
    AWSSecurityFindingFormat,
    Compliance,
    ProductFields,
    Recommendation,
    Remediation,
    Resource,
    Severity,
)
from prowler.lib.utils.utils import hash_sha512
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
)

METADATA_FIXTURE_PATH = (
    f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
)


class TestASFF:
    def test_asff(self):
        status = "PASS"
        finding = generate_finding_output(
            status=status,
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        associated_standards, compliance_summary = ASFF.format_compliance(
            finding.compliance
        )

        expected = AWSSecurityFindingFormat(
            Id=f"prowler-{finding.metadata.CheckID}-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}-{hash_sha512(finding.resource_uid)}",
            ProductArn=f"arn:{AWS_COMMERCIAL_PARTITION}:securityhub:{AWS_REGION_EU_WEST_1}::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version,
                ProwlerResourceName=finding.resource_uid,
            ),
            GeneratorId="prowler-" + finding.metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.metadata.Severity.value),
            Title=finding.metadata.CheckTitle,
            Resources=[
                Resource(
                    Id=finding.resource_uid,
                    Type=finding.metadata.ResourceType,
                    Partition=AWS_COMMERCIAL_PARTITION,
                    Region=AWS_REGION_EU_WEST_1,
                    Tags={"key1": "value1"},
                )
            ],
            Compliance=Compliance(
                Status=ASFF.generate_status(status),
                RelatedRequirements=compliance_summary,
                AssociatedStandards=associated_standards,
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=finding.metadata.Remediation.Recommendation.Text,
                    Url=finding.metadata.Remediation.Recommendation.Url,
                )
            ),
            Description=finding.status_extended,
        )

        asff = ASFF(findings=[finding])

        assert len(asff.data) == 1
        asff_finding = asff.data[0]

        assert asff_finding == expected

    def test_asff_without_remediation_recommendation_url(self):
        status = "PASS"
        finding = generate_finding_output(
            status=status,
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
        )
        finding.metadata.Remediation.Recommendation.Url = (
            "https://hub.prowler.com/check/check-id"
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        associated_standards, compliance_summary = ASFF.format_compliance(
            finding.compliance
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        expected = AWSSecurityFindingFormat(
            Id=f"prowler-{finding.metadata.CheckID}-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}-{hash_sha512(finding.resource_uid)}",
            ProductArn=f"arn:{AWS_COMMERCIAL_PARTITION}:securityhub:{AWS_REGION_EU_WEST_1}::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version,
                ProwlerResourceName=finding.resource_uid,
            ),
            GeneratorId="prowler-" + finding.metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.metadata.Severity.value),
            Title=finding.metadata.CheckTitle,
            Resources=[
                Resource(
                    Id=finding.resource_uid,
                    Type=finding.metadata.ResourceType,
                    Partition=AWS_COMMERCIAL_PARTITION,
                    Region=AWS_REGION_EU_WEST_1,
                    Tags={"key1": "value1"},
                )
            ],
            Compliance=Compliance(
                Status=ASFF.generate_status(status),
                RelatedRequirements=compliance_summary,
                AssociatedStandards=associated_standards,
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=finding.metadata.Remediation.Recommendation.Text,
                    Url="https://hub.prowler.com/check/check-id",
                )
            ),
            Description=finding.status_extended,
        )

        asff = ASFF(findings=[finding])

        assert len(asff.data) == 1
        asff_finding = asff.data[0]

        assert asff_finding == expected

    def test_asff_without_resource_tags(self):
        status = "PASS"
        finding = generate_finding_output(
            status=status,
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
        )
        finding.metadata.Remediation.Recommendation.Url = (
            "https://hub.prowler.com/check/check-id"
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        associated_standards, compliance_summary = ASFF.format_compliance(
            finding.compliance
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        expected = AWSSecurityFindingFormat(
            Id=f"prowler-{finding.metadata.CheckID}-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}-{hash_sha512(finding.resource_uid)}",
            ProductArn=f"arn:{AWS_COMMERCIAL_PARTITION}:securityhub:{AWS_REGION_EU_WEST_1}::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version,
                ProwlerResourceName=finding.resource_uid,
            ),
            GeneratorId="prowler-" + finding.metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.metadata.Severity.value),
            Title=finding.metadata.CheckTitle,
            Resources=[
                Resource(
                    Id=finding.resource_uid,
                    Type=finding.metadata.ResourceType,
                    Partition=AWS_COMMERCIAL_PARTITION,
                    Region=AWS_REGION_EU_WEST_1,
                    Tags=None,
                )
            ],
            Compliance=Compliance(
                Status=ASFF.generate_status(status),
                RelatedRequirements=compliance_summary,
                AssociatedStandards=associated_standards,
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=finding.metadata.Remediation.Recommendation.Text,
                    Url="https://hub.prowler.com/check/check-id",
                )
            ),
            Description=finding.status_extended,
        )

        asff = ASFF(findings=[finding])

        assert len(asff.data) == 1
        asff_finding = asff.data[0]

        assert asff_finding == expected

    def test_asff_with_long_description_and_remediation_recommendation_text(
        self,
    ):
        status = "PASS"
        finding = generate_finding_output(
            status=status,
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
        )
        finding.metadata.Remediation.Recommendation.Url = (
            "https://hub.prowler.com/check/check-id"
        )
        finding.metadata.Remediation.Recommendation.Text = "x" * 513

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        associated_standards, compliance_summary = ASFF.format_compliance(
            finding.compliance
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        expected = AWSSecurityFindingFormat(
            Id=f"prowler-{finding.metadata.CheckID}-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}-{hash_sha512(finding.resource_uid)}",
            ProductArn=f"arn:{AWS_COMMERCIAL_PARTITION}:securityhub:{AWS_REGION_EU_WEST_1}::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version,
                ProwlerResourceName=finding.resource_uid,
            ),
            GeneratorId="prowler-" + finding.metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.metadata.Severity.value),
            Title=finding.metadata.CheckTitle,
            Resources=[
                Resource(
                    Id=finding.resource_uid,
                    Type=finding.metadata.ResourceType,
                    Partition=AWS_COMMERCIAL_PARTITION,
                    Region=AWS_REGION_EU_WEST_1,
                    Tags={"key1": "value1"},
                )
            ],
            Compliance=Compliance(
                Status=ASFF.generate_status(status),
                RelatedRequirements=compliance_summary,
                AssociatedStandards=associated_standards,
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=f"{'x' * 509}...",
                    Url="https://hub.prowler.com/check/check-id",
                )
            ),
            Description=finding.status_extended,
        )

        asff = ASFF(findings=[finding])

        assert len(asff.data) == 1
        asff_finding = asff.data[0]

        assert asff_finding == expected

    def test_fill_json_asff_with_long_associated_standards(self):

        status = "PASS"
        finding = generate_finding_output(
            status=status,
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
            compliance={
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
                "KISA-ISMS-P-2023": ["2.6.1"],
                "KISA-ISMS-P-2023-korean": ["2.6.1"],
            },
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        associated_standards, compliance_summary = ASFF.format_compliance(
            finding.compliance
        )

        expected = AWSSecurityFindingFormat(
            Id=f"prowler-{finding.metadata.CheckID}-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}-{hash_sha512(finding.resource_uid)}",
            ProductArn=f"arn:{AWS_COMMERCIAL_PARTITION}:securityhub:{AWS_REGION_EU_WEST_1}::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version,
                ProwlerResourceName=finding.resource_uid,
            ),
            GeneratorId="prowler-" + finding.metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.metadata.CheckType,
            FirstObservedAt=timestamp,
            UpdatedAt=timestamp,
            CreatedAt=timestamp,
            Severity=Severity(Label=finding.metadata.Severity.value),
            Title=finding.metadata.CheckTitle,
            Resources=[
                Resource(
                    Id=finding.resource_uid,
                    Type=finding.metadata.ResourceType,
                    Partition=AWS_COMMERCIAL_PARTITION,
                    Region=AWS_REGION_EU_WEST_1,
                    Tags={"key1": "value1"},
                )
            ],
            Compliance=Compliance(
                Status=ASFF.generate_status(status),
                RelatedRequirements=compliance_summary,
                AssociatedStandards=associated_standards,
            ),
            Remediation=Remediation(
                Recommendation=Recommendation(
                    Text=finding.metadata.Remediation.Recommendation.Text,
                    Url=finding.metadata.Remediation.Recommendation.Url,
                )
            ),
            Description=finding.status_extended,
        )

        asff = ASFF(findings=[finding])

        assert len(asff.data) == 1
        asff_finding = asff.data[0]

        assert asff_finding == expected

    @freeze_time(datetime.now())
    def test_asff_write_to_file(self):
        mock_file = StringIO()

        status = "PASS"
        finding = generate_finding_output(
            status=status,
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
        )
        finding.metadata.Remediation.Recommendation.Url = (
            "https://hub.prowler.com/check/check-id"
        )

        timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        expected_asff = [
            {
                "SchemaVersion": "2018-10-08",
                "Id": "prowler-service_test_check_id-123456789012-eu-west-1-1aa220687",
                "ProductArn": "arn:aws:securityhub:eu-west-1::product/prowler/prowler",
                "RecordState": "ACTIVE",
                "ProductFields": {
                    "ProviderName": "Prowler",
                    "ProviderVersion": prowler_version,
                    "ProwlerResourceName": "test-arn",
                },
                "GeneratorId": "prowler-service_test_check_id",
                "AwsAccountId": "123456789012",
                "Types": ["test-type"],
                "FirstObservedAt": timestamp,
                "UpdatedAt": timestamp,
                "CreatedAt": timestamp,
                "Severity": {"Label": "HIGH"},
                "Title": "service_test_check_id",
                "Description": "This is a test",
                "Resources": [
                    {
                        "Type": "test-resource",
                        "Id": "test-arn",
                        "Partition": "aws",
                        "Region": "eu-west-1",
                        "Tags": {"key1": "value1"},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "test-compliance t e s t - c o m p l i a n c e"
                    ],
                    "AssociatedStandards": [{"StandardsId": "test-compliance"}],
                },
                "Remediation": {
                    "Recommendation": {
                        "Text": "",
                        "Url": "https://hub.prowler.com/check/check-id",
                    }
                },
            }
        ]

        asff = ASFF(findings=[finding])
        asff._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            asff.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        assert loads(content) == expected_asff

    def test_batch_write_data_to_file_without_findings(self):
        assert not ASFF([])._file_descriptor

    def test_asff_generate_status(self):
        assert ASFF.generate_status("PASS") == "PASSED"
        assert ASFF.generate_status("FAIL") == "FAILED"
        assert ASFF.generate_status("FAIL", True) == "WARNING"
        assert ASFF.generate_status("SOMETHING ELSE") == "NOT_AVAILABLE"
