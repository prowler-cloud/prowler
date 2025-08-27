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
        finding.metadata.Remediation.Recommendation.Url = ""

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
                    Url="https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
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
        finding.metadata.Remediation.Recommendation.Url = ""

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
                    Url="https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
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
        finding.metadata.Remediation.Recommendation.Url = ""
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
                    Url="https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
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
        finding.metadata.Remediation.Recommendation.Url = ""

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
                        "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html",
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

    def test_asff_preserves_existing_timestamps(self):
        """Test that ASFF preserves existing timestamps for findings that already exist in Security Hub."""
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

        # Mock existing finding timestamps from Security Hub
        finding_id = f"prowler-{finding.metadata.CheckID}-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}-{hash_sha512(finding.resource_uid)}"
        existing_timestamps = {
            finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        associated_standards, compliance_summary = ASFF.format_compliance(
            finding.compliance
        )

        expected = AWSSecurityFindingFormat(
            Id=finding_id,
            ProductArn=f"arn:{AWS_COMMERCIAL_PARTITION}:securityhub:{AWS_REGION_EU_WEST_1}::product/prowler/prowler",
            ProductFields=ProductFields(
                ProviderVersion=prowler_version,
                ProwlerResourceName=finding.resource_uid,
            ),
            GeneratorId="prowler-" + finding.metadata.CheckID,
            AwsAccountId=AWS_ACCOUNT_NUMBER,
            Types=finding.metadata.CheckType,
            FirstObservedAt="2023-01-01T00:00:00Z",  # Should preserve existing timestamp
            UpdatedAt=current_timestamp,  # Should update with current timestamp
            CreatedAt="2023-01-01T00:00:00Z",  # Should preserve existing timestamp
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

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        assert len(asff.data) == 1
        asff_finding = asff.data[0]

        assert asff_finding == expected
        # Verify that FirstObservedAt and CreatedAt are preserved
        assert asff_finding.FirstObservedAt == "2023-01-01T00:00:00Z"
        assert asff_finding.CreatedAt == "2023-01-01T00:00:00Z"
        # Verify that UpdatedAt uses current timestamp
        assert asff_finding.UpdatedAt == current_timestamp

    def test_asff_uses_current_timestamps_for_new_findings(self):
        """Test that ASFF uses current timestamps for new findings when no existing timestamps are provided."""
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

        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

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
            FirstObservedAt=current_timestamp,  # Should use current timestamp for new findings
            UpdatedAt=current_timestamp,
            CreatedAt=current_timestamp,
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
        # Verify that all timestamps use current timestamp for new findings
        assert asff_finding.FirstObservedAt == current_timestamp
        assert asff_finding.UpdatedAt == current_timestamp
        assert asff_finding.CreatedAt == current_timestamp

    def test_asff_constructor_with_existing_timestamps(self):
        """Test that ASFF constructor properly stores existing timestamps."""
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

        # Generate the actual finding ID that will be used
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Existing timestamps with the correct ID
        existing_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        # Create ASFF output with timestamps in constructor
        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # Verify that timestamps are preserved
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        assert finding_asff.FirstObservedAt == "2023-01-01T00:00:00Z"
        assert finding_asff.CreatedAt == "2023-01-01T00:00:00Z"

    def test_asff_constructor_without_existing_timestamps(self):
        """Test that ASFF constructor works without existing timestamps."""
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

        # Create ASFF output without timestamps parameter
        asff = ASFF(findings=[finding])

        # Verify that current timestamps are used
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding_asff.FirstObservedAt == current_timestamp
        assert finding_asff.CreatedAt == current_timestamp
        assert finding_asff.UpdatedAt == current_timestamp

    def test_asff_transform_method_parameter_override(self):
        """Test that transform method parameter overrides constructor parameter."""
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

        # Generate the actual finding ID
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Constructor timestamps
        constructor_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        # Transform method timestamps (different)
        transform_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-02-01T00:00:00Z",
                "CreatedAt": "2023-02-01T00:00:00Z",
                "UpdatedAt": "2023-02-01T00:00:00Z",
            }
        }

        # Create ASFF output with constructor timestamps
        asff = ASFF(
            findings=[finding], existing_findings_timestamps=constructor_timestamps
        )

        # Clear existing data and transform with different timestamps
        asff._data = []
        asff.transform([finding], transform_timestamps)

        # Verify that transform method timestamps are used
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        assert finding_asff.FirstObservedAt == "2023-02-01T00:00:00Z"
        assert finding_asff.CreatedAt == "2023-02-01T00:00:00Z"

    def test_asff_transform_method_without_parameter(self):
        """Test that transform method uses constructor timestamps when no parameter is provided."""
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

        # Generate the actual finding ID
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Constructor timestamps
        constructor_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        # Create ASFF output with timestamps in constructor
        asff = ASFF(
            findings=[finding], existing_findings_timestamps=constructor_timestamps
        )

        # Clear existing data and transform without parameter (should use constructor timestamps)
        asff._data = []
        asff.transform([finding])

        # Verify that constructor timestamps are used
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        assert finding_asff.FirstObservedAt == "2023-01-01T00:00:00Z"
        assert finding_asff.CreatedAt == "2023-01-01T00:00:00Z"

    def test_asff_handles_partial_existing_timestamps(self):
        """Test that ASFF handles cases where only some timestamp fields exist in the existing data."""
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

        # Generate the actual finding ID
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Mock existing finding with only FirstObservedAt timestamp
        existing_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                # Missing CreatedAt and UpdatedAt
            }
        }

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # Should preserve FirstObservedAt, use current timestamp for missing fields
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        assert finding_asff.FirstObservedAt == "2023-01-01T00:00:00Z"
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding_asff.CreatedAt == current_timestamp
        assert finding_asff.UpdatedAt == current_timestamp

    def test_asff_handles_missing_timestamp_fields(self):
        """Test that ASFF handles cases where timestamp fields are missing from the dictionary."""
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

        # Generate the actual finding ID
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Mock existing finding with missing keys (not None values)
        existing_timestamps = {
            actual_finding_id: {
                # Missing FirstObservedAt, CreatedAt, and UpdatedAt keys entirely
            }
        }

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # Should use current timestamp for all fields when keys are missing
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding_asff.FirstObservedAt == current_timestamp
        assert finding_asff.CreatedAt == current_timestamp
        assert finding_asff.UpdatedAt == current_timestamp

    def test_asff_handles_empty_existing_timestamps_dict(self):
        """Test that ASFF handles empty existing timestamps dictionary."""
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

        # Empty existing timestamps
        existing_timestamps = {}

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # Should use current timestamp for all fields
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding_asff.FirstObservedAt == current_timestamp
        assert finding_asff.CreatedAt == current_timestamp
        assert finding_asff.UpdatedAt == current_timestamp

    def test_asff_handles_none_existing_timestamps(self):
        """Test that ASFF handles None existing timestamps parameter."""
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

        # None existing timestamps
        asff = ASFF(findings=[finding], existing_findings_timestamps=None)

        # Should use current timestamp for all fields
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding_asff.FirstObservedAt == current_timestamp
        assert finding_asff.CreatedAt == current_timestamp
        assert finding_asff.UpdatedAt == current_timestamp

    def test_asff_finding_id_generation_consistency(self):
        """Test that finding ID generation is consistent between timestamp lookup and ASFF creation."""
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

        # Generate the expected finding ID
        expected_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Create existing timestamps with the expected ID
        existing_timestamps = {
            expected_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # Verify that the finding ID matches and timestamps are preserved
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        assert finding_asff.Id == expected_finding_id
        assert finding_asff.FirstObservedAt == "2023-01-01T00:00:00Z"
        assert finding_asff.CreatedAt == "2023-01-01T00:00:00Z"

    def test_asff_multiple_findings_mixed_timestamps(self):
        """Test that ASFF handles multiple findings with mixed existing and new timestamps."""
        # Create multiple findings
        finding1 = generate_finding_output(
            status="PASS",
            status_extended="First finding",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource-1",
            resource_uid="test-arn-1",
            resource_tags={"key1": "value1"},
        )

        finding2 = generate_finding_output(
            status="FAIL",
            status_extended="Second finding",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource-2",
            resource_uid="test-arn-2",
            resource_tags={"key2": "value2"},
        )

        # Only first finding has existing timestamps
        finding1_id = f"prowler-{finding1.metadata.CheckID}-{finding1.account_uid}-{finding1.region}-{hash_sha512(finding1.resource_uid)}"
        existing_timestamps = {
            finding1_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        asff = ASFF(
            findings=[finding1, finding2],
            existing_findings_timestamps=existing_timestamps,
        )

        # Verify that first finding preserves timestamps
        assert len(asff.data) == 2

        finding1_asff = asff.data[0]
        assert finding1_asff.FirstObservedAt == "2023-01-01T00:00:00Z"
        assert finding1_asff.CreatedAt == "2023-01-01T00:00:00Z"

        # Verify that second finding uses current timestamps
        finding2_asff = asff.data[1]
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding2_asff.FirstObservedAt == current_timestamp
        assert finding2_asff.CreatedAt == current_timestamp
        assert finding2_asff.UpdatedAt == current_timestamp

    def test_asff_updated_at_always_current(self):
        """Test that UpdatedAt is always set to current timestamp regardless of existing data."""
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

        # Generate the actual finding ID
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Existing timestamps with old UpdatedAt
        existing_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",  # Old timestamp
            }
        }

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # Verify that UpdatedAt is current time, not the old timestamp
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        assert finding_asff.FirstObservedAt == "2023-01-01T00:00:00Z"
        assert finding_asff.CreatedAt == "2023-01-01T00:00:00Z"
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding_asff.UpdatedAt == current_timestamp
        assert finding_asff.UpdatedAt != "2023-01-01T00:00:00Z"

    def test_asff_handles_duplicate_finding_ids(self):
        """Test that ASFF handles cases where multiple findings might have the same ID."""
        # Create findings with same check ID but different resources
        finding1 = generate_finding_output(
            status="PASS",
            status_extended="First finding",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource-1",
            resource_uid="test-arn-1",
            resource_tags={"key1": "value1"},
        )

        finding2 = generate_finding_output(
            status="FAIL",
            status_extended="Second finding",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource-2",
            resource_uid="test-arn-2",
            resource_tags={"key2": "value2"},
        )

        # Create existing timestamps for one finding
        finding1_id = f"prowler-{finding1.metadata.CheckID}-{finding1.account_uid}-{finding1.region}-{hash_sha512(finding1.resource_uid)}"
        existing_timestamps = {
            finding1_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        asff = ASFF(
            findings=[finding1, finding2],
            existing_findings_timestamps=existing_timestamps,
        )

        # Verify that findings are processed correctly
        assert len(asff.data) == 2

        # First finding should preserve timestamps
        finding1_asff = asff.data[0]
        assert finding1_asff.FirstObservedAt == "2023-01-01T00:00:00Z"
        assert finding1_asff.CreatedAt == "2023-01-01T00:00:00Z"

        # Second finding should use current timestamps
        finding2_asff = asff.data[1]
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding2_asff.FirstObservedAt == current_timestamp
        assert finding2_asff.CreatedAt == current_timestamp

    def test_asff_handles_manual_status_findings(self):
        """Test that ASFF correctly skips MANUAL status findings even with existing timestamps."""
        finding = generate_finding_output(
            status="MANUAL",
            status_extended="This is a manual finding",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
        )

        # Generate the actual finding ID
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Existing timestamps
        existing_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # MANUAL findings should be skipped
        assert len(asff.data) == 0

    def test_asff_timestamp_format_consistency(self):
        """Test that all timestamps use consistent ISO 8601 format."""
        finding = generate_finding_output(
            status="PASS",
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
        )

        # Generate the actual finding ID
        actual_finding_id = f"prowler-{finding.metadata.CheckID}-{finding.account_uid}-{finding.region}-{hash_sha512(finding.resource_uid)}"

        # Existing timestamps in different formats
        existing_timestamps = {
            actual_finding_id: {
                "FirstObservedAt": "2023-01-01T00:00:00Z",
                "CreatedAt": "2023-01-01T00:00:00Z",
                "UpdatedAt": "2023-01-01T00:00:00Z",
            }
        }

        asff = ASFF(
            findings=[finding], existing_findings_timestamps=existing_timestamps
        )

        # Verify that all timestamps use consistent format
        assert len(asff.data) == 1
        finding_asff = asff.data[0]

        # Check format: YYYY-MM-DDTHH:MM:SSZ
        import re

        timestamp_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"

        assert re.match(timestamp_pattern, finding_asff.FirstObservedAt)
        assert re.match(timestamp_pattern, finding_asff.CreatedAt)
        assert re.match(timestamp_pattern, finding_asff.UpdatedAt)

    def test_asff_backward_compatibility(self):
        """Test that ASFF maintains backward compatibility when no existing timestamps are provided."""
        finding = generate_finding_output(
            status="PASS",
            status_extended="This is a test",
            region=AWS_REGION_EU_WEST_1,
            resource_details="Test resource details",
            resource_name="test-resource",
            resource_uid="test-arn",
            resource_tags={"key1": "value1"},
        )

        # Test with no existing timestamps (backward compatibility)
        asff = ASFF(findings=[finding])

        # Verify that current timestamps are used
        assert len(asff.data) == 1
        finding_asff = asff.data[0]
        current_timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert finding_asff.FirstObservedAt == current_timestamp
        assert finding_asff.UpdatedAt == current_timestamp
        assert finding_asff.CreatedAt == current_timestamp
