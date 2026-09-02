import json
from unittest import mock

from prowler.lib.check.models import Check_Report_AWS
from prowler.providers.aws.services.kms.kms_service import Key
from prowler.providers.aws.services.kms.lib.inventory import (
    generate_describe_error_report,
    generate_scan_error_reports,
    is_key_detail_unretrieved,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
)

METADATA = json.dumps(
    {
        "Provider": "aws",
        "CheckID": "kms_cmk_rotation_enabled",
        "CheckTitle": "KMS CMK rotation is enabled",
        "CheckType": [],
        "ServiceName": "kms",
        "SubServiceName": "",
        "ResourceIdTemplate": "arn:partition:kms:region:account-id:key/key-id",
        "Severity": "medium",
        "ResourceType": "AwsKmsKey",
        "Description": "Check KMS CMK rotation",
        "Risk": "Risk",
        "RelatedUrl": "",
        "Remediation": {
            "Code": {"NativeIaC": "", "Terraform": "", "CLI": "", "Other": ""},
            "Recommendation": {"Text": "", "Url": ""},
        },
        "Categories": [],
        "DependsOn": [],
        "RelatedTo": [],
        "Notes": "",
        "Compliance": [],
    }
)


class Test_KMS_Inventory:
    def test_is_key_detail_unretrieved(self):
        # Key with detail_retrieved=False
        key_unretrieved = Key(
            id="key-1",
            arn=f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/key-1",
            region=AWS_REGION_US_EAST_1,
            detail_retrieved=False,
        )
        assert is_key_detail_unretrieved(key_unretrieved) is True

        # Key with describe_error
        key_error = Key(
            id="key-2",
            arn=f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/key-2",
            region=AWS_REGION_US_EAST_1,
            detail_retrieved=False,
            describe_error="AccessDeniedException",
        )
        assert is_key_detail_unretrieved(key_error) is True

        # Key successfully retrieved
        key_retrieved = Key(
            id="key-3",
            arn=f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/key-3",
            region=AWS_REGION_US_EAST_1,
            detail_retrieved=True,
            manager="CUSTOMER",
            state="Enabled",
        )
        assert is_key_detail_unretrieved(key_retrieved) is False

    def test_generate_scan_error_reports(self):
        kms_client = mock.MagicMock()
        kms_client.audited_partition = "aws"
        kms_client.audited_account = AWS_ACCOUNT_NUMBER
        kms_client.keys_scan_errors = {AWS_REGION_US_EAST_1: "AccessDeniedException"}

        reports = generate_scan_error_reports(
            metadata=METADATA,
            action_text="customer-managed keys have automatic rotation enabled",
            client=kms_client,
        )

        assert len(reports) == 1
        assert isinstance(reports[0], Check_Report_AWS)
        assert reports[0].status == "MANUAL"
        assert reports[0].region == AWS_REGION_US_EAST_1
        assert reports[0].resource_id == "key/unknown"
        assert (
            reports[0].resource_arn
            == f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/unknown"
        )
        assert (
            reports[0].status_extended
            == f"KMS keys could not be listed in region {AWS_REGION_US_EAST_1} (AccessDeniedException); verify manually that customer-managed keys have automatic rotation enabled."
        )

    def test_generate_describe_error_report(self):
        key = Key(
            id="key-123",
            arn=f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/key-123",
            region=AWS_REGION_US_EAST_1,
            detail_retrieved=False,
            describe_error="AccessDeniedException",
        )

        report = generate_describe_error_report(
            metadata=METADATA,
            key=key,
            action_text="customer-managed keys have automatic rotation enabled",
        )

        assert isinstance(report, Check_Report_AWS)
        assert report.status == "MANUAL"
        assert report.region == AWS_REGION_US_EAST_1
        assert report.resource_id == "key-123"
        assert (
            report.resource_arn
            == f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/key-123"
        )
        assert (
            report.status_extended
            == "KMS key key-123 details could not be retrieved (AccessDeniedException); verify manually that customer-managed keys have automatic rotation enabled."
        )

    def test_generate_describe_error_report_fallback_error(self):
        key = Key(
            id="key-456",
            arn=f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/key-456",
            region=AWS_REGION_US_EAST_1,
            detail_retrieved=False,
            describe_error=None,
        )

        report = generate_describe_error_report(
            metadata=METADATA,
            key=key,
            action_text="customer-managed keys have automatic rotation enabled",
        )

        assert report.status == "MANUAL"
        assert (
            report.status_extended
            == "KMS key key-456 details could not be retrieved (DescribeKey failed); verify manually that customer-managed keys have automatic rotation enabled."
        )
