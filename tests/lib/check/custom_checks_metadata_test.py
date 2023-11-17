import logging
import os

import pytest

from prowler.lib.check.custom_checks_metadata import (
    parse_custom_checks_metadata_file,
    update_check_metadata,
    update_checks_metadata,
)
from prowler.lib.check.models import (
    Check_Metadata_Model,
    Code,
    Recommendation,
    Remediation,
)

CUSTOM_CHECKS_METADATA_FIXTURE_FILE = f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/custom_checks_metadata_example.yaml"
CUSTOM_CHECKS_METADATA_FIXTURE_FILE_NOT_VALID = f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/custom_checks_metadata_example_not_valid.yaml"

AWS_PROVIDER = "aws"
AZURE_PROVIDER = "azure"
GCP_PROVIDER = "gcp"

S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME = "s3_bucket_level_public_access_block"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY = "medium"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_METADATA = Check_Metadata_Model(
    Provider="aws",
    CheckID=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME,
    CheckTitle="Check S3 Bucket Level Public Access Block.",
    CheckType=["Data Protection"],
    CheckAliases=[],
    ServiceName="s3",
    SubServiceName="",
    ResourceIdTemplate="arn:partition:s3:::bucket_name",
    Severity=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY,
    ResourceType="AwsS3Bucket",
    Description="Check S3 Bucket Level Public Access Block.",
    Risk="Public access policies may be applied to sensitive data buckets.",
    RelatedUrl="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    Remediation=Remediation(
        Code=Code(
            NativeIaC="",
            Terraform="https://docs.bridgecrew.io/docs/bc_aws_s3_20#terraform",
            CLI="aws s3api put-public-access-block --region <REGION_NAME> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true --bucket <BUCKET_NAME>",
            Other="https://github.com/cloudmatos/matos/tree/master/remediations/aws/s3/s3/block-public-access",
        ),
        Recommendation=Recommendation(
            Text="You can enable Public Access Block at the bucket level to prevent the exposure of your data stored in S3.",
            Url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ),
    ),
    Categories=[],
    DependsOn=[],
    RelatedTo=[],
    Notes="",
    Compliance=[],
)


class TestCustomChecksMetadata:
    def test_parse_custom_checks_metadata_file_for_aws(self):
        assert parse_custom_checks_metadata_file(
            AWS_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE
        ) == {
            "Checks": {
                "s3_bucket_level_public_access_block": {"Severity": "high"},
                "s3_bucket_no_mfa_delete": {"Severity": "high"},
            }
        }

    def test_parse_custom_checks_metadata_file_for_azure(self):
        assert parse_custom_checks_metadata_file(
            AZURE_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE
        ) == {"Checks": {"sqlserver_auditing_enabled": {"Severity": "high"}}}

    def test_parse_custom_checks_metadata_file_for_gcp(self):
        assert parse_custom_checks_metadata_file(
            GCP_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE
        ) == {"Checks": {"bigquery_dataset_cmk_encryption": {"Severity": "low"}}}

    def test_parse_custom_checks_metadata_file_for_aws_validation_error(self, caplog):
        caplog.set_level(logging.CRITICAL)

        with pytest.raises(SystemExit) as error:
            parse_custom_checks_metadata_file(
                AWS_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE_NOT_VALID
            )
        assert error.type == SystemExit
        assert error.value.code == 1
        assert "'Checks' is a required property" in caplog.text

    def test_update_checks_metadata(self):
        updated_severity = "high"
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_METADATA,
        }
        custom_checks_metadata = {
            "Checks": {
                S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: {
                    "Severity": updated_severity
                },
            }
        }

        bulk_checks_metadata_updated = update_checks_metadata(
            bulk_checks_metadata, custom_checks_metadata
        ).get(S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME)

        assert bulk_checks_metadata_updated.Severity == updated_severity

    def test_update_checks_metadata_not_present_field(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_METADATA,
        }
        custom_checks_metadata = {
            "Checks": {
                S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: {
                    "RandomField": "random_value"
                },
            }
        }

        bulk_checks_metadata_updated = update_checks_metadata(
            bulk_checks_metadata, custom_checks_metadata
        ).get(S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME)

        assert (
            bulk_checks_metadata_updated.Severity
            == S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY
        )

    def test_update_check_metadata(self):
        updated_severity = "high"
        custom_checks_metadata = {"Severity": updated_severity}

        check_metadata_updated = update_check_metadata(
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_METADATA, custom_checks_metadata
        )
        assert check_metadata_updated.Severity == updated_severity

    def test_update_check_metadata_not_present_field(self):
        custom_checks_metadata = {"RandomField": "random_value"}

        check_metadata_updated = update_check_metadata(
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_METADATA, custom_checks_metadata
        )
        assert (
            check_metadata_updated.Severity
            == S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY
        )
