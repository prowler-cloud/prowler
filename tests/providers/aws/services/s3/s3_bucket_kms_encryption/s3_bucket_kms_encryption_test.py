from unittest import mock

from boto3 import client, session
from moto import mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


class Test_s3_bucket_kms_encryption:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=AWS_ACCOUNT_ARN,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
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
        return audit_info

    @mock_s3
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
            new=S3(audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                s3_bucket_kms_encryption,
            )

            check = s3_bucket_kms_encryption()
            result = check.execute()

            assert len(result) == 0

    @mock_s3
    def test_bucket_no_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
            new=S3(audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                s3_bucket_kms_encryption,
            )

            check = s3_bucket_kms_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Server Side Encryption is not configured with kms for S3 Bucket {bucket_name_us}."
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    @mock_s3
    def test_bucket_no_kms_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        }

        s3_client_us_east_1.put_bucket_encryption(
            Bucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
            new=S3(audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                s3_bucket_kms_encryption,
            )

            check = s3_bucket_kms_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Server Side Encryption is not configured with kms for S3 Bucket {bucket_name_us}."
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    @mock_s3
    def test_bucket_kms_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        kms_encryption = "aws:kms"
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": f"{kms_encryption}",
                        "KMSMasterKeyID": "12345678",
                    }
                }
            ]
        }

        s3_client_us_east_1.put_bucket_encryption(
            Bucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                    s3_bucket_kms_encryption,
                )

                check = s3_bucket_kms_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has Server Side Encryption with {kms_encryption}."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    @mock_s3
    def test_bucket_kms_dsse_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        kms_encryption = "aws:kms:dsse"
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": f"{kms_encryption}",
                        "KMSMasterKeyID": "12345678",
                    }
                }
            ]
        }

        s3_client_us_east_1.put_bucket_encryption(
            Bucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                    s3_bucket_kms_encryption,
                )

                check = s3_bucket_kms_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has Server Side Encryption with {kms_encryption}."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION
