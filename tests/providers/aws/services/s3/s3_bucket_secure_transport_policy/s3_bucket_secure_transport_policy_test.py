from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"


class Test_s3_bucket_secure_transport_policy:
    # Mocked Audit Info
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
        )
        return audit_info

    @mock_s3
    def test_bucket_no_policy(self):
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                check = s3_bucket_secure_transport_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "does not have a bucket policy",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == "us-east-1"

    @mock_s3
    def test_bucket_comply_policy(self):
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        ssl_policy = """
{
  "Version": "2012-10-17",
  "Id": "PutObjPolicy",
  "Statement": [
    {
      "Sid": "s3-bucket-ssl-requests-only",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::bucket_test_us/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
"""
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=ssl_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                check = s3_bucket_secure_transport_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "bucket policy to deny requests over insecure transport",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == "us-east-1"

    @mock_s3
    def test_bucket_uncomply_policy(self):
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        ssl_policy = """
{
  "Version": "2012-10-17",
  "Id": "PutObjPolicy",
  "Statement": [
    {
      "Sid": "s3-bucket-ssl-requests-only",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bucket_test_us/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
"""
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=ssl_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                check = s3_bucket_secure_transport_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "allows requests over insecure transport in the bucket policy",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == "us-east-1"
