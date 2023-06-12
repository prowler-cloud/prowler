from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_s3_bucket_server_access_logging_enabled:
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
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
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
        )
        return audit_info

    @mock_s3
    def test_bucket_no_logging(self):
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
                "prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled import (
                    s3_bucket_server_access_logging_enabled,
                )

                check = s3_bucket_server_access_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "server access logging disabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )

    @mock_s3
    def test_bucket_with_logging(self):
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client_us_east_1.get_bucket_acl(Bucket=bucket_name_us)[
            "Owner"
        ]
        s3_client_us_east_1.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            "Type": "Group",
                        },
                        "Permission": "WRITE",
                    },
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            "Type": "Group",
                        },
                        "Permission": "READ_ACP",
                    },
                    {
                        "Grantee": {"Type": "CanonicalUser", "ID": bucket_owner["ID"]},
                        "Permission": "FULL_CONTROL",
                    },
                ],
                "Owner": bucket_owner,
            },
        )

        s3_client_us_east_1.put_bucket_logging(
            Bucket=bucket_name_us,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": bucket_name_us,
                    "TargetPrefix": "{}/".format(bucket_name_us),
                    "TargetGrants": [
                        {
                            "Grantee": {
                                "ID": "SOMEIDSTRINGHERE9238748923734823917498237489237409123840983274",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "READ",
                        },
                        {
                            "Grantee": {
                                "ID": "SOMEIDSTRINGHERE9238748923734823917498237489237409123840983274",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "WRITE",
                        },
                    ],
                }
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled import (
                    s3_bucket_server_access_logging_enabled,
                )

                check = s3_bucket_server_access_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "server access logging enabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
