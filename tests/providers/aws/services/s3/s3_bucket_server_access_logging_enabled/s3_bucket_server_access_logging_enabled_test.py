from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_s3_bucket_server_access_logging_enabled:
    @mock_aws
    def test_bucket_no_logging(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled import (
                    s3_bucket_server_access_logging_enabled,
                )

                check = s3_bucket_server_access_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has server access logging disabled."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )

    @mock_aws
    def test_bucket_with_logging(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled import (
                    s3_bucket_server_access_logging_enabled,
                )

                check = s3_bucket_server_access_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has server access logging enabled."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )

    @mock_aws
    def test_multiple_buckets_mixed_logging(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)

        bucket_fail = "bucket_test_no_logging"
        bucket_pass = "bucket_test_with_logging"

        # Create two buckets
        s3_client_us_east_1.create_bucket(Bucket=bucket_fail)
        s3_client_us_east_1.create_bucket(Bucket=bucket_pass)

        # Enable logging on the PASS bucket (same pattern as existing test)
        bucket_owner = s3_client_us_east_1.get_bucket_acl(Bucket=bucket_pass)["Owner"]
        s3_client_us_east_1.put_bucket_acl(
            Bucket=bucket_pass,
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
            Bucket=bucket_pass,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": bucket_pass,
                    "TargetPrefix": f"{bucket_pass}/",
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled.s3_client",
                new=S3(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_bucket_server_access_logging_enabled.s3_bucket_server_access_logging_enabled import (
                    s3_bucket_server_access_logging_enabled,
                )

                check = s3_bucket_server_access_logging_enabled()
                result = check.execute()

                # Two buckets -> two findings
                assert len(result) == 2

                # Make assertions order-independent
                by_id = {finding.resource_id: finding for finding in result}

                assert by_id[bucket_fail].status == "FAIL"
                assert (
                    by_id[bucket_fail].status_extended
                    == f"S3 Bucket {bucket_fail} has server access logging disabled."
                )

                assert by_id[bucket_pass].status == "PASS"
                assert (
                    by_id[bucket_pass].status_extended
                    == f"S3 Bucket {bucket_pass} has server access logging enabled."
                )

                assert (
                    by_id[bucket_fail].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_fail}"
                )
                assert (
                    by_id[bucket_pass].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_pass}"
                )
