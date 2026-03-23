from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_s3_bucket_website_hosting_disabled:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled.s3_client",
                new=S3(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled import (
                    s3_bucket_website_hosting_disabled,
                )

                check = s3_bucket_website_hosting_disabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_bucket_no_website_hosting(self):
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
                "prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled.s3_client",
                new=S3(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled import (
                    s3_bucket_website_hosting_disabled,
                )

                check = s3_bucket_website_hosting_disabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} does not have static website hosting enabled."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )

    @mock_aws
    def test_bucket_with_website_hosting(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        s3_client_us_east_1.put_bucket_website(
            Bucket=bucket_name_us,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "error.html"},
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled.s3_client",
                new=S3(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled import (
                    s3_bucket_website_hosting_disabled,
                )

                check = s3_bucket_website_hosting_disabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has static website hosting enabled."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )

    @mock_aws
    def test_multiple_buckets_mixed_website_hosting(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)

        bucket_fail = "bucket_with_website"
        bucket_pass = "bucket_without_website"

        s3_client_us_east_1.create_bucket(Bucket=bucket_fail)
        s3_client_us_east_1.create_bucket(Bucket=bucket_pass)

        s3_client_us_east_1.put_bucket_website(
            Bucket=bucket_fail,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled.s3_client",
                new=S3(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_bucket_website_hosting_disabled.s3_bucket_website_hosting_disabled import (
                    s3_bucket_website_hosting_disabled,
                )

                check = s3_bucket_website_hosting_disabled()
                result = check.execute()

                assert len(result) == 2

                by_id = {finding.resource_id: finding for finding in result}

                assert by_id[bucket_fail].status == "FAIL"
                assert (
                    by_id[bucket_fail].status_extended
                    == f"S3 Bucket {bucket_fail} has static website hosting enabled."
                )

                assert by_id[bucket_pass].status == "PASS"
                assert (
                    by_id[bucket_pass].status_extended
                    == f"S3 Bucket {bucket_pass} does not have static website hosting enabled."
                )
