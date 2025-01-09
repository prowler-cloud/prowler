from unittest import mock
from unittest.mock import patch

from prowler.providers.aws.services.s3.s3_service import (
    AccessPoint,
    PublicAccessBlock,
    S3Control,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_access_point_public_access_block:
    def test_no_access_points(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            s3control_client = mock.MagicMock()
            s3control_client.access_points = {}

            with patch(
                "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
                s3control_client,
            ):
                check = s3_access_point_public_access_block()
                result = check.execute()

                assert len(result) == 0

    def test_access_points_with_public_access_block(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        # US-EAST-1 Access Point
        ap_name_us = "test-access-point-us-east-1"
        bucket_name_us = "test-bucket-us-east-1"
        arn_us = f"arn:aws:s3:us-east-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"

        # EU-WEST-1 Access Point
        ap_name_eu = "test-access-point-eu-west-1"
        bucket_name_eu = "test-bucket-eu-west-1"
        arn_eu = f"arn:aws:s3:eu-west-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            s3control_client = mock.MagicMock()
            s3control_client.access_points = {
                arn_us: AccessPoint(
                    arn=arn_us,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_us,
                    bucket=bucket_name_us,
                    region="us-east-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=True,
                        ignore_public_acls=True,
                        block_public_policy=True,
                        restrict_public_buckets=True,
                    ),
                ),
                arn_eu: AccessPoint(
                    arn=arn_eu,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_eu,
                    bucket=bucket_name_eu,
                    region="eu-west-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=True,
                        ignore_public_acls=True,
                        block_public_policy=True,
                        restrict_public_buckets=True,
                    ),
                ),
            }

            with patch(
                "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
                s3control_client,
            ):
                check = s3_access_point_public_access_block()
                result = check.execute()

                # ALL REGIONS
                assert len(result) == 2

                # AWS_REGION_US_EAST_1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Access Point {ap_name_us} of bucket {bucket_name_us} does have Public Access Block enabled."
                )
                assert result[0].resource_id == ap_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

                # AWS_REGION_EU_WEST_1
                assert result[1].status == "PASS"
                assert (
                    result[1].status_extended
                    == f"Access Point {ap_name_eu} of bucket {bucket_name_eu} does have Public Access Block enabled."
                )
                assert result[1].resource_id == ap_name_eu
                assert (
                    result[1].resource_arn
                    == f"arn:aws:s3:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"
                )
                assert result[1].region == AWS_REGION_EU_WEST_1

    def test_access_points_without_public_access_block(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        # US-EAST-1 Access Point
        ap_name_us = "test-access-point-us-east-1"
        bucket_name_us = "test-bucket-us-east-1"
        arn_us = f"arn:aws:s3:us-east-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"

        # EU-WEST-1 Access Point
        ap_name_eu = "test-access-point-eu-west-1"
        bucket_name_eu = "test-bucket-eu-west-1"
        arn_eu = f"arn:aws:s3:eu-west-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            s3control_client = mock.MagicMock()
            s3control_client.access_points = {
                arn_us: AccessPoint(
                    arn=arn_us,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_us,
                    bucket=bucket_name_us,
                    region="us-east-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=False,
                        ignore_public_acls=False,
                        block_public_policy=False,
                        restrict_public_buckets=False,
                    ),
                ),
                arn_eu: AccessPoint(
                    arn=arn_eu,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_eu,
                    bucket=bucket_name_eu,
                    region="eu-west-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=False,
                        ignore_public_acls=False,
                        block_public_policy=False,
                        restrict_public_buckets=False,
                    ),
                ),
            }

            with patch(
                "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
                s3control_client,
            ):
                check = s3_access_point_public_access_block()
                result = check.execute()

                # ALL REGIONS
                assert len(result) == 2

                # AWS_REGION_US_EAST_1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Access Point {ap_name_us} of bucket {bucket_name_us} does not have Public Access Block enabled."
                )
                assert result[0].resource_id == ap_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

                # AWS_REGION_EU_WEST_1
                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == f"Access Point {ap_name_eu} of bucket {bucket_name_eu} does not have Public Access Block enabled."
                )
                assert result[1].resource_id == ap_name_eu
                assert (
                    result[1].resource_arn
                    == f"arn:aws:s3:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"
                )
                assert result[1].region == AWS_REGION_EU_WEST_1

    def test_access_points_without_one_public_access_block(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        # US-EAST-1 Access Point
        ap_name_us = "test-access-point-us-east-1"
        bucket_name_us = "test-bucket-us-east-1"
        arn_us = f"arn:aws:s3:us-east-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"

        # EU-WEST-1 Access Point
        ap_name_eu = "test-access-point-eu-west-1"
        bucket_name_eu = "test-bucket-eu-west-1"
        arn_eu = f"arn:aws:s3:eu-west-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            s3control_client = mock.MagicMock()
            s3control_client.access_points = {
                arn_us: AccessPoint(
                    arn=arn_us,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_us,
                    bucket=bucket_name_us,
                    region="us-east-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=True,
                        ignore_public_acls=True,
                        block_public_policy=True,
                        restrict_public_buckets=True,
                    ),
                ),
                arn_eu: AccessPoint(
                    arn=arn_eu,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_eu,
                    bucket=bucket_name_eu,
                    region="eu-west-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=True,
                        ignore_public_acls=False,
                        block_public_policy=True,
                        restrict_public_buckets=True,
                    ),
                ),
            }

            with patch(
                "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
                s3control_client,
            ):
                check = s3_access_point_public_access_block()
                result = check.execute()

                # ALL REGIONS
                assert len(result) == 2

                # AWS_REGION_US_EAST_1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Access Point {ap_name_us} of bucket {bucket_name_us} does have Public Access Block enabled."
                )
                assert result[0].resource_id == ap_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

                # AWS_REGION_EU_WEST_1
                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == f"Access Point {ap_name_eu} of bucket {bucket_name_eu} does not have Public Access Block enabled."
                )
                assert result[1].resource_id == ap_name_eu
                assert (
                    result[1].resource_arn
                    == f"arn:aws:s3:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"
                )
                assert result[1].region == AWS_REGION_EU_WEST_1

    def test_access_points_mixed_regions(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1, "ap-southeast-2"]
        )

        ap_name_us = "test-access-point-us-east-1"
        ap_name_eu = "test-access-point-eu-west-1"
        ap_name_ap = "test-access-point-ap-southeast-2"

        arn_us = f"arn:aws:s3:us-east-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"
        arn_eu = f"arn:aws:s3:eu-west-1:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"
        arn_ap = (
            f"arn:aws:s3:ap-southeast-2:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_ap}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            s3control_client = mock.MagicMock()
            s3control_client.access_points = {
                arn_us: AccessPoint(
                    arn=arn_us,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_us,
                    bucket="bucket-us",
                    region="us-east-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=True,
                        ignore_public_acls=True,
                        block_public_policy=True,
                        restrict_public_buckets=True,
                    ),
                ),
                arn_eu: AccessPoint(
                    arn=arn_eu,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_eu,
                    bucket="bucket-eu",
                    region="eu-west-1",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=False,
                        ignore_public_acls=False,
                        block_public_policy=False,
                        restrict_public_buckets=False,
                    ),
                ),
                arn_ap: AccessPoint(
                    arn=arn_ap,
                    account_id=AWS_ACCOUNT_NUMBER,
                    name=ap_name_ap,
                    bucket="bucket-ap",
                    region="ap-southeast-2",
                    public_access_block=PublicAccessBlock(
                        block_public_acls=True,
                        ignore_public_acls=False,
                        block_public_policy=True,
                        restrict_public_buckets=True,
                    ),
                ),
            }

            with patch(
                "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
                s3control_client,
            ):
                check = s3_access_point_public_access_block()
                results = check.execute()

                assert len(results) == 3
                for result in results:
                    if result.resource_id == ap_name_us:
                        assert result.region == AWS_REGION_US_EAST_1
                        assert result.status == "PASS"
                        assert (
                            result.status_extended
                            == f"Access Point {ap_name_us} of bucket bucket-us does have Public Access Block enabled."
                        )
                        assert (
                            result.resource_arn
                            == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_us}"
                        )
                    elif result.resource_id == ap_name_eu:
                        assert result.region == AWS_REGION_EU_WEST_1
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == f"Access Point {ap_name_eu} of bucket bucket-eu does not have Public Access Block enabled."
                        )
                        assert (
                            result.resource_arn
                            == f"arn:aws:s3:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_eu}"
                        )
                    elif result.resource_id == ap_name_ap:
                        assert result.region == "ap-southeast-2"
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == f"Access Point {ap_name_ap} of bucket bucket-ap does not have Public Access Block enabled."
                        )
                        assert (
                            result.resource_arn
                            == f"arn:aws:s3:ap-southeast-2:{AWS_ACCOUNT_NUMBER}:accesspoint/{ap_name_ap}"
                        )
