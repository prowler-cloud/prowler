from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    Distribution,
    Origin,
)
from prowler.providers.aws.services.s3.s3_service import Bucket
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)


class Test_cloudfront_s3_origin_non_existent_bucket:
    @mock.patch(
        "prowler.providers.aws.services.s3.s3_service.S3._head_bucket",
        new=mock.MagicMock(return_value=False),
    )
    def test_no_distributions(self):
        # Distributions
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        s3_client = mock.MagicMock()
        # Buckets
        s3_client.buckets = {}

        with mock.patch(
            "prowler.providers.aws.services.s3.s3_service.S3", new=s3_client
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket import (
                cloudfront_distributions_s3_origin_non_existent_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existent_bucket()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_nonexistent_origins(self):
        # Distributions
        domain = "nonexistent-bucket.s3.eu-west-1.amazonaws.com"
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=AWS_REGION_EU_WEST_1,
                logging_enabled=True,
                origins=[
                    Origin(
                        domain_name=domain,
                        id="S3-ORIGIN",
                        origin_protocol_policy="",
                        origin_ssl_protocols=[],
                        s3_origin_config={"OriginAccessIdentity": ""},
                    ),
                ],
            )
        }
        # Buckets
        nonexistent_bucket = "nonexistent-bucket"
        s3_client = mock.MagicMock()
        s3_client.buckets = {}

        with mock.patch(
            "prowler.providers.aws.services.s3.s3_service.S3", new=s3_client
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.s3_client._head_bucket",
            new=mock.MagicMock(return_value=False),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket import (
                cloudfront_distributions_s3_origin_non_existent_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existent_bucket()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has non-existent S3 buckets as origins: {nonexistent_bucket}."
            )

    def test_distribution_no_nonexistent_origins(self):
        # Distributions
        domain = "existent-bucket.s3.eu-west-1.amazonaws.com"
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=AWS_REGION_EU_WEST_1,
                logging_enabled=True,
                origins=[
                    Origin(
                        domain_name=domain,
                        id="S3-ORIGIN",
                        origin_protocol_policy="",
                        origin_ssl_protocols=[],
                    ),
                ],
            )
        }
        # Buckets
        bucket_name = "existent-bucket"
        s3_client = mock.MagicMock()
        s3_client.audited_account = AWS_ACCOUNT_NUMBER
        s3_client.buckets = {
            f"arn:aws:s3:::{bucket_name}": Bucket(
                name=bucket_name,
                region=AWS_REGION_EU_WEST_1,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.s3.s3_service.S3", new=s3_client
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.s3_client._head_bucket",
            new=mock.MagicMock(return_value=True),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket import (
                cloudfront_distributions_s3_origin_non_existent_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existent_bucket()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} does not have non-existent S3 buckets as origins."
            )
