from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import Distribution
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_s3_origin_non_existing_bucket:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existing_bucket.cloudfront_distributions_s3_origin_non_existing_bucket import (
                cloudfront_distributions_s3_origin_non_existing_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existing_bucket()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_nonexistent_origins(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                origins=[
                    {
                        "DomainName": "",
                        "Id": "S3-ORIGIN",
                        "S3OriginConfig": {
                            "OriginAccessIdentity": "",
                        },
                    }
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existing_bucket.cloudfront_distributions_s3_origin_non_existing_bucket import (
                cloudfront_distributions_s3_origin_non_existing_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existing_bucket()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has nonexistent S3 origins."
            )

    def test_distribution_no_nonexistent_origins(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                origins=[
                    {
                        "DomainName": "example.com",
                        "Id": "S3-ORIGIN",
                        "S3OriginConfig": {
                            "OriginAccessIdentity": "",
                        },
                    }
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existing_bucket.cloudfront_distributions_s3_origin_non_existing_bucket import (
                cloudfront_distributions_s3_origin_non_existing_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existing_bucket()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} does not have nonexistent S3 origins."
            )
