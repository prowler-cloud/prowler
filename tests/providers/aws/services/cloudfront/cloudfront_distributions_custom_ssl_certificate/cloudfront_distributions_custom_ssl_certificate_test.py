from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import Distribution
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_custom_ssl_certificate:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_custom_ssl_certificate.cloudfront_distributions_custom_ssl_certificate import (
                cloudfront_distributions_custom_ssl_certificate,
            )

            check = cloudfront_distributions_custom_ssl_certificate()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_default_certificate(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                origins=[],
                default_certificate=True,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_custom_ssl_certificate.cloudfront_distributions_custom_ssl_certificate import (
                cloudfront_distributions_custom_ssl_certificate,
            )

            check = cloudfront_distributions_custom_ssl_certificate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is using the default SSL/TLS certificate."
            )

    def test_distribution_custom_certificate(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                origins=[],
                default_certificate=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_custom_ssl_certificate.cloudfront_distributions_custom_ssl_certificate import (
                cloudfront_distributions_custom_ssl_certificate,
            )

            check = cloudfront_distributions_custom_ssl_certificate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is using a custom SSL/TLS certificate."
            )
