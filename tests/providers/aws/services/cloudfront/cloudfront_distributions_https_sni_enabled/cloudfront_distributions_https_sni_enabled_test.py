from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    Distribution,
    SSLSupportMethod,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "us-east-1"


class Test_cloudfront_distributions_https_sni_enabled:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_sni_enabled.cloudfront_distributions_https_sni_enabled import (
                cloudfront_distributions_https_sni_enabled,
            )

            check = cloudfront_distributions_https_sni_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_no_certificate(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                origins=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_sni_enabled.cloudfront_distributions_https_sni_enabled import (
                cloudfront_distributions_https_sni_enabled,
            )

            check = cloudfront_distributions_https_sni_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_certificate_not_set_up(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                origins=[],
                ssl_support_method=SSLSupportMethod.static_ip,
                certificate="arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_sni_enabled.cloudfront_distributions_https_sni_enabled import (
                cloudfront_distributions_https_sni_enabled,
            )

            check = cloudfront_distributions_https_sni_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is not serving HTTPS requests using SNI."
            )

    def test_distribution_valid_configuration(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                origins=[],
                ssl_support_method=SSLSupportMethod.sni_only,
                certificate="arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_sni_enabled.cloudfront_distributions_https_sni_enabled import (
                cloudfront_distributions_https_sni_enabled,
            )

            check = cloudfront_distributions_https_sni_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is serving HTTPS requests using SNI."
            )
