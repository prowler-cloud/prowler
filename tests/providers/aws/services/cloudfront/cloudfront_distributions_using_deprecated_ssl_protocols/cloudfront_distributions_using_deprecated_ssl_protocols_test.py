from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    Distribution,
    Origin,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_using_deprecated_ssl_protocols:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_using_deprecated_ssl_protocols.cloudfront_distributions_using_deprecated_ssl_protocols import (
                cloudfront_distributions_using_deprecated_ssl_protocols,
            )

            check = cloudfront_distributions_using_deprecated_ssl_protocols()
            result = check.execute()

            assert len(result) == 0

    def test_one_distribution_using_deprecated_ssl_protocols(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id="string",
                        domain_name="string",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=["SSLv3"],
                    )
                ],
                origin_failover=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_using_deprecated_ssl_protocols.cloudfront_distributions_using_deprecated_ssl_protocols import (
                cloudfront_distributions_using_deprecated_ssl_protocols,
            )

            check = cloudfront_distributions_using_deprecated_ssl_protocols()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is using a deprecated SSL protocol."
            )
            assert result[0].resource_tags == []

    def test_one_distribution_using_SSL_and_TLS(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id="string",
                        domain_name="string",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=[
                            "SSLv3",
                            "TLSv1.2",
                        ],
                    )
                ],
                origin_failover=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_using_deprecated_ssl_protocols.cloudfront_distributions_using_deprecated_ssl_protocols import (
                cloudfront_distributions_using_deprecated_ssl_protocols,
            )

            check = cloudfront_distributions_using_deprecated_ssl_protocols()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is using a deprecated SSL protocol."
            )
            assert result[0].resource_tags == []

    def test_one_distribution_using_SSL_and_bad_TLS(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id="string",
                        domain_name="string",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=[
                            "SSLv3",
                            "TLSv1.1",
                        ],
                    )
                ],
                origin_failover=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_using_deprecated_ssl_protocols.cloudfront_distributions_using_deprecated_ssl_protocols import (
                cloudfront_distributions_using_deprecated_ssl_protocols,
            )

            check = cloudfront_distributions_using_deprecated_ssl_protocols()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is using a deprecated SSL protocol."
            )
            assert result[0].resource_tags == []

    def test_one_distribution_not_using_deprecated_ssl_protocols(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id="string",
                        domain_name="string",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=[
                            "TLSv1.2",
                        ],
                    )
                ],
                origin_failover=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_using_deprecated_ssl_protocols.cloudfront_distributions_using_deprecated_ssl_protocols import (
                cloudfront_distributions_using_deprecated_ssl_protocols,
            )

            check = cloudfront_distributions_using_deprecated_ssl_protocols()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is not using a deprecated SSL protocol."
            )
            assert result[0].resource_tags == []
