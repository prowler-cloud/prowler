from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    DefaultCacheConfigBehaviour,
    Distribution,
    ViewerProtocolPolicy,
)

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{DEFAULT_ACCOUNT_ID}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_https_enabled:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_enabled.cloudfront_distributions_https_enabled import (
                cloudfront_distributions_https_enabled,
            )

            check = cloudfront_distributions_https_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_one_distribution_https_disabled(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[],
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.allow_all,
                    field_level_encryption_id="",
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_enabled.cloudfront_distributions_https_enabled import (
                cloudfront_distributions_https_enabled,
            )

            check = cloudfront_distributions_https_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} viewers can use HTTP or HTTPS"
            )

    def test_one_distribution_https_redirect(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[],
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.redirect_to_https,
                    field_level_encryption_id="",
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_enabled.cloudfront_distributions_https_enabled import (
                cloudfront_distributions_https_enabled,
            )

            check = cloudfront_distributions_https_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has redirect to HTTPS"
            )

    def test_one_distribution_https_only(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[],
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.https_only,
                    field_level_encryption_id="",
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_https_enabled.cloudfront_distributions_https_enabled import (
                cloudfront_distributions_https_enabled,
            )

            check = cloudfront_distributions_https_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has HTTPS only"
            )
