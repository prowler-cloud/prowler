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


class Test_cloudfront_distributions_logging_enabled:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_logging_enabled.cloudfront_distributions_logging_enabled import (
                cloudfront_distributions_logging_enabled,
            )

            check = cloudfront_distributions_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_one_distribution_logging_enabled(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
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
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_logging_enabled.cloudfront_distributions_logging_enabled import (
                cloudfront_distributions_logging_enabled,
            )

            check = cloudfront_distributions_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has logging enabled."
            )

    def test_one_distribution_logging_disabled_realtime_disabled(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=False,
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.https_only,
                    field_level_encryption_id="",
                ),
                origins=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_logging_enabled.cloudfront_distributions_logging_enabled import (
                cloudfront_distributions_logging_enabled,
            )

            check = cloudfront_distributions_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has logging disabled."
            )
            assert result[0].resource_tags == []

    def test_one_distribution_logging_disabled_realtime_enabled(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=False,
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn=DISTRIBUTION_ARN,
                    viewer_protocol_policy=ViewerProtocolPolicy.https_only,
                    field_level_encryption_id="",
                ),
                origins=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_logging_enabled.cloudfront_distributions_logging_enabled import (
                cloudfront_distributions_logging_enabled,
            )

            check = cloudfront_distributions_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has logging enabled."
            )
            assert result[0].resource_tags == []

    def test_one_distribution_logging_enabled_realtime_enabled(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=True,
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn=DISTRIBUTION_ARN,
                    viewer_protocol_policy=ViewerProtocolPolicy.https_only,
                    field_level_encryption_id="",
                ),
                origins=[],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_logging_enabled.cloudfront_distributions_logging_enabled import (
                cloudfront_distributions_logging_enabled,
            )

            check = cloudfront_distributions_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has logging enabled."
            )
            assert result[0].resource_tags == []
