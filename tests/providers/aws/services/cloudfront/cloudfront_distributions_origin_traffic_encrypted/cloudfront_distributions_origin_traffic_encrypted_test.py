from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    DefaultCacheConfigBehaviour,
    Distribution,
    Origin,
    ViewerProtocolPolicy,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_origin_traffic_encrypted:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_origin_traffic_encrypted.cloudfront_distributions_origin_traffic_encrypted import (
                cloudfront_distributions_origin_traffic_encrypted,
            )

            check = cloudfront_distributions_origin_traffic_encrypted()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_no_traffic_encryption(self):
        cloudfront_client = mock.MagicMock
        id = "origin1"
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id=id,
                        domain_name="asdf.s3.us-east-1.amazonaws.com",
                        origin_protocol_policy="",
                        origin_ssl_protocols=[],
                    )
                ],
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.allow_all,
                    field_level_encryption_id="",
                ),
                default_root_object="",
                viewer_protocol_policy="",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_origin_traffic_encrypted.cloudfront_distributions_origin_traffic_encrypted import (
                cloudfront_distributions_origin_traffic_encrypted,
            )

            check = cloudfront_distributions_origin_traffic_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} does not encrypt traffic to custom origins {id}."
            )
            assert result[0].resource_tags == []

    def test_distribution_http_only(self):
        cloudfront_client = mock.MagicMock
        id = "origin1"
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id=id,
                        domain_name="asdf.s3.us-east-1.amazonaws.com",
                        origin_protocol_policy="http-only",
                        origin_ssl_protocols=[],
                    )
                ],
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.allow_all,
                    field_level_encryption_id="",
                ),
                default_root_object="index.html",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_origin_traffic_encrypted.cloudfront_distributions_origin_traffic_encrypted import (
                cloudfront_distributions_origin_traffic_encrypted,
            )

            check = cloudfront_distributions_origin_traffic_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} does not encrypt traffic to custom origins {id}."
            )
            assert result[0].resource_tags == []

    def test_distribution_match_viewer_allow_all(self):
        cloudfront_client = mock.MagicMock
        id = "origin1"
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id=id,
                        domain_name="asdf.s3.us-east-1.amazonaws.com",
                        origin_protocol_policy="match-viewer",
                        origin_ssl_protocols=[],
                    )
                ],
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.allow_all,
                    field_level_encryption_id="",
                ),
                default_root_object="index.html",
                viewer_protocol_policy="allow-all",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_origin_traffic_encrypted.cloudfront_distributions_origin_traffic_encrypted import (
                cloudfront_distributions_origin_traffic_encrypted,
            )

            check = cloudfront_distributions_origin_traffic_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} does not encrypt traffic to custom origins {id}."
            )
            assert result[0].resource_tags == []

    def test_distribution_traffic_encrypted(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id="origin1",
                        domain_name="asdf.s3.us-east-1.amazonaws.com",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=[],
                    )
                ],
                default_cache_config=DefaultCacheConfigBehaviour(
                    realtime_log_config_arn="",
                    viewer_protocol_policy=ViewerProtocolPolicy.allow_all,
                    field_level_encryption_id="",
                ),
                default_root_object="index.html",
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_origin_traffic_encrypted.cloudfront_distributions_origin_traffic_encrypted import (
                cloudfront_distributions_origin_traffic_encrypted,
            )

            check = cloudfront_distributions_origin_traffic_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} does encrypt traffic to custom origins."
            )
            assert result[0].resource_tags == []
