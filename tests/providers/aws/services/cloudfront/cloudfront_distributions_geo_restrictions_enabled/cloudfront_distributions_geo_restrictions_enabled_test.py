from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    Distribution,
    GeoRestrictionType,
)
from tests.providers.aws.audit_info_utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_geo_restrictions_enabled:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_geo_restrictions_enabled.cloudfront_distributions_geo_restrictions_enabled import (
                cloudfront_distributions_geo_restrictions_enabled,
            )

            check = cloudfront_distributions_geo_restrictions_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_one_distribution_geo_restriction_disabled(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[],
                geo_restriction_type=GeoRestrictionType.none,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_geo_restrictions_enabled.cloudfront_distributions_geo_restrictions_enabled import (
                cloudfront_distributions_geo_restrictions_enabled,
            )

            check = cloudfront_distributions_geo_restrictions_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has Geo restrictions disabled."
            )
            assert result[0].resource_tags == []

    def test_one_distribution_geo_restriction_enabled_whitelist(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[],
                geo_restriction_type=GeoRestrictionType.whitelist,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_geo_restrictions_enabled.cloudfront_distributions_geo_restrictions_enabled import (
                cloudfront_distributions_geo_restrictions_enabled,
            )

            check = cloudfront_distributions_geo_restrictions_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has Geo restrictions enabled."
            )
            assert result[0].resource_tags == []

    def test_one_distribution_geo_restriction_enabled_blacklist(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[],
                geo_restriction_type=GeoRestrictionType.blacklist,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_geo_restrictions_enabled.cloudfront_distributions_geo_restrictions_enabled import (
                cloudfront_distributions_geo_restrictions_enabled,
            )

            check = cloudfront_distributions_geo_restrictions_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has Geo restrictions enabled."
            )
            assert result[0].resource_tags == []
