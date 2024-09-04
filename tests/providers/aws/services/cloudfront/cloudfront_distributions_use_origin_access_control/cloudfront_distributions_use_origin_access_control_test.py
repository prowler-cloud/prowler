from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import Distribution
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_use_origin_access_control:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_use_origin_access_control.cloudfront_distributions_use_origin_access_control import (
                cloudfront_distributions_use_origin_access_control,
            )

            check = cloudfront_distributions_use_origin_access_control()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_using_origin_access_control(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    {
                        "Id": "string",
                        "DomainName": "string",
                        "OriginPath": "string",
                        "CustomHeaders": {
                            "Quantity": 123,
                            "Items": [
                                {
                                    "HeaderName": "string",
                                    "HeaderValue": "string",
                                },
                            ],
                        },
                        "S3OriginConfig": {"OriginAccessIdentity": "string"},
                        "CustomOriginConfig": {
                            "HTTPPort": 123,
                            "HTTPSPort": 123,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {
                                "Quantity": 123,
                                "Items": [
                                    "SSLv3",
                                ],
                            },
                            "OriginReadTimeout": 123,
                            "OriginKeepaliveTimeout": 123,
                        },
                        "ConnectionAttempts": 123,
                        "ConnectionTimeout": 123,
                        "OriginShield": {
                            "Enabled": False,
                            "OriginShieldRegion": "string",
                        },
                        "OriginAccessControlId": "string",
                    },
                ],
                origin_access_control=True,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_use_origin_access_control.cloudfront_distributions_use_origin_access_control import (
                cloudfront_distributions_use_origin_access_control,
            )

            check = cloudfront_distributions_use_origin_access_control()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is using origin access control (OAC)."
            )
            assert result[0].resource_tags == []

    def test_distribution_not_using_origin_access_control(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            "DISTRIBUTION_ID": Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[],
                origin_access_control=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_use_origin_access_control.cloudfront_distributions_use_origin_access_control import (
                cloudfront_distributions_use_origin_access_control,
            )

            check = cloudfront_distributions_use_origin_access_control()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is not using origin access control (OAC)."
            )
            assert result[0].resource_tags == []
