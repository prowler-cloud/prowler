from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.cloudfront.cloudfront_service import Distribution

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{DEFAULT_ACCOUNT_ID}:distribution/{DISTRIBUTION_ID}"
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
                                    "TLSv1.2",
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
                                    "TLSv1.1",
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
                                "Items": ["TLSv1.2"],
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
