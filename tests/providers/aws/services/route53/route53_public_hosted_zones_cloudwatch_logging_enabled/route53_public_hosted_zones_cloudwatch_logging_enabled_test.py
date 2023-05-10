from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.route53.route53_service import (
    HostedZone,
    LoggingConfig,
)

AWS_REGION = "us-east-1"


class Test_route53_public_hosted_zones_cloudwatch_logging_enabled:
    def test_no_hosted_zones(self):
        route53 = mock.MagicMock
        route53.hosted_zones = {}

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_client",
            new=route53,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled import (
                route53_public_hosted_zones_cloudwatch_logging_enabled,
            )

            check = route53_public_hosted_zones_cloudwatch_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_hosted_zone__public_logging_enabled(self):
        route53 = mock.MagicMock
        hosted_zone_name = "test-domain.com"
        hosted_zone_id = "ABCDEF12345678"
        log_group_name = "test-log-group"
        log_group_arn = (
            f"rn:aws:logs:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:log-group:{log_group_name}"
        )
        route53.hosted_zones = {
            hosted_zone_name: HostedZone(
                name=hosted_zone_name,
                arn=f"arn:aws:route53:::{hosted_zone_id}",
                id=hosted_zone_id,
                private_zone=False,
                region=AWS_REGION,
                logging_config=LoggingConfig(cloudwatch_log_group_arn=log_group_arn),
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_client",
            new=route53,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled import (
                route53_public_hosted_zones_cloudwatch_logging_enabled,
            )

            check = route53_public_hosted_zones_cloudwatch_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == hosted_zone_id
            assert result[0].region == AWS_REGION
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Route53 Public Hosted Zone {hosted_zone_id} has query logging enabled in Log Group {log_group_arn}"
            )

    def test_hosted_zone__public_logging_disabled(self):
        route53 = mock.MagicMock
        hosted_zone_name = "test-domain.com"
        hosted_zone_id = "ABCDEF12345678"
        route53.hosted_zones = {
            hosted_zone_name: HostedZone(
                name=hosted_zone_name,
                arn=f"arn:aws:route53:::{hosted_zone_id}",
                id=hosted_zone_id,
                private_zone=False,
                region=AWS_REGION,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_client",
            new=route53,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled import (
                route53_public_hosted_zones_cloudwatch_logging_enabled,
            )

            check = route53_public_hosted_zones_cloudwatch_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == hosted_zone_id
            assert result[0].region == AWS_REGION
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Route53 Public Hosted Zone {hosted_zone_id} has query logging disabled"
            )

    def test_hosted_zone__private(self):
        route53 = mock.MagicMock
        hosted_zone_name = "test-domain.com"
        hosted_zone_id = "ABCDEF12345678"
        route53.hosted_zones = {
            hosted_zone_name: HostedZone(
                name=hosted_zone_name,
                arn=f"arn:aws:route53:::{hosted_zone_id}",
                id=hosted_zone_id,
                private_zone=True,
                region=AWS_REGION,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_client",
            new=route53,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled import (
                route53_public_hosted_zones_cloudwatch_logging_enabled,
            )

            check = route53_public_hosted_zones_cloudwatch_logging_enabled()
            result = check.execute()

            assert len(result) == 0
