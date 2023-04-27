from unittest import mock

from prowler.providers.aws.services.route53.route53_service import HostedZone
from prowler.providers.aws.services.shield.shield_service import Protection

AWS_REGION = "eu-west-1"


class Test_shield_advanced_protection_in_route53_hosted_zones:
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        # Route53 Client
        route53_client = mock.MagicMock
        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.route53.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones.route53_client",
            new=route53_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones import (
                shield_advanced_protection_in_route53_hosted_zones,
            )

            check = shield_advanced_protection_in_route53_hosted_zones()
            result = check.execute()

            assert len(result) == 0

    def test_shield_enabled_route53_hosted_zone_protected(self):
        # Route53 Client
        route53_client = mock.MagicMock
        hosted_zone_id = "ABCDEF12345678"
        hosted_zone_arn = f"arn:aws:route53:::hostedzone/{hosted_zone_id}"
        hosted_zone_name = "test-hosted-zone"

        route53_client.hosted_zones = {
            hosted_zone_id: HostedZone(
                id=hosted_zone_id,
                arn=hosted_zone_arn,
                name=hosted_zone_name,
                hosted_zone_name=hosted_zone_name,
                private_zone=False,
                region=AWS_REGION,
            )
        }

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=hosted_zone_arn,
                protection_arn="",
                region=AWS_REGION,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.route53.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones.route53_client",
            new=route53_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones import (
                shield_advanced_protection_in_route53_hosted_zones,
            )

            check = shield_advanced_protection_in_route53_hosted_zones()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == hosted_zone_id
            assert result[0].resource_arn == hosted_zone_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Route53 Hosted Zone {hosted_zone_id} is protected by AWS Shield Advanced"
            )

    def test_shield_enabled_route53_hosted_zone_not_protected(self):
        # Route53 Client
        route53_client = mock.MagicMock
        hosted_zone_id = "ABCDEF12345678"
        hosted_zone_arn = f"arn:aws:route53:::hostedzone/{hosted_zone_id}"
        hosted_zone_name = "test-hosted-zone"

        route53_client.hosted_zones = {
            hosted_zone_id: HostedZone(
                id=hosted_zone_id,
                arn=hosted_zone_arn,
                name=hosted_zone_name,
                hosted_zone_name=hosted_zone_name,
                private_zone=False,
                region=AWS_REGION,
            )
        }

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.route53.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones.route53_client",
            new=route53_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones import (
                shield_advanced_protection_in_route53_hosted_zones,
            )

            check = shield_advanced_protection_in_route53_hosted_zones()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == hosted_zone_id
            assert result[0].resource_arn == hosted_zone_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Route53 Hosted Zone {hosted_zone_id} is not protected by AWS Shield Advanced"
            )

    def test_shield_disabled_route53_hosted_zone_not_protected(self):
        # Route53 Client
        route53_client = mock.MagicMock
        hosted_zone_id = "ABCDEF12345678"
        hosted_zone_arn = f"arn:aws:route53:::hostedzone/{hosted_zone_id}"
        hosted_zone_name = "test-hosted-zone"

        route53_client.hosted_zones = {
            hosted_zone_id: HostedZone(
                id=hosted_zone_id,
                arn=hosted_zone_arn,
                name=hosted_zone_name,
                hosted_zone_name=hosted_zone_name,
                private_zone=False,
                region=AWS_REGION,
            )
        }

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.route53.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones.route53_client",
            new=route53_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_route53_hosted_zones.shield_advanced_protection_in_route53_hosted_zones import (
                shield_advanced_protection_in_route53_hosted_zones,
            )

            check = shield_advanced_protection_in_route53_hosted_zones()
            result = check.execute()

            assert len(result) == 0
