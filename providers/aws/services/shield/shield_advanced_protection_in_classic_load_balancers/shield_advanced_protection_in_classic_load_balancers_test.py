from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID
from providers.aws.services.elb.elb_service import LoadBalancer
from providers.aws.services.shield.shield_service import Protection

AWS_REGION = "eu-west-1"


class Test_shield_advanced_protection_in_classic_load_balancers:
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        # ELB Client
        elb_client = mock.MagicMock
        with mock.patch(
            "providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "providers.aws.services.elb.elb_service.ELB",
            new=elb_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 0

    def test_shield_enabled_elb_protected(self):
        # ELB Client
        elb_client = mock.MagicMock
        elb_name = "mylb"
        elb_arn = f"arn:aws:elasticloadbalancing:${AWS_REGION}:${DEFAULT_ACCOUNT_ID}:loadbalancer/{elb_name}"
        elb_client.loadbalancers = [
            LoadBalancer(
                name=elb_name,
                dns="",
                arn=elb_arn,
                scheme="internal",
                listeners=[],
                region=AWS_REGION,
            )
        ]

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=elb_arn,
                protection_arn="",
                region=AWS_REGION,
            )
        }

        with mock.patch(
            "providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "providers.aws.services.elb.elb_service.ELB",
            new=elb_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ELB {elb_name} is protected by AWS Shield Advanced"
            )

    def test_shield_enabled_elb_not_protected(self):
        # ELB Client
        elb_client = mock.MagicMock
        elb_name = "mylb"
        elb_arn = f"arn:aws:elasticloadbalancing:${AWS_REGION}:${DEFAULT_ACCOUNT_ID}:loadbalancer/{elb_name}"
        elb_client.loadbalancers = [
            LoadBalancer(
                name=elb_name,
                dns="",
                arn=elb_arn,
                scheme="internal",
                listeners=[],
                region=AWS_REGION,
            )
        ]

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        with mock.patch(
            "providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "providers.aws.services.elb.elb_service.ELB",
            new=elb_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ELB {elb_name} is not protected by AWS Shield Advanced"
            )

    def test_shield_disabled_elb_not_protected(self):
        # ELB Client
        elb_client = mock.MagicMock
        elb_name = "mylb"
        elb_arn = f"arn:aws:elasticloadbalancing:${AWS_REGION}:${DEFAULT_ACCOUNT_ID}:loadbalancer/{elb_name}"
        elb_client.loadbalancers = [
            LoadBalancer(
                name=elb_name,
                dns="",
                arn=elb_arn,
                scheme="internal",
                listeners=[],
                region=AWS_REGION,
            )
        ]

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        with mock.patch(
            "providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "providers.aws.services.elb.elb_service.ELB",
            new=elb_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_classic_load_balancers.shield_advanced_protection_in_classic_load_balancers import (
                shield_advanced_protection_in_classic_load_balancers,
            )

            check = shield_advanced_protection_in_classic_load_balancers()
            result = check.execute()

            assert len(result) == 0
