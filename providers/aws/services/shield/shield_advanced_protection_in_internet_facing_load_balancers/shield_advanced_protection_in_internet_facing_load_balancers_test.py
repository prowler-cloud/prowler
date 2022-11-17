from unittest import mock

from providers.aws.services.elbv2.elbv2_service import (
    LoadBalancerv2,
)
from providers.aws.services.shield.shield_service import Protection
from moto.core import DEFAULT_ACCOUNT_ID

AWS_REGION = "eu-west-1"


class Test_shield_advanced_protection_in_internet_facing_load_balancers:
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        # ELBv2 Client
        elbv2_client = mock.MagicMock
        with mock.patch(
            "providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "providers.aws.services.elbv2.elbv2_service.ELBv2",
            new=elbv2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 0

    def test_shield_enabled_elbv2_internet_facing_protected(self):
        # ELBv2 Client
        elbv2_client = mock.MagicMock
        elb_name = "test-elb"
        elb_arn = (
            f"arn:aws:elasticloadbalancing:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:{elb_name}"
        )
        elbv2_client.loadbalancersv2 = [
            LoadBalancerv2(
                name=elb_name,
                dns="test-dns.com",
                arn=elb_arn,
                region=AWS_REGION,
                listeners=[],
                scheme="internet-facing",
                type="application",
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
            "providers.aws.services.elbv2.elbv2_service.ELBv2",
            new=elbv2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ELBv2 ALB {elb_name} is protected by AWS Shield Advanced"
            )

    def test_shield_enabled_elbv2_internal_protected(self):
        # ELBv2 Client
        elbv2_client = mock.MagicMock
        elb_name = "test-elb"
        elb_arn = (
            f"arn:aws:elasticloadbalancing:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:{elb_name}"
        )
        elbv2_client.loadbalancersv2 = [
            LoadBalancerv2(
                name=elb_name,
                dns="test-dns.com",
                arn=elb_arn,
                region=AWS_REGION,
                listeners=[],
                scheme="internal",
                type="application",
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
            "providers.aws.services.elbv2.elbv2_service.ELBv2",
            new=elbv2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 0

    def test_shield_enabled_elbv2_internet_facing_not_protected(self):
        # ELBv2 Client
        elbv2_client = mock.MagicMock
        elb_name = "test-elb"
        elb_arn = (
            f"arn:aws:elasticloadbalancing:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:{elb_name}"
        )
        elbv2_client.loadbalancersv2 = [
            LoadBalancerv2(
                name=elb_name,
                dns="test-dns.com",
                arn=elb_arn,
                region=AWS_REGION,
                listeners=[],
                scheme="internet-facing",
                type="application",
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
            "providers.aws.services.elbv2.elbv2_service.ELBv2",
            new=elbv2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == elb_name
            assert result[0].resource_arn == elb_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ELBv2 ALB {elb_name} is not protected by AWS Shield Advanced"
            )

    def test_shield_disabled_elbv2_internet_facing_not_protected(self):
        # ELBv2 Client
        elbv2_client = mock.MagicMock
        elb_name = "test-elb"
        elb_arn = (
            f"arn:aws:elasticloadbalancing:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:{elb_name}"
        )
        elbv2_client.loadbalancersv2 = [
            LoadBalancerv2(
                name=elb_name,
                dns="test-dns.com",
                arn=elb_arn,
                region=AWS_REGION,
                listeners=[],
                scheme="internet-facing",
                type="application",
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
            "providers.aws.services.elbv2.elbv2_service.ELBv2",
            new=elbv2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_internet_facing_load_balancers.shield_advanced_protection_in_internet_facing_load_balancers import (
                shield_advanced_protection_in_internet_facing_load_balancers,
            )

            check = shield_advanced_protection_in_internet_facing_load_balancers()
            result = check.execute()

            assert len(result) == 0
