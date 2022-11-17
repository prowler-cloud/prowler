from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID
from providers.aws.services.ec2.ec2_service import ElasticIP
from providers.aws.services.shield.shield_service import Protection

AWS_REGION = "eu-west-1"


class Test_shield_advanced_protection_in_associated_elastic_ips:
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        # EC2 Client
        ec2_client = mock.MagicMock
        with mock.patch(
            "providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "providers.aws.services.ec2.ec2_service.EC2",
            new=ec2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 0

    def test_shield_enabled_ip_protected(self):
        # EC2 Client
        ec2_client = mock.MagicMock
        allocation_id = "test-eip"
        elastic_ip_arn = f"arn:aws:ec2:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:eip-allocation/{allocation_id}"
        ec2_client.elastic_ips = [
            ElasticIP(
                public_ip="5.5.5.5",
                association_id="",
                allocation_id=allocation_id,
                arn=elastic_ip_arn,
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
                resource_arn=elastic_ip_arn,
                protection_arn="",
                region=AWS_REGION,
            )
        }

        with mock.patch(
            "providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "providers.aws.services.ec2.ec2_service.EC2",
            new=ec2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == allocation_id
            assert result[0].resource_arn == elastic_ip_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elastic IP {allocation_id} is protected by AWS Shield Advanced"
            )

    def test_shield_enabled_ip_not_protected(self):
        # EC2 Client
        ec2_client = mock.MagicMock
        allocation_id = "test-eip"
        elastic_ip_arn = f"arn:aws:ec2:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:eip-allocation/{allocation_id}"
        ec2_client.elastic_ips = [
            ElasticIP(
                public_ip="5.5.5.5",
                association_id="",
                allocation_id=allocation_id,
                arn=elastic_ip_arn,
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
            "providers.aws.services.ec2.ec2_service.EC2",
            new=ec2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == allocation_id
            assert result[0].resource_arn == elastic_ip_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elastic IP {allocation_id} is not protected by AWS Shield Advanced"
            )

    def test_shield_disabled_ip_not_protected(self):
        # EC2 Client
        ec2_client = mock.MagicMock
        allocation_id = "test-eip"
        elastic_ip_arn = f"arn:aws:ec2:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:eip-allocation/{allocation_id}"
        ec2_client.elastic_ips = [
            ElasticIP(
                public_ip="5.5.5.5",
                association_id="",
                allocation_id=allocation_id,
                arn=elastic_ip_arn,
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
            "providers.aws.services.ec2.ec2_service.EC2",
            new=ec2_client,
        ):
            # Test Check
            from providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 0
