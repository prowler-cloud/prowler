from unittest import mock

from boto3 import client
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.shield.shield_service import Protection
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_shield_advanced_protection_in_associated_elastic_ips:
    @mock_aws
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(set_mocked_aws_provider([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_shield_enabled_ip_protected(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        resp = ec2_client.allocate_address(Domain="vpc", Address="127.38.43.222")
        allocation_id = resp["AllocationId"]
        elastic_ip_arn = f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:eip-allocation/{allocation_id}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=elastic_ip_arn,
                protection_arn="",
                region=AWS_REGION_EU_WEST_1,
            )
        }

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(set_mocked_aws_provider([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == allocation_id
            assert result[0].resource_arn == elastic_ip_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elastic IP {allocation_id} is protected by AWS Shield Advanced."
            )

    @mock_aws
    def test_shield_enabled_ip_not_protected(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        resp = ec2_client.allocate_address(Domain="vpc", Address="127.38.43.222")
        allocation_id = resp["AllocationId"]
        elastic_ip_arn = f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:eip-allocation/{allocation_id}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(set_mocked_aws_provider([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == allocation_id
            assert result[0].resource_arn == elastic_ip_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elastic IP {allocation_id} is not protected by AWS Shield Advanced."
            )

    @mock_aws
    def test_shield_disabled_ip_not_protected(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        resp = ec2_client.allocate_address(Domain="vpc", Address="127.38.43.222")
        allocation_id = resp["AllocationId"]
        _ = f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:eip-allocation/{allocation_id}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(set_mocked_aws_provider([AWS_REGION_EU_WEST_1])),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 0
