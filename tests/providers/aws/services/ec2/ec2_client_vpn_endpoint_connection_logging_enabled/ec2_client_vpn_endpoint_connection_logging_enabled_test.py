from unittest import mock

from moto import mock_aws

from prowler.providers.aws.services.ec2.ec2_service import VpnEndpoint
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_client_vpn_endpoint_connection_logging_enabled:
    @mock_aws
    def test_ec2_no_vpn_endpoints(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client_vpn_endpoint_connection_logging_enabled import (
                ec2_client_vpn_endpoint_connection_logging_enabled,
            )

            check = ec2_client_vpn_endpoint_connection_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_ec2_vpn_endpoint_without_connection_logging(self):
        # Create EC2 Mocked Resources
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        ec2 = EC2(aws_provider)

        # Assuming that you mock the creation of a VPN endpoint without connection logging
        ec2.vpn_endpoints = {
            "arn:aws:ec2:us-east-1:123456789012:client-vpn-endpoint/cvpn-endpoint-1234567890abcdef0": VpnEndpoint(
                id="cvpn-endpoint-1234567890abcdef0",
                connection_logging=False,
                region=AWS_REGION_US_EAST_1,
                tags=None,
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client",
            new=ec2,
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client_vpn_endpoint_connection_logging_enabled import (
                ec2_client_vpn_endpoint_connection_logging_enabled,
            )

            check = ec2_client_vpn_endpoint_connection_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"Client VPN endpoint cvpn-endpoint-1234567890abcdef0 in region {AWS_REGION_US_EAST_1} does not have client connection logging enabled."
            )
            assert (
                result[0].resource_arn
                == "arn:aws:ec2:us-east-1:123456789012:client-vpn-endpoint/cvpn-endpoint-1234567890abcdef0"
            )

    @mock_aws
    def test_ec2_vpn_endpoint_with_connection_logging(self):
        # Create EC2 Mocked Resources
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        ec2 = EC2(aws_provider)

        # Assuming that you mock the creation of a VPN endpoint with connection logging
        ec2.vpn_endpoints = {
            "arn:aws:ec2:us-east-1:123456789012:client-vpn-endpoint/cvpn-endpoint-1234567890abcdef0": VpnEndpoint(
                id="cvpn-endpoint-1234567890abcdef0",
                connection_logging=True,
                region=AWS_REGION_US_EAST_1,
                tags=None,
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client",
            new=ec2,
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_client_vpn_endpoint_connection_logging_enabled.ec2_client_vpn_endpoint_connection_logging_enabled import (
                ec2_client_vpn_endpoint_connection_logging_enabled,
            )

            check = ec2_client_vpn_endpoint_connection_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"Client VPN endpoint cvpn-endpoint-1234567890abcdef0 in region {AWS_REGION_US_EAST_1} has client connection logging enabled."
            )
            assert (
                result[0].resource_arn
                == "arn:aws:ec2:us-east-1:123456789012:client-vpn-endpoint/cvpn-endpoint-1234567890abcdef0"
            )
