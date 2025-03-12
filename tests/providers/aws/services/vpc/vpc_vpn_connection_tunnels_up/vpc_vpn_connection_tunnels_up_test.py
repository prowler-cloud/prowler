from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeVpnConnections":
        return {
            "VpnConnections": [
                {
                    "VpnConnectionId": "vpn-1234567890abcdef0",
                    "CustomerGatewayId": "cgw-0123456789abcdef0",
                    "VpnGatewayId": "vgw-0123456789abcdef0",
                    "State": "available",
                    "Type": "ipsec.1",
                    "VgwTelemetry": [
                        {
                            "OutsideIpAddress": "192.168.1.1",
                            "Status": "UP",
                            "AcceptedRouteCount": 10,
                        },
                        {
                            "OutsideIpAddress": "192.168.1.2",
                            "Status": "UP",
                            "AcceptedRouteCount": 5,
                        },
                    ],
                    "Tags": [{"Key": "Name", "Value": "MyVPNConnection"}],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "DescribeVpnConnections":
        return {
            "VpnConnections": [
                {
                    "VpnConnectionId": "vpn-1234567890abcdef0",
                    "CustomerGatewayId": "cgw-0123456789abcdef0",
                    "VpnGatewayId": "vgw-0123456789abcdef0",
                    "State": "available",
                    "Type": "ipsec.1",
                    "VgwTelemetry": [
                        {
                            "OutsideIpAddress": "192.168.1.1",
                            "Status": "UP",
                            "AcceptedRouteCount": 10,
                        },
                        {
                            "OutsideIpAddress": "192.168.1.2",
                            "Status": "DOWN",
                            "AcceptedRouteCount": 5,
                        },
                    ],
                    "Tags": [{"Key": "Name", "Value": "MyVPNConnection"}],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_vpc_vpn_connection_tunnels_up:
    @mock_aws
    def test_no_vpn_connections(self):

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_vpn_connection_tunnels_up.vpc_vpn_connection_tunnels_up.vpc_client",
            new=VPC(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.vpc.vpc_vpn_connection_tunnels_up.vpc_vpn_connection_tunnels_up import (
                vpc_vpn_connection_tunnels_up,
            )

            check = vpc_vpn_connection_tunnels_up()
            result = check.execute()

            assert len(result) == 0

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_vpn_both_tunnels_up(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_vpn_connection_tunnels_up.vpc_vpn_connection_tunnels_up.vpc_client",
            new=VPC(aws_provider),
        ):
            from prowler.providers.aws.services.vpc.vpc_vpn_connection_tunnels_up.vpc_vpn_connection_tunnels_up import (
                vpc_vpn_connection_tunnels_up,
            )

            check = vpc_vpn_connection_tunnels_up()
            result = check.execute()

            # Se espera que el resultado sea PASS ya que ambos túneles están "UP"
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "vpn-1234567890abcdef0"
            assert (
                result[0].resource_arn
                == "arn:aws:ec2:us-east-1:123456789012:vpn-connection/vpn-1234567890abcdef0"
            )
            assert (
                result[0].status_extended
                == "VPN Connection vpn-1234567890abcdef0 has both tunnels UP. "
            )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_vpn_one_tunnel_down(self):

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_vpn_connection_tunnels_up.vpc_vpn_connection_tunnels_up.vpc_client",
            new=VPC(aws_provider),
        ):
            from prowler.providers.aws.services.vpc.vpc_vpn_connection_tunnels_up.vpc_vpn_connection_tunnels_up import (
                vpc_vpn_connection_tunnels_up,
            )

            check = vpc_vpn_connection_tunnels_up()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "vpn-1234567890abcdef0"
            assert (
                result[0].resource_arn
                == "arn:aws:ec2:us-east-1:123456789012:vpn-connection/vpn-1234567890abcdef0"
            )
            assert (
                result[0].status_extended
                == "VPN Connection vpn-1234567890abcdef0 has at least one tunnel DOWN. "
            )
