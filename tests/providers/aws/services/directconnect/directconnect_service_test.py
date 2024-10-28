import botocore
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.directconnect.directconnect_service import (
    DirectConnect,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Mocking DX Calls - Moto does not allow describe connection across all DXs
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "DescribeConnections":
        return {
            "connections": [
                {
                    "ownerAccount": AWS_ACCOUNT_NUMBER,
                    "connectionId": "dx-moto-test-conn-20241022005109",
                    "connectionName": "test-conn",
                    "connectionState": "available",
                    "region": AWS_REGION_US_EAST_1,
                    "location": "Ashburn",
                    "bandwidth": "5000",
                    "vlan": 123,
                    "tags": [
                        {"key": "string", "value": "string"},
                    ],
                },
            ]
        }

    if operation_name == "DescribeVirtualInterfaces":
        return {
            "virtualInterfaces": [
                {
                    "ownerAccount": AWS_ACCOUNT_NUMBER,
                    "virtualInterfaceId": "vif-moto-test-conn",
                    "location": "Ashburn",
                    "connectionId": "dx-moto-test-conn-20241022005109",
                    "virtualInterfaceType": "public",
                    "virtualInterfaceName": "test-viff",
                    "vlan": 123,
                    "asn": 123,
                    "amazonSideAsn": 123,
                    "addressFamily": "ipv4",
                    "virtualInterfaceState": "available",
                    "customerRouterConfig": "test",
                    "mtu": 123,
                    "jumboFrameCapable": True,
                    "virtualGatewayId": "vgw-moto-test-conn",
                    "directConnectGatewayId": "dxgw-moto-test-conn",
                    "region": AWS_REGION_US_EAST_1,
                    "tags": [
                        {"key": "string", "value": "string"},
                    ],
                    "siteLinkEnabled": True,
                },
                {
                    "ownerAccount": AWS_ACCOUNT_NUMBER,
                    "virtualInterfaceId": "vif-moto-test-conn-2",
                    "location": "Ashburn",
                    "connectionId": "dx-moto-test-conn-202410220051092",
                    "virtualInterfaceType": "public",
                    "virtualInterfaceName": "test-viff-2",
                    "vlan": 123,
                    "asn": 123,
                    "amazonSideAsn": 123,
                    "addressFamily": "ipv4",
                    "virtualInterfaceState": "available",
                    "customerRouterConfig": "test",
                    "mtu": 123,
                    "jumboFrameCapable": True,
                    "virtualGatewayId": "vgw-moto-test-conn",
                    "directConnectGatewayId": "dxgw-moto-test-conn",
                    "region": AWS_REGION_US_EAST_1,
                    "tags": [
                        {"key": "string", "value": "string"},
                    ],
                    "siteLinkEnabled": True,
                },
            ]
        }
    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_DirectConnect_Service:
    # Test DirectConnect Service
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(AWS_REGION_US_EAST_1)
        directconnect = DirectConnect(aws_provider)
        assert directconnect.service == "directconnect"

    # Test DirectConnect client
    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(AWS_REGION_US_EAST_1)
        directconnect = DirectConnect(aws_provider)
        for regional_client in directconnect.regional_clients.values():
            assert regional_client.__class__.__name__ == "DirectConnect"

    # Test DirectConnect session
    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider(AWS_REGION_US_EAST_1)
        directconnect = DirectConnect(aws_provider)
        assert directconnect.session.__class__.__name__ == "Session"

    # Test DirectConnect Session
    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider(AWS_REGION_US_EAST_1)
        directconnect = DirectConnect(aws_provider)
        assert directconnect.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_describe_connect(self):
        arn = f"arn:aws:directconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:dxcon/dx-moto-test-conn-20241022005109"

        aws_provider = set_mocked_aws_provider(AWS_REGION_US_EAST_1)
        directconnect = DirectConnect(aws_provider)
        assert len(directconnect.connections) == 1
        assert directconnect.connections[arn].region == AWS_REGION_US_EAST_1
        assert directconnect.connections[arn].location == "Ashburn"
        assert directconnect.connections[arn].name == "test-conn"
        assert directconnect.connections[arn].id == "dx-moto-test-conn-20241022005109"

    @mock_aws
    def test_describe_vif(self):
        aws_provider = set_mocked_aws_provider(AWS_REGION_US_EAST_1)
        directconnect = DirectConnect(aws_provider)
        vif_arn = f"arn:aws:directconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:dxvif/vif-moto-test-conn"
        assert len(directconnect.vifs) == 2
        assert directconnect.vifs[vif_arn].arn == vif_arn
        assert directconnect.vifs[vif_arn].region == AWS_REGION_US_EAST_1
        assert directconnect.vifs[vif_arn].location == "Ashburn"
        assert (
            directconnect.vifs[vif_arn].connection_id
            == "dx-moto-test-conn-20241022005109"
        )
        assert directconnect.vifs[vif_arn].vgw_gateway_id == "vgw-moto-test-conn"
        assert directconnect.vifs[vif_arn].dx_gateway_id == "dxgw-moto-test-conn"
        assert directconnect.vifs[vif_arn].name == "test-viff"

    @mock_aws
    def test_describe_vgws(self):
        aws_provider = set_mocked_aws_provider(AWS_REGION_US_EAST_1)
        directconnect = DirectConnect(aws_provider)
        vgw_arn = f"arn:aws:directconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:virtual-gateway/vgw-moto-test-conn"
        dxgw_arn = f"arn:aws:directconnect:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:dx-gateway/dxgw-moto-test-conn"
        assert len(directconnect.vifs) == 2
        assert len(directconnect.vgws) == 1
        assert len(directconnect.dxgws) == 1
        assert directconnect.vgws[vgw_arn].region == AWS_REGION_US_EAST_1
        assert directconnect.vgws[vgw_arn].id == "vgw-moto-test-conn"
        assert directconnect.vgws[vgw_arn].connections == [
            "dx-moto-test-conn-20241022005109",
            "dx-moto-test-conn-202410220051092",
        ]
        assert directconnect.vgws[vgw_arn].vifs == [
            "vif-moto-test-conn",
            "vif-moto-test-conn-2",
        ]
        assert directconnect.dxgws[dxgw_arn].region == AWS_REGION_US_EAST_1
        assert directconnect.dxgws[dxgw_arn].id == "dxgw-moto-test-conn"
        assert directconnect.dxgws[dxgw_arn].connections == [
            "dx-moto-test-conn-20241022005109",
            "dx-moto-test-conn-202410220051092",
        ]
        assert directconnect.dxgws[dxgw_arn].vifs == [
            "vif-moto-test-conn",
            "vif-moto-test-conn-2",
        ]
