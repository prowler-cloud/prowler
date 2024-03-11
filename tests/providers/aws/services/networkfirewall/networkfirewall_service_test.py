from unittest.mock import patch

import botocore

from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    NetworkFirewall,
)
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

FIREWALL_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall"
FIREWALL_NAME = "my-firewall"
VPC_ID = "vpc-12345678901234567"
POLICY_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/my-policy"

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListFirewalls":
        return {
            "Firewalls": [
                {"FirewallName": FIREWALL_NAME, "FirewallArn": FIREWALL_ARN},
            ]
        }
    if operation_name == "DescribeFirewall":
        return {
            "Firewall": {
                "DeleteProtection": True,
                "Description": "Description of the firewall",
                "EncryptionConfiguration": {
                    "KeyId": "my-key-id",
                    "Type": "CUSTOMER_KMS",
                },
                "FirewallArn": FIREWALL_ARN,
                "FirewallId": "firewall-id",
                "FirewallName": FIREWALL_NAME,
                "FirewallPolicyArn": POLICY_ARN,
                "FirewallPolicyChangeProtection": False,
                "SubnetChangeProtection": False,
                "SubnetMappings": [{"IPAddressType": "string", "SubnetId": "string"}],
                "Tags": [{"Key": "test_tag", "Value": "test_value"}],
                "VpcId": VPC_ID,
            }
        }

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_NetworkFirewall_Service:
    def test__get_client__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        networkfirewall = NetworkFirewall(aws_provider)
        assert (
            networkfirewall.regional_clients[AWS_REGION_US_EAST_1].__class__.__name__
            == "NetworkFirewall"
        )

    def test__get_service__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        networkfirewall = NetworkFirewall(aws_provider)
        assert networkfirewall.service == "network-firewall"

    def test__list_firewalls__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        networkfirewall = NetworkFirewall(aws_provider)
        assert len(networkfirewall.network_firewalls) == 1
        assert networkfirewall.network_firewalls[0].arn == FIREWALL_ARN
        assert networkfirewall.network_firewalls[0].region == AWS_REGION_US_EAST_1
        assert networkfirewall.network_firewalls[0].name == FIREWALL_NAME

    def test__describe_firewall__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        networkfirewall = NetworkFirewall(aws_provider)
        assert len(networkfirewall.network_firewalls) == 1
        assert networkfirewall.network_firewalls[0].arn == FIREWALL_ARN
        assert networkfirewall.network_firewalls[0].region == AWS_REGION_US_EAST_1
        assert networkfirewall.network_firewalls[0].name == FIREWALL_NAME
        assert networkfirewall.network_firewalls[0].policy_arn == POLICY_ARN
        assert networkfirewall.network_firewalls[0].vpc_id == VPC_ID
        assert networkfirewall.network_firewalls[0].tags == [
            {"Key": "test_tag", "Value": "test_value"}
        ]
        assert networkfirewall.network_firewalls[0].encryption_type == "CUSTOMER_KMS"
