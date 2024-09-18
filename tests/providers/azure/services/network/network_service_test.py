from unittest.mock import patch

from azure.mgmt.network.models import FlowLog

from prowler.providers.azure.services.network.network_service import (
    BastionHost,
    Network,
    NetworkWatcher,
    PublicIp,
    SecurityGroup,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_network_get_security_groups(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            SecurityGroup(
                id="id",
                name="name",
                location="location",
                security_rules=[],
            )
        ]
    }


def mock_network_get_bastion_hosts(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            BastionHost(
                id="id",
                name="name",
                location="location",
            )
        ]
    }


def mock_network_get_network_watchers(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            NetworkWatcher(
                id="id",
                name="name",
                location="location",
                flow_logs=[FlowLog(enabled=True, retention_policy=90)],
            )
        ]
    }


def mock_network_get_public_ip_addresses(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            PublicIp(
                id="id",
                name="name",
                location="location",
                ip_address="ip_address",
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
    new=mock_network_get_security_groups,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
    new=mock_network_get_bastion_hosts,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
    new=mock_network_get_network_watchers,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
    new=mock_network_get_public_ip_addresses,
)
class Test_Network_Service:
    def test_get_client(self):
        network = Network(set_mocked_azure_provider())
        assert (
            network.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "NetworkManagementClient"
        )

    def test_get_security_groups(self):
        network = Network(set_mocked_azure_provider())
        assert (
            network.security_groups[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
            == "SecurityGroup"
        )
        assert network.security_groups[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert network.security_groups[AZURE_SUBSCRIPTION_ID][0].name == "name"
        assert network.security_groups[AZURE_SUBSCRIPTION_ID][0].location == "location"
        assert network.security_groups[AZURE_SUBSCRIPTION_ID][0].security_rules == []

    def test_get_network_watchers(self):
        network = Network(set_mocked_azure_provider())
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
            == "NetworkWatcher"
        )
        assert network.network_watchers[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert network.network_watchers[AZURE_SUBSCRIPTION_ID][0].name == "name"
        assert network.network_watchers[AZURE_SUBSCRIPTION_ID][0].location == "location"
        assert network.network_watchers[AZURE_SUBSCRIPTION_ID][0].flow_logs == [
            FlowLog(enabled=True, retention_policy=90)
        ]

    def _get_flow_logs(self):
        network = Network(set_mocked_azure_provider())
        nw_name = "name"
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION_ID][0]
            .flow_logs[nw_name][0]
            .__class__.__name__
            == "FlowLog"
        )
        assert network.network_watchers[AZURE_SUBSCRIPTION_ID][0].flow_logs == [
            FlowLog(enabled=True, retention_policy=90)
        ]
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION_ID][0].flow_logs[0].enabled
            is True
        )
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION_ID][0]
            .flow_logs[0]
            .retention_policy
            == 90
        )

    def _get_bastion_hosts(self):
        network = Network(set_mocked_azure_provider())
        assert (
            network.bastion_hosts[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
            == "BastionHost"
        )
        assert network.bastion_hosts[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert network.bastion_hosts[AZURE_SUBSCRIPTION_ID][0].name == "name"
        assert network.bastion_hosts[AZURE_SUBSCRIPTION_ID][0].location == "location"

    def _get_public_ip_addresses(self):
        network = Network(set_mocked_azure_provider())
        assert (
            network.public_ip_addresses[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
            == "PublicIp"
        )
        assert network.public_ip_addresses[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert network.public_ip_addresses[AZURE_SUBSCRIPTION_ID][0].name == "name"
        assert (
            network.public_ip_addresses[AZURE_SUBSCRIPTION_ID][0].location == "location"
        )
        assert (
            network.public_ip_addresses[AZURE_SUBSCRIPTION_ID][0].ip_address
            == "ip_address"
        )
