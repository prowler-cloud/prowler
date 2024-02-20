from unittest.mock import patch

from azure.mgmt.network.models import FlowLog

from prowler.providers.azure.services.network.network_service import (
    BastionHost,
    Network,
    NetworkWatcher,
    SecurityGroup,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_network_get_security_groups(_, token):
    return {
        AZURE_SUBSCRIPTION: [
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
        AZURE_SUBSCRIPTION: [
            BastionHost(
                id="id",
                name="name",
                location="location",
            )
        ]
    }


def mock_network_get_network_watchers(_):
    return {
        AZURE_SUBSCRIPTION: [
            NetworkWatcher(
                id="id",
                name="name",
                location="location",
                flow_logs=[FlowLog(enabled=True, retention_policy=90)],
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.network.network_service.Network.__get_security_groups__",
    new=mock_network_get_security_groups,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network.__get_bastion_hosts__",
    new=mock_network_get_bastion_hosts,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network.__get_network_watchers__",
    new=mock_network_get_network_watchers,
)
class Test_Network_Service:
    def test__get_client__(self):
        network = Network(set_mocked_azure_audit_info())
        assert (
            network.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "NetworkManagementClient"
        )

    def test__get_security_groups__(self):
        network = Network(set_mocked_azure_audit_info())
        assert (
            network.security_groups[AZURE_SUBSCRIPTION][0].__class__.__name__
            == "SecurityGroup"
        )
        assert network.security_groups[AZURE_SUBSCRIPTION][0].id == "id"
        assert network.security_groups[AZURE_SUBSCRIPTION][0].name == "name"
        assert network.security_groups[AZURE_SUBSCRIPTION][0].location == "location"
        assert network.security_groups[AZURE_SUBSCRIPTION][0].security_rules == []

    def test__get_network_watchers__(self):
        network = Network(set_mocked_azure_audit_info())
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION][0].__class__.__name__
            == "NetworkWatcher"
        )
        assert network.network_watchers[AZURE_SUBSCRIPTION][0].id == "id"
        assert network.network_watchers[AZURE_SUBSCRIPTION][0].name == "name"
        assert network.network_watchers[AZURE_SUBSCRIPTION][0].location == "location"
        assert network.network_watchers[AZURE_SUBSCRIPTION][0].flow_logs == [
            FlowLog(enabled=True, retention_policy=90)
        ]

    def __get_flow_logs__(self):
        network = Network(set_mocked_azure_audit_info())
        nw_name = "name"
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION][0]
            .flow_logs[nw_name][0]
            .__class__.__name__
            == "FlowLog"
        )
        assert network.network_watchers[AZURE_SUBSCRIPTION][0].flow_logs == [
            FlowLog(enabled=True, retention_policy=90)
        ]
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION][0].flow_logs[0].enabled is True
        )
        assert (
            network.network_watchers[AZURE_SUBSCRIPTION][0]
            .flow_logs[0]
            .retention_policy
            == 90
        )

    def __get_bastion_hosts__(self):
        network = Network(set_mocked_azure_audit_info())
        assert (
            network.bastion_hosts[AZURE_SUBSCRIPTION][0].__class__.__name__
            == "BastionHost"
        )
        assert network.bastion_hosts[AZURE_SUBSCRIPTION][0].id == "id"
        assert network.bastion_hosts[AZURE_SUBSCRIPTION][0].name == "name"
        assert network.bastion_hosts[AZURE_SUBSCRIPTION][0].location == "location"
