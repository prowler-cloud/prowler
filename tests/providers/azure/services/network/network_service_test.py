from unittest.mock import patch

from azure.mgmt.network.models import FlowLog, NetworkWatcher

from prowler.providers.azure.services.network.network_service import (
    Network,
    SecurityGroup,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_sqlserver_get_security_groups(_):
    network_watchers = [
        NetworkWatcher(
            id="id",
            location="location",
        )
    ]
    return {
        AZURE_SUBSCRIPTION: [
            SecurityGroup(
                id="id",
                name="name",
                location="location",
                security_rules=[],
                network_watchers=network_watchers,
                subscription_locations=["location"],
                flow_logs=[FlowLog(enabled=True, retention_policy=90)],
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.network.network_service.Network.__get_security_groups__",
    new=mock_sqlserver_get_security_groups,
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
            network.security_groups[AZURE_SUBSCRIPTION][0]
            .network_watchers[0]
            .__class__.__name__
            == "NetworkWatcher"
        )
        assert (
            network.security_groups[AZURE_SUBSCRIPTION][0].network_watchers[0].id
            == "id"
        )
        assert (
            network.security_groups[AZURE_SUBSCRIPTION][0].network_watchers[0].location
            == "location"
        )

    def test__get_subscription_locations__(self):
        network = Network(set_mocked_azure_audit_info())
        assert network.security_groups[AZURE_SUBSCRIPTION][
            0
        ].subscription_locations == ["location"]

    def __get_flow_logs__(self):
        network = Network(set_mocked_azure_audit_info())
        nw_name = "name"
        assert (
            network.security_groups[AZURE_SUBSCRIPTION][0]
            .flow_logs[nw_name][0]
            .__class__.__name__
            == "FlowLog"
        )
        assert network.security_groups[AZURE_SUBSCRIPTION][0].flow_logs == [
            FlowLog(enabled=True, retention_policy=90)
        ]
        assert (
            network.security_groups[AZURE_SUBSCRIPTION][0].flow_logs[0].enabled is True
        )
        assert (
            network.security_groups[AZURE_SUBSCRIPTION][0].flow_logs[0].retention_policy
            == 90
        )
