from unittest.mock import MagicMock, patch

from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.network import models as azure_network_models
from azure.mgmt.network.models import (
    ApplicationGatewaySku,
    ApplicationGatewayWebApplicationFirewallConfiguration,
    FlowLog,
    SubResource,
)

from prowler.providers.azure.services.network.network_service import (
    ApplicationGateway,
    BastionHost,
    Network,
    NetworkWatcher,
    PublicIp,
    SecurityGroup,
    VirtualNetwork,
    WafPolicy,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
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


def mock_network_get_virtual_networks(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            VirtualNetwork(
                id="id",
                name="name",
                location="location",
                enable_ddos_protection=False,
                subnets=[],
            )
        ]
    }


def mock_network_get_waf_policies(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "waf_id": WafPolicy(
                id="waf_id", name="waf_name", location="location", state="Enabled"
            )
        }
    }


def mock_network_get_application_gateways(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "id": ApplicationGateway(
                id="id",
                name="name",
                location="location",
                firewall_policy_id="policy_id",
                http2_enabled=True,
            )
        }
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
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_virtual_networks",
    new=mock_network_get_virtual_networks,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
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

    def test_get_waf_policies(self):
        network = Network(set_mocked_azure_provider())
        policy = network.waf_policies[AZURE_SUBSCRIPTION_ID]["waf_id"]
        assert policy.__class__.__name__ == "WafPolicy"
        assert policy.name == "waf_name"
        assert policy.state == "Enabled"

    def test_get_application_gateways(self):
        network = Network(set_mocked_azure_provider())
        gateway = network.application_gateways[AZURE_SUBSCRIPTION_ID]["id"]
        assert gateway.__class__.__name__ == "ApplicationGateway"
        assert gateway.name == "name"
        assert gateway.firewall_policy_id == "policy_id"
        assert gateway.http2_enabled is True

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


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_security_groups:
    def test_get_security_groups_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.network_security_groups.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = None

        result = network._get_security_groups()

        mock_client.network_security_groups.list_all.assert_called_once()
        mock_client.network_security_groups.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_security_groups_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.network_security_groups.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = network._get_security_groups()

        mock_client.network_security_groups.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.network_security_groups.list_all.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_security_groups_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = network._get_security_groups()

        mock_client.network_security_groups.list.assert_not_called()
        mock_client.network_security_groups.list_all.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []

    def test_get_security_groups_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.network_security_groups = MagicMock()
        mock_client.network_security_groups.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = network._get_security_groups()

        assert mock_client.network_security_groups.list.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_security_groups_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.network_security_groups = MagicMock()
        mock_client.network_security_groups.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        network._get_security_groups()

        mock_client.network_security_groups.list.assert_called_once_with(
            resource_group_name="RG"
        )


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_network_watchers:
    def test_get_network_watchers_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()
        mock_client.network_watchers.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = None

        result = network._get_network_watchers()

        mock_client.network_watchers.list_all.assert_called_once()
        mock_client.network_watchers.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_network_watchers_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()
        mock_client.network_watchers.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = network._get_network_watchers()

        mock_client.network_watchers.list_all.assert_called_once()
        mock_client.network_watchers.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_network_watchers_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()
        mock_client.network_watchers.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = network._get_network_watchers()

        mock_client.network_watchers.list_all.assert_called_once()
        mock_client.network_watchers.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_bastion_hosts:
    def test_get_bastion_hosts_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.bastion_hosts = MagicMock()
        mock_client.bastion_hosts.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = None

        result = network._get_bastion_hosts()

        mock_client.bastion_hosts.list.assert_called_once()
        mock_client.bastion_hosts.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_bastion_hosts_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.bastion_hosts = MagicMock()
        mock_client.bastion_hosts.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = network._get_bastion_hosts()

        mock_client.bastion_hosts.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.bastion_hosts.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_bastion_hosts_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.bastion_hosts = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = network._get_bastion_hosts()

        mock_client.bastion_hosts.list_by_resource_group.assert_not_called()
        mock_client.bastion_hosts.list.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_public_ip_addresses:
    def test_get_public_ip_addresses_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.public_ip_addresses = MagicMock()
        mock_client.public_ip_addresses.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = None

        result = network._get_public_ip_addresses()

        mock_client.public_ip_addresses.list_all.assert_called_once()
        mock_client.public_ip_addresses.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_public_ip_addresses_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.public_ip_addresses = MagicMock()
        mock_client.public_ip_addresses.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = network._get_public_ip_addresses()

        mock_client.public_ip_addresses.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.public_ip_addresses.list_all.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_public_ip_addresses_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.public_ip_addresses = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = network._get_public_ip_addresses()

        mock_client.public_ip_addresses.list.assert_not_called()
        mock_client.public_ip_addresses.list_all.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_network_watchers_extra:
    def test_get_network_watchers_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()
        mock_client.network_watchers.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = network._get_network_watchers()

        mock_client.network_watchers.list_all.assert_called_once()
        mock_client.network_watchers.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_network_watchers_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()
        mock_client.network_watchers.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        network._get_network_watchers()

        mock_client.network_watchers.list_all.assert_called_once()
        mock_client.network_watchers.list.assert_not_called()


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_bastion_hosts_extra:
    def test_get_bastion_hosts_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.bastion_hosts = MagicMock()
        mock_client.bastion_hosts.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = network._get_bastion_hosts()

        assert mock_client.bastion_hosts.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_bastion_hosts_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.bastion_hosts = MagicMock()
        mock_client.bastion_hosts.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        network._get_bastion_hosts()

        mock_client.bastion_hosts.list_by_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_public_ip_addresses_extra:
    def test_get_public_ip_addresses_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.public_ip_addresses = MagicMock()
        mock_client.public_ip_addresses.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = network._get_public_ip_addresses()

        assert mock_client.public_ip_addresses.list.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_public_ip_addresses_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.public_ip_addresses = MagicMock()
        mock_client.public_ip_addresses.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        network._get_public_ip_addresses()

        mock_client.public_ip_addresses.list.assert_called_once_with(
            resource_group_name="RG"
        )


@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_waf_policies",
    new=mock_network_get_waf_policies,
)
@patch(
    "prowler.providers.azure.services.network.network_service.Network._get_application_gateways",
    new=mock_network_get_application_gateways,
)
class Test_Network_get_virtual_networks_extra:
    def _ctx(self):
        return (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
        )

    def test_get_virtual_networks_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.virtual_networks = MagicMock()
        mock_client.virtual_networks.list_all.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_virtual_networks",
                new=mock_network_get_virtual_networks,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = None

        result = network._get_virtual_networks()

        mock_client.virtual_networks.list_all.assert_called_once()
        mock_client.virtual_networks.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_virtual_networks_with_resource_group(self):
        mock_client = MagicMock()
        mock_client.virtual_networks = MagicMock()
        mock_client.virtual_networks.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_virtual_networks",
                new=mock_network_get_virtual_networks,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = network._get_virtual_networks()

        mock_client.virtual_networks.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.virtual_networks.list_all.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_virtual_networks_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.virtual_networks = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_virtual_networks",
                new=mock_network_get_virtual_networks,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = network._get_virtual_networks()

        mock_client.virtual_networks.list.assert_not_called()
        mock_client.virtual_networks.list_all.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []

    def test_get_virtual_networks_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.virtual_networks = MagicMock()
        mock_client.virtual_networks.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_virtual_networks",
                new=mock_network_get_virtual_networks,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = network._get_virtual_networks()

        assert mock_client.virtual_networks.list.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_virtual_networks_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.virtual_networks = MagicMock()
        mock_client.virtual_networks.list.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_security_groups",
                new=mock_network_get_security_groups,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_bastion_hosts",
                new=mock_network_get_bastion_hosts,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_network_watchers",
                new=mock_network_get_network_watchers,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_public_ip_addresses",
                new=mock_network_get_public_ip_addresses,
            ),
            patch(
                "prowler.providers.azure.services.network.network_service.Network._get_virtual_networks",
                new=mock_network_get_virtual_networks,
            ),
        ):
            network = Network(set_mocked_azure_provider())

        network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        network.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        network._get_virtual_networks()

        mock_client.virtual_networks.list.assert_called_once_with(
            resource_group_name="RG"
        )


NETWORK = "prowler.providers.azure.services.network.network_service.Network"
GATEWAY_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/applicationGateways/agw1"
GATEWAY_POLICY_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf1"


def build_network_with_client(mock_client, resource_groups=None):
    with (
        patch(f"{NETWORK}._get_security_groups", new=mock_network_get_security_groups),
        patch(f"{NETWORK}._get_bastion_hosts", new=mock_network_get_bastion_hosts),
        patch(
            f"{NETWORK}._get_network_watchers", new=mock_network_get_network_watchers
        ),
        patch(
            f"{NETWORK}._get_public_ip_addresses",
            new=mock_network_get_public_ip_addresses,
        ),
        patch(
            f"{NETWORK}._get_virtual_networks", new=mock_network_get_virtual_networks
        ),
        patch(f"{NETWORK}._get_waf_policies", new=mock_network_get_waf_policies),
        patch(
            f"{NETWORK}._get_application_gateways",
            new=mock_network_get_application_gateways,
        ),
    ):
        network = Network(set_mocked_azure_provider())
    network.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
    network.resource_groups = resource_groups
    return network


def build_sdk_waf_policy(state, policy_id=GATEWAY_POLICY_ID, name="waf1"):
    waf_policy = azure_network_models.WebApplicationFirewallPolicy(
        id=policy_id,
        location="westeurope",
        policy_settings=azure_network_models.PolicySettings(state=state),
    )
    waf_policy.name = name
    return waf_policy


def build_waf_policy_model(state, policy_id=GATEWAY_POLICY_ID):
    return WafPolicy(id=policy_id, name="waf1", location="westeurope", state=state)


def build_sdk_application_gateway(name="agw1", policy_id=None):
    gateway = azure_network_models.ApplicationGateway(
        id=GATEWAY_ID.replace("agw1", name),
        location="westeurope",
        sku=ApplicationGatewaySku(name="WAF_v2", tier="WAF_v2"),
        firewall_policy=SubResource(id=policy_id) if policy_id else None,
    )
    gateway.name = name
    return gateway


def get_gateways(mock_client, listed_policies=(), resource_groups=None):
    """Collect gateways with the given WAF policies already listed."""
    network = build_network_with_client(mock_client, resource_groups)
    network.waf_policies = {
        AZURE_SUBSCRIPTION_ID: {policy.id: policy for policy in listed_policies}
    }
    return network, network._get_application_gateways()


class Test_Network_get_waf_policies:
    def test_maps_policy_state(self):
        mock_client = MagicMock()
        mock_client.web_application_firewall_policies.list_all.return_value = [
            build_sdk_waf_policy("Enabled")
        ]

        network = build_network_with_client(mock_client)
        result = network._get_waf_policies()

        assert network.waf_policies_lookup_failed == set()
        policy = result[AZURE_SUBSCRIPTION_ID][GATEWAY_POLICY_ID]
        assert policy.id == GATEWAY_POLICY_ID
        assert policy.name == "waf1"
        assert policy.location == "westeurope"
        assert policy.state == "Enabled"

    def test_uses_resource_group_scope(self):
        mock_client = MagicMock()
        mock_client.web_application_firewall_policies.list.return_value = []

        network = build_network_with_client(
            mock_client, {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}
        )
        result = network._get_waf_policies()

        mock_client.web_application_firewall_policies.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.web_application_firewall_policies.list_all.assert_not_called()
        assert result == {AZURE_SUBSCRIPTION_ID: {}}

    def test_api_error_marks_subscription_lookup_failed(self):
        mock_client = MagicMock()
        mock_client.web_application_firewall_policies.list_all.side_effect = Exception(
            "boom"
        )

        network = build_network_with_client(mock_client)
        result = network._get_waf_policies()

        assert result == {AZURE_SUBSCRIPTION_ID: {}}
        assert network.waf_policies_lookup_failed == {AZURE_SUBSCRIPTION_ID}

    def test_resource_group_error_marks_subscription_lookup_failed(self):
        mock_client = MagicMock()
        mock_client.web_application_firewall_policies.list.side_effect = Exception(
            "boom"
        )

        network = build_network_with_client(
            mock_client, {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}
        )
        result = network._get_waf_policies()

        assert result == {AZURE_SUBSCRIPTION_ID: {}}
        assert network.waf_policies_lookup_failed == {AZURE_SUBSCRIPTION_ID}

    def test_missing_resource_group_is_not_a_failed_lookup(self):
        mock_client = MagicMock()
        mock_client.web_application_firewall_policies.list.side_effect = (
            ResourceNotFoundError("gone")
        )

        network = build_network_with_client(
            mock_client, {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}
        )
        result = network._get_waf_policies()

        assert result == {AZURE_SUBSCRIPTION_ID: {}}
        assert network.waf_policies_lookup_failed == set()

    def test_unmappable_policy_is_skipped_and_marks_subscription(self):
        broken = azure_network_models.WebApplicationFirewallPolicy(
            location="westeurope"
        )
        mock_client = MagicMock()
        mock_client.web_application_firewall_policies.list_all.return_value = [
            broken,
            build_sdk_waf_policy("Enabled"),
        ]

        network = build_network_with_client(mock_client)
        result = network._get_waf_policies()

        assert list(result[AZURE_SUBSCRIPTION_ID]) == [GATEWAY_POLICY_ID]
        assert network.waf_policies_lookup_failed == {AZURE_SUBSCRIPTION_ID}


class Test_Network_get_application_gateways:
    def test_maps_gateway_settings(self):
        gateway = azure_network_models.ApplicationGateway(
            id=GATEWAY_ID,
            location="westeurope",
            sku=ApplicationGatewaySku(name="WAF_v2", tier="WAF_v2"),
            firewall_policy=SubResource(id=GATEWAY_POLICY_ID),
            enable_http2=True,
        )
        gateway.name = "agw1"
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [gateway]

        network, result = get_gateways(mock_client, [build_waf_policy_model("Enabled")])

        assert network.application_gateways_lookup_failed == set()
        mock_client.web_application_firewall_policies.get.assert_not_called()
        mapped = result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID]
        assert mapped.name == "agw1"
        assert mapped.location == "westeurope"
        assert mapped.firewall_policy_id == GATEWAY_POLICY_ID
        assert mapped.firewall_policy_enabled is True
        assert mapped.waf_configuration_enabled is False
        assert mapped.http2_enabled is True

    def test_maps_legacy_waf_configuration(self):
        waf_configuration = ApplicationGatewayWebApplicationFirewallConfiguration(
            enabled=True,
            firewall_mode="Prevention",
            rule_set_type="OWASP",
            rule_set_version="3.2",
        )
        gateway = azure_network_models.ApplicationGateway(
            id=GATEWAY_ID,
            location="westeurope",
            sku=ApplicationGatewaySku(name="WAF_v2", tier="WAF_v2"),
            web_application_firewall_configuration=waf_configuration,
        )
        gateway.name = "agw1"
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [gateway]

        _, result = get_gateways(mock_client)

        mapped = result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID]
        assert mapped.firewall_policy_id is None
        assert mapped.firewall_policy_enabled is None
        assert mapped.waf_configuration_enabled is True
        assert mapped.http2_enabled is False

    def test_uses_resource_group_scope(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list.return_value = []

        _, result = get_gateways(
            mock_client, resource_groups={AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}
        )

        mock_client.application_gateways.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.application_gateways.list_all.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_api_error_marks_subscription_lookup_failed(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.side_effect = Exception("boom")

        network, result = get_gateways(mock_client)

        assert result == {AZURE_SUBSCRIPTION_ID: {}}
        assert network.application_gateways_lookup_failed == {AZURE_SUBSCRIPTION_ID}

    def test_resource_group_error_marks_subscription_lookup_failed(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list.side_effect = Exception("boom")

        network, result = get_gateways(
            mock_client, resource_groups={AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}
        )

        assert result == {AZURE_SUBSCRIPTION_ID: {}}
        assert network.application_gateways_lookup_failed == {AZURE_SUBSCRIPTION_ID}

    def test_maps_disabled_waf_policy_whatever_its_casing(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=GATEWAY_POLICY_ID.upper())
        ]

        _, result = get_gateways(mock_client, [build_waf_policy_model("disabled")])

        assert (
            result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID].firewall_policy_enabled is False
        )

    def test_unlisted_waf_policy_is_read_by_id(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=GATEWAY_POLICY_ID)
        ]
        mock_client.web_application_firewall_policies.get.return_value = (
            build_sdk_waf_policy("Enabled")
        )

        _, result = get_gateways(mock_client)

        mock_client.web_application_firewall_policies.get.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP, policy_name="waf1"
        )
        assert result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID].firewall_policy_enabled is True

    def test_waf_policy_read_error_is_recorded_and_leaves_state_unknown(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=GATEWAY_POLICY_ID)
        ]
        mock_client.web_application_firewall_policies.get.side_effect = Exception(
            "boom"
        )

        network, result = get_gateways(mock_client)

        assert result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID].firewall_policy_enabled is None
        assert network.waf_policy_reads_failed == {GATEWAY_POLICY_ID.casefold()}
        assert network.application_gateways_lookup_failed == set()

    def test_missing_waf_policy_is_not_a_failed_read(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=GATEWAY_POLICY_ID)
        ]
        mock_client.web_application_firewall_policies.get.side_effect = (
            ResourceNotFoundError("gone")
        )

        network, result = get_gateways(mock_client)

        assert result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID].firewall_policy_enabled is None
        assert network.waf_policy_reads_failed == set()

    def test_waf_policy_in_another_subscription_is_not_read(self):
        other_subscription_policy_id = GATEWAY_POLICY_ID.replace(
            AZURE_SUBSCRIPTION_ID, "00000000-0000-0000-0000-000000000000"
        )
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=other_subscription_policy_id)
        ]

        network, result = get_gateways(mock_client)

        mock_client.web_application_firewall_policies.get.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID].firewall_policy_enabled is None
        assert network.waf_policy_reads_failed == set()

    def test_waf_policy_without_known_state_leaves_state_unknown(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=GATEWAY_POLICY_ID)
        ]

        _, result = get_gateways(mock_client, [build_waf_policy_model(None)])

        mock_client.web_application_firewall_policies.get.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID].firewall_policy_enabled is None

    def test_policy_reference_that_is_not_a_waf_policy_id_is_not_read(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=f"{GATEWAY_POLICY_ID}/extra")
        ]

        network, result = get_gateways(mock_client)

        mock_client.web_application_firewall_policies.get.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID][GATEWAY_ID].firewall_policy_enabled is None
        assert network.waf_policy_reads_failed == set()

    def test_shared_unlisted_waf_policy_is_read_once(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            build_sdk_application_gateway(policy_id=GATEWAY_POLICY_ID),
            build_sdk_application_gateway(
                name="agw2", policy_id=GATEWAY_POLICY_ID.upper()
            ),
        ]
        mock_client.web_application_firewall_policies.get.return_value = (
            build_sdk_waf_policy("Enabled")
        )

        _, result = get_gateways(mock_client)

        assert len(result[AZURE_SUBSCRIPTION_ID]) == 2
        mock_client.web_application_firewall_policies.get.assert_called_once()

    def test_unmappable_gateway_is_skipped_and_marks_subscription(self):
        broken = azure_network_models.ApplicationGateway(location="westeurope")
        mock_client = MagicMock()
        mock_client.application_gateways.list_all.return_value = [
            broken,
            build_sdk_application_gateway(),
        ]

        network, result = get_gateways(mock_client)

        assert list(result[AZURE_SUBSCRIPTION_ID]) == [GATEWAY_ID]
        assert network.application_gateways_lookup_failed == {AZURE_SUBSCRIPTION_ID}

    def test_failed_resource_group_keeps_gateways_from_the_others(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list.side_effect = [
            [build_sdk_application_gateway()],
            Exception("boom"),
        ]

        network, result = get_gateways(
            mock_client,
            resource_groups={AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP, "rg2"]},
        )

        assert list(result[AZURE_SUBSCRIPTION_ID]) == [GATEWAY_ID]
        assert network.application_gateways_lookup_failed == {AZURE_SUBSCRIPTION_ID}

    def test_missing_resource_group_is_not_a_failed_lookup(self):
        mock_client = MagicMock()
        mock_client.application_gateways.list.side_effect = ResourceNotFoundError(
            "gone"
        )

        network, result = get_gateways(
            mock_client, resource_groups={AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}
        )

        assert result == {AZURE_SUBSCRIPTION_ID: {}}
        assert network.application_gateways_lookup_failed == set()
