from unittest.mock import MagicMock, patch

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
        mock_client.network_watchers.list.return_value = []

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

        mock_client.network_watchers.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.network_watchers.list_all.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_network_watchers_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()

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

        mock_client.network_watchers.list.assert_not_called()
        mock_client.network_watchers.list_all.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == []


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


class Test_Network_get_network_watchers_extra:
    def test_get_network_watchers_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()
        mock_client.network_watchers.list.return_value = []

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

        assert mock_client.network_watchers.list.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_network_watchers_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.network_watchers = MagicMock()
        mock_client.network_watchers.list.return_value = []

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

        mock_client.network_watchers.list.assert_called_once_with(
            resource_group_name="RG"
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
