from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.network.network_service import BastionHost
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_network_bastion_host_exists:
    def test_no_bastion_hosts(self):
        network_client = mock.MagicMock
        network_client.bastion_hosts = {AZURE_SUBSCRIPTION: []}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_bastion_host_exists.network_bastion_host_exists import (
                network_bastion_host_exists,
            )

            check = network_bastion_host_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bastion Host from subscription {AZURE_SUBSCRIPTION} does not exist"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "Bastion Host"
            assert result[0].resource_id == "N/A"

    def test_network_bastion_host_exists(self):
        network_client = mock.MagicMock
        bastion_host_name = "Bastion Host Name"
        bastion_host_id = str(uuid4())

        network_client.bastion_hosts = {
            AZURE_SUBSCRIPTION: [
                BastionHost(
                    id=bastion_host_id,
                    name=bastion_host_name,
                    location="location",
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_bastion_host_exists.network_bastion_host_exists import (
                network_bastion_host_exists,
            )

            check = network_bastion_host_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bastion Host from subscription {AZURE_SUBSCRIPTION} available are: {bastion_host_name}"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "Bastion Host"
            assert result[0].resource_id == bastion_host_id
