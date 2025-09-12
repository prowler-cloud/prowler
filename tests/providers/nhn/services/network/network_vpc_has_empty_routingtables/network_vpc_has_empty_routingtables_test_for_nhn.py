from unittest import mock
from uuid import uuid4

from prowler.providers.nhn.services.network.network_service import Network
from tests.providers.nhn.nhn_fixtures import set_mocked_nhn_provider


class Test_vpc_has_empty_routingtables:
    def test_no_networks(self):
        # 1) Make a MagicMock for network_client
        network_client = mock.MagicMock()
        network_client.networks = []

        # 2) Patch get_global_provider() to return a mocked NHN provider
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                # patch the 'network_empty_routingtables.network_client' used in the check code
                "prowler.providers.nhn.services.network.network_vpc_has_empty_routingtables.network_vpc_has_empty_routingtables.network_client",
                new=network_client,
            ),
        ):
            # 3) Import the check code AFTER patching
            from prowler.providers.nhn.services.network.network_vpc_has_empty_routingtables.network_vpc_has_empty_routingtables import (
                network_vpc_has_empty_routingtables,
            )

            # 4) Run the check
            check = network_vpc_has_empty_routingtables()
            result = check.execute()

            # 5) Assertions
            assert len(result) == 0  # no networks => no findings

    def test_vpc_has_empty_routingtables(self):
        # Make a MagicMock for network_client
        network_client = mock.MagicMock()

        # Suppose we have 1 network with empty_routingtables=True => FAIL expected
        network_id = str(uuid4())
        network_name = "testNetwork"
        mock_network = mock.MagicMock(spec=Network)
        mock_network.id = network_id
        mock_network.name = network_name
        mock_network.empty_routingtables = True
        network_client.networks = [mock_network]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                "prowler.providers.nhn.services.network.network_vpc_has_empty_routingtables.network_vpc_has_empty_routingtables.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.nhn.services.network.network_vpc_has_empty_routingtables.network_vpc_has_empty_routingtables import (
                network_vpc_has_empty_routingtables,
            )

            check = network_vpc_has_empty_routingtables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has empty routingtables" in result[0].status_extended
            assert result[0].resource_name == network_name
            assert result[0].resource_id == network_id

    def test_vpc_does_not_have_empty_routingtables(self):
        # Another scenario: network with empty_routingtables=False => PASS expected
        network_client = mock.MagicMock()

        network_id = str(uuid4())
        network_name = "testNetwork"
        mock_network = mock.MagicMock(spec=Network)
        mock_network.id = network_id
        mock_network.name = network_name
        mock_network.empty_routingtables = False
        network_client.networks = [mock_network]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_nhn_provider(),
            ),
            mock.patch(
                "prowler.providers.nhn.services.network.network_vpc_has_empty_routingtables.network_vpc_has_empty_routingtables.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.nhn.services.network.network_vpc_has_empty_routingtables.network_vpc_has_empty_routingtables import (
                network_vpc_has_empty_routingtables,
            )

            check = network_vpc_has_empty_routingtables()
            result = check.execute()

            assert len(result) == 0
            assert result[0].status == "PASS"
            assert "dose not have empty routingtables" in result[0].status_extended
            assert result[0].resource_name == network_name
            assert result[0].resource_id == network_id
