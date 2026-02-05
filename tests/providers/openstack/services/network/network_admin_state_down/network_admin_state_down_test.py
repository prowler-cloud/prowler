"""Tests for network_admin_state_down check."""

from unittest import mock

from prowler.providers.openstack.services.network.network_service import NetworkResource
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_network_admin_state_down:
    def test_network_admin_state_up(self):
        network_client = mock.MagicMock()
        network_client.networks = [
            NetworkResource(
                id="net-1",
                name="production-network",
                status="ACTIVE",
                admin_state_up=True,
                shared=False,
                external=False,
                port_security_enabled=True,
                subnets=["subnet-1"],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_admin_state_down.network_admin_state_down.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_admin_state_down.network_admin_state_down import (
                network_admin_state_down,
            )

            check = network_admin_state_down()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "is administratively enabled" in result[0].status_extended

    def test_network_admin_state_down(self):
        network_client = mock.MagicMock()
        network_client.networks = [
            NetworkResource(
                id="net-2",
                name="disabled-network",
                status="DOWN",
                admin_state_up=False,
                shared=False,
                external=False,
                port_security_enabled=True,
                subnets=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_admin_state_down.network_admin_state_down.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_admin_state_down.network_admin_state_down import (
                network_admin_state_down,
            )

            check = network_admin_state_down()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "is administratively disabled" in result[0].status_extended
            assert "admin_state_up=False" in result[0].status_extended
