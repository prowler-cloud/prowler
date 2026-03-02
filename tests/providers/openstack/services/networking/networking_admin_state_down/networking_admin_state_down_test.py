"""Tests for network_admin_state_down check."""

from unittest import mock

from prowler.providers.openstack.services.networking.networking_service import (
    NetworkResource,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_networking_admin_state_down:
    def test_no_networks(self):
        """Test when no networks exist."""
        network_client = mock.MagicMock()
        network_client.networks = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.networking.networking_admin_state_down.networking_admin_state_down.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_admin_state_down.networking_admin_state_down import (
                networking_admin_state_down,
            )

            check = networking_admin_state_down()
            result = check.execute()

            assert len(result) == 0

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
                "prowler.providers.openstack.services.networking.networking_admin_state_down.networking_admin_state_down.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_admin_state_down.networking_admin_state_down import (
                networking_admin_state_down,
            )

            check = networking_admin_state_down()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Network production-network (net-1) is administratively enabled."
            )
            assert result[0].resource_id == "net-1"
            assert result[0].resource_name == "production-network"
            assert result[0].region == OPENSTACK_REGION

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
                "prowler.providers.openstack.services.networking.networking_admin_state_down.networking_admin_state_down.networking_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.networking.networking_admin_state_down.networking_admin_state_down import (
                networking_admin_state_down,
            )

            check = networking_admin_state_down()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Network disabled-network (net-2) is administratively disabled (admin_state_up=False) and cannot carry traffic."
            )
            assert result[0].resource_id == "net-2"
            assert result[0].resource_name == "disabled-network"
            assert result[0].region == OPENSTACK_REGION
